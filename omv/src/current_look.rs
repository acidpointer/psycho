//! Background persistence for the in-game "Current Look".
//!
//! `omv.toml` and external shader sidecars are the durable working state. The
//! render thread applies edits immediately, then [`AutosaveCoordinator`]
//! coalesces rapid UI changes before handing one immutable snapshot to
//! [`CurrentLookService`]. The worker owns all file reads, serialization, and
//! atomic writes.
//!
//! The worker fingerprints every tracked working file. A normal autosave is
//! rejected when a pre-publication guard observes that a file changed after
//! the worker's last known revision. This is deliberately stricter than
//! last-writer-wins: ordinary editor/menu conflicts require an explicit user
//! decision. The UI can reload the files or authorize one overwrite with the
//! current in-game look. Preset files and `omv-state.toml` are outside this
//! module's ownership.
//!
//! # Startup layout boundary
//!
//! `CurrentLookService` is created from `ScreenShaderRuntime::configure`, which
//! runs during `NVSEPlugin_Load`. Consequently every channel command, event,
//! and snapshot layout in this module belongs to the pre-Deferred footprint.
//! Do not embed config for a deferred engine feature in any of them, even if
//! the worker will use it only later. Native Shadows demonstrates the required
//! pattern: autosave reads a coherent feature-owned atomic snapshot, and
//! reload parses and publishes that detached table on this already-existing
//! worker after the reload transaction succeeds. This preserves the feature
//! without changing channel capacity, allocation size, or startup ownership.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::mpsc::{
        Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

use crate::{
    config::{CONFIG_PATH, GraphicsMenuConfig},
    shaders::{self, ScreenShaderSource},
};

const AUTOSAVE_DELAY: Duration = Duration::from_millis(750);
const AUTOSAVE_RETRY_MIN: Duration = Duration::from_secs(2);
const AUTOSAVE_RETRY_MAX: Duration = Duration::from_secs(30);
const EXTERNAL_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// An immutable render-state snapshot owned by the persistence worker.
///
/// Capturing clones can allocate, so callers should create snapshots only
/// after [`AutosaveCoordinator::take_due_save`] accepts a revision.
/// Do not add detached/deferred engine settings to this struct; query their
/// post-Deferred owner inside [`save_snapshot`] instead.
pub(crate) struct CurrentLookSnapshot {
    revision: u64,
    menu_config: GraphicsMenuConfig,
    sources: Vec<ScreenShaderSource>,
}

impl CurrentLookSnapshot {
    /// Captures the complete working look for one accepted autosave revision.
    pub(crate) fn capture(
        revision: u64,
        menu_config: GraphicsMenuConfig,
        sources: &[ScreenShaderSource],
    ) -> Self {
        Self {
            revision,
            menu_config,
            sources: sources.to_vec(),
        }
    }
}

/// Identifies the operation associated with a worker error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CurrentLookOperation {
    /// Saving a concrete autosave revision.
    Save(u64),
    /// Reloading the complete working look from disk.
    Reload,
    /// Watching tracked files for edits made outside the game.
    Monitor,
}

/// A non-blocking event produced by the Current Look worker.
///
/// This enum's maximum variant size is fixed during `NVSEPlugin_Load`. Do not
/// add deferred engine settings to a variant; publish them through the
/// feature's passive post-Deferred state before sending the existing event.
pub(crate) enum CurrentLookEvent {
    /// The supplied revision is durably published.
    Saved { revision: u64 },
    /// Disk state was loaded successfully and can replace the live look.
    Reloaded {
        menu_config: GraphicsMenuConfig,
        sources: Vec<ScreenShaderSource>,
    },
    /// A tracked file changed outside OMV.
    ///
    /// `blocked_revision` is present when the change was discovered at the
    /// commit guard for a save that the coordinator already marked in-flight.
    ExternalChange { blocked_revision: Option<u64> },
    /// A worker operation failed without blocking the render thread.
    Error {
        operation: CurrentLookOperation,
        message: String,
    },
}

/// Frozen bounded-channel payload allocated during `NVSEPlugin_Load`.
///
/// A new deferred feature must reuse the established reload/save operations
/// and its own post-Deferred state instead of widening this enum.
enum CurrentLookCommand {
    Track(Vec<PathBuf>),
    Save {
        snapshot: CurrentLookSnapshot,
        overwrite_external: bool,
    },
    Reload(Vec<ScreenShaderSource>),
    Stop,
}

/// Non-blocking render-thread handle for Current Look persistence.
///
/// Commands use a bounded queue. Queue saturation is reported to the caller
/// instead of stalling a render callback.
pub(crate) struct CurrentLookService {
    sender: SyncSender<CurrentLookCommand>,
    receiver: Receiver<CurrentLookEvent>,
}

impl CurrentLookService {
    /// Starts the file-owning worker and initializes its `omv.toml` revision.
    pub(crate) fn start() -> Result<Self> {
        let (command_sender, command_receiver) = sync_channel(4);
        let (event_sender, event_receiver) = sync_channel(4);
        let handle = thread::Builder::new()
            .name("omv-current-look".to_owned())
            .spawn(move || current_look_worker(command_receiver, event_sender))
            .context("failed to start Current Look persistence worker")?;
        drop(handle);
        Ok(Self {
            sender: command_sender,
            receiver: event_receiver,
        })
    }

    /// Adds the currently installed external shader sidecars to conflict
    /// detection without reading them on the render thread.
    pub(crate) fn track_sources(&self, sources: &[ScreenShaderSource]) -> Result<()> {
        let paths = sources
            .iter()
            .filter(|source| source.is_external_file())
            .map(|source| source.config_path.clone())
            .collect();
        self.send(CurrentLookCommand::Track(paths))
    }

    /// Queues a normal or explicitly authorized Current Look publication.
    pub(crate) fn save(
        &self,
        snapshot: CurrentLookSnapshot,
        overwrite_external: bool,
    ) -> Result<()> {
        self.send(CurrentLookCommand::Save {
            snapshot,
            overwrite_external,
        })
    }

    /// Queues a complete reload of `omv.toml` and external shader sidecars.
    pub(crate) fn reload(&self, sources: &[ScreenShaderSource]) -> Result<()> {
        self.send(CurrentLookCommand::Reload(sources.to_vec()))
    }

    /// Drains all events currently available without waiting.
    pub(crate) fn try_take_events(&self) -> Vec<CurrentLookEvent> {
        let mut events = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return events,
            }
        }
    }

    fn send(&self, command: CurrentLookCommand) -> Result<()> {
        match self.sender.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => bail!("Current Look worker is busy"),
            Err(TrySendError::Disconnected(_)) => {
                bail!("Current Look worker is unavailable")
            }
        }
    }
}

impl Drop for CurrentLookService {
    fn drop(&mut self) {
        let _ = self.sender.try_send(CurrentLookCommand::Stop);
    }
}

/// Pure render-thread state machine for debounce, retries, and conflicts.
///
/// This type never performs I/O and never owns a configuration snapshot. It
/// grants at most one save revision at a time, which bounds cloning and keeps
/// stale completions from clearing newer edits.
#[derive(Debug)]
pub(crate) struct AutosaveCoordinator {
    latest_revision: u64,
    saved_revision: u64,
    deadline: Option<Instant>,
    save_in_flight: Option<u64>,
    reload_in_flight: bool,
    external_change: bool,
    retry_count: u32,
}

impl Default for AutosaveCoordinator {
    fn default() -> Self {
        Self {
            latest_revision: 0,
            saved_revision: 0,
            deadline: None,
            save_in_flight: None,
            reload_in_flight: false,
            external_change: false,
            retry_count: 0,
        }
    }
}

impl AutosaveCoordinator {
    /// Records a UI edit and moves the trailing-edge autosave deadline.
    pub(crate) fn note_change(&mut self, now: Instant) {
        self.latest_revision = self.latest_revision.wrapping_add(1).max(1);
        self.deadline = Some(now + AUTOSAVE_DELAY);
        self.retry_count = 0;
    }

    /// Records an atomic action, such as preset activation, that should be
    /// persisted on the next service tick rather than after the UI debounce.
    pub(crate) fn note_immediate_change(&mut self, now: Instant) {
        self.latest_revision = self.latest_revision.wrapping_add(1).max(1);
        self.deadline = Some(now);
        self.retry_count = 0;
    }

    /// Ends the debounce window early, for example when the workbench closes.
    pub(crate) fn flush_pending(&mut self, now: Instant) {
        if self.is_dirty() && self.deadline.is_some() {
            self.deadline = Some(now);
        }
    }

    /// Returns one due revision and marks it in-flight.
    ///
    /// External conflicts and reloads suspend normal saves until the user
    /// chooses which state wins.
    pub(crate) fn take_due_save(&mut self, now: Instant) -> Option<u64> {
        if self.external_change || self.reload_in_flight || self.save_in_flight.is_some() {
            return None;
        }
        if self.deadline.is_none_or(|deadline| deadline > now) {
            return None;
        }
        let revision = self.latest_revision;
        self.deadline = None;
        self.save_in_flight = Some(revision);
        Some(revision)
    }

    /// Marks a durable save completion without discarding newer pending edits.
    pub(crate) fn save_succeeded(&mut self, revision: u64, now: Instant) {
        if self.save_in_flight != Some(revision) {
            return;
        }
        self.save_in_flight = None;
        self.saved_revision = self.saved_revision.max(revision);
        self.retry_count = 0;
        self.external_change = false;
        if self.latest_revision > self.saved_revision && self.deadline.is_none() {
            self.deadline = Some(now + AUTOSAVE_DELAY);
        }
    }

    /// Releases a failed save and schedules a bounded exponential retry.
    pub(crate) fn save_failed(&mut self, revision: u64, now: Instant) {
        if self.save_in_flight != Some(revision) {
            return;
        }
        self.save_in_flight = None;
        self.retry_count = self.retry_count.saturating_add(1).min(5);
        let multiplier = 1u32 << self.retry_count.saturating_sub(1);
        let retry = AUTOSAVE_RETRY_MIN
            .saturating_mul(multiplier)
            .min(AUTOSAVE_RETRY_MAX);
        self.deadline = Some(now + retry);
    }

    /// Suspends autosave after an external file revision is observed.
    pub(crate) fn external_change_detected(&mut self, blocked_revision: Option<u64>) {
        if blocked_revision.is_some() && blocked_revision != self.save_in_flight {
            return;
        }
        if blocked_revision.is_some() {
            self.save_in_flight = None;
        }
        self.external_change = true;
        self.deadline = None;
    }

    /// Begins an explicit disk reload if a conflict is waiting.
    pub(crate) fn begin_reload(&mut self) -> bool {
        if !self.external_change || self.reload_in_flight || self.save_in_flight.is_some() {
            return false;
        }
        self.reload_in_flight = true;
        true
    }

    /// Accepts a complete disk reload as both the live and persisted state.
    pub(crate) fn reload_succeeded(&mut self) {
        self.latest_revision = self.latest_revision.wrapping_add(1).max(1);
        self.saved_revision = self.latest_revision;
        self.deadline = None;
        self.save_in_flight = None;
        self.reload_in_flight = false;
        self.external_change = false;
        self.retry_count = 0;
    }

    /// Releases a failed reload while preserving the conflict decision.
    pub(crate) fn reload_failed(&mut self) {
        self.reload_in_flight = false;
    }

    /// Begins the conflict-only "keep in-game look" publication.
    pub(crate) fn begin_external_overwrite(&mut self) -> Option<u64> {
        if !self.external_change || self.reload_in_flight || self.save_in_flight.is_some() {
            return None;
        }
        let revision = self.latest_revision;
        self.save_in_flight = Some(revision);
        Some(revision)
    }

    /// Returns whether tracked files require an explicit conflict decision.
    pub(crate) fn has_external_change(&self) -> bool {
        self.external_change
    }

    /// Returns whether unsaved live revisions remain.
    pub(crate) fn is_dirty(&self) -> bool {
        self.latest_revision > self.saved_revision
    }

    /// Returns whether a due-time check is potentially useful this frame.
    pub(crate) fn has_pending_deadline(&self) -> bool {
        self.deadline.is_some()
    }
}

fn current_look_worker(
    receiver: Receiver<CurrentLookCommand>,
    sender: SyncSender<CurrentLookEvent>,
) {
    let mut tracked = TrackedFiles::new();
    let mut external_reported = false;
    let mut monitor_error_reported = false;
    if let Err(err) = tracked.rebase() {
        monitor_error_reported = true;
        if sender
            .send(CurrentLookEvent::Error {
                operation: CurrentLookOperation::Monitor,
                message: format!("{err:#}"),
            })
            .is_err()
        {
            return;
        }
    }

    loop {
        match receiver.recv_timeout(EXTERNAL_CHECK_INTERVAL) {
            Ok(CurrentLookCommand::Track(paths)) => {
                if let Err(err) = tracked.replace_external_paths(paths)
                    && sender
                        .send(CurrentLookEvent::Error {
                            operation: CurrentLookOperation::Monitor,
                            message: format!("{err:#}"),
                        })
                        .is_err()
                {
                    return;
                }
            }
            Ok(CurrentLookCommand::Save {
                snapshot,
                overwrite_external,
            }) => {
                if let Err(err) =
                    tracked.replace_external_paths(external_config_paths(&snapshot.sources))
                {
                    if sender
                        .send(CurrentLookEvent::Error {
                            operation: CurrentLookOperation::Save(snapshot.revision),
                            message: format!("{err:#}"),
                        })
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }

                if !overwrite_external {
                    match tracked.has_changed() {
                        Ok(true) => {
                            external_reported = true;
                            if sender
                                .send(CurrentLookEvent::ExternalChange {
                                    blocked_revision: Some(snapshot.revision),
                                })
                                .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            if sender
                                .send(CurrentLookEvent::Error {
                                    operation: CurrentLookOperation::Save(snapshot.revision),
                                    message: format!("{err:#}"),
                                })
                                .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                    }
                }

                let revision = snapshot.revision;
                match save_snapshot(snapshot, &mut tracked, overwrite_external) {
                    Ok(SnapshotSaveOutcome::Saved) => {
                        external_reported = false;
                        monitor_error_reported = false;
                        if sender.send(CurrentLookEvent::Saved { revision }).is_err() {
                            return;
                        }
                    }
                    Ok(SnapshotSaveOutcome::ExternalChange) => {
                        external_reported = true;
                        if sender
                            .send(CurrentLookEvent::ExternalChange {
                                blocked_revision: Some(revision),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(err) => {
                        // Rebase after our own failed publication. Otherwise a
                        // successfully written earlier file would be mistaken
                        // for an external edit on the retry.
                        let message = match tracked.rebase() {
                            Ok(()) => format!("{err:#}"),
                            Err(rebase_err) => {
                                format!("{err:#}; could not refresh file revisions: {rebase_err:#}")
                            }
                        };
                        if sender
                            .send(CurrentLookEvent::Error {
                                operation: CurrentLookOperation::Save(revision),
                                message,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            Ok(CurrentLookCommand::Reload(sources)) => {
                let result = reload_snapshot(&mut tracked, sources);
                match result {
                    Ok((menu_config, sources)) => {
                        external_reported = false;
                        monitor_error_reported = false;
                        if sender
                            .send(CurrentLookEvent::Reloaded {
                                menu_config,
                                sources,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(err) => {
                        if sender
                            .send(CurrentLookEvent::Error {
                                operation: CurrentLookOperation::Reload,
                                message: format!("{err:#}"),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            Ok(CurrentLookCommand::Stop) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => match tracked.has_changed() {
                Ok(true) if !external_reported => {
                    external_reported = true;
                    monitor_error_reported = false;
                    if sender
                        .send(CurrentLookEvent::ExternalChange {
                            blocked_revision: None,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(_) => monitor_error_reported = false,
                Err(err) if !monitor_error_reported => {
                    monitor_error_reported = true;
                    if sender
                        .send(CurrentLookEvent::Error {
                            operation: CurrentLookOperation::Monitor,
                            message: format!("{err:#}"),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => {}
            },
        }
    }
}

enum SnapshotSaveOutcome {
    Saved,
    ExternalChange,
}

fn save_snapshot(
    mut snapshot: CurrentLookSnapshot,
    tracked: &mut TrackedFiles,
    overwrite_external: bool,
) -> Result<SnapshotSaveOutcome> {
    // Publish the launch-critical working config immediately after the
    // revision guard. Sidecars follow; each file still uses its own atomic
    // replacement because ordinary filesystems cannot atomically replace the
    // complete heterogeneous set.
    crate::config::save_menu_config(&snapshot.menu_config)?;
    tracked.rebase_path(Path::new(CONFIG_PATH))?;

    for source in &mut snapshot.sources {
        if !source.is_external_file() {
            continue;
        }
        // The initial set-wide guard cannot protect a later sidecar from an
        // editor racing a preceding write. Re-check each destination at the
        // last useful point before its atomic replacement.
        if !overwrite_external && tracked.path_changed(&source.config_path)? {
            return Ok(SnapshotSaveOutcome::ExternalChange);
        }
        source.save_config_to_disk()?;
        tracked.rebase_path(&source.config_path)?;
    }
    Ok(SnapshotSaveOutcome::Saved)
}

fn reload_snapshot(
    tracked: &mut TrackedFiles,
    mut sources: Vec<ScreenShaderSource>,
) -> Result<(GraphicsMenuConfig, Vec<ScreenShaderSource>)> {
    tracked.replace_external_paths(external_config_paths(&sources))?;
    let menu_config = crate::config::load_menu_config_from_disk()?;
    let native_shadows = crate::config::load_native_shadows_config_from_disk()?;
    shaders::reload_external_shader_configs(&mut sources)?;
    tracked.rebase()?;
    // Shadow configuration is intentionally absent from the pre-Deferred
    // Current Look message layout. External reloads already execute on this
    // post-Deferred worker, so publish the validated table only after every
    // file in the reload transaction succeeded.
    crate::effects::shadows::configure_runtime_options(
        crate::effects::shadows::NativeShadowsSettings::from(native_shadows),
    );
    Ok((menu_config, sources))
}

fn external_config_paths(sources: &[ScreenShaderSource]) -> Vec<PathBuf> {
    sources
        .iter()
        .filter(|source| source.is_external_file())
        .map(|source| source.config_path.clone())
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileRevision {
    Missing,
    Content { bytes: u64, fingerprint: u64 },
}

struct TrackedFiles {
    baseline: BTreeMap<PathBuf, FileRevision>,
}

impl TrackedFiles {
    fn new() -> Self {
        let mut baseline = BTreeMap::new();
        baseline.insert(PathBuf::from(CONFIG_PATH), FileRevision::Missing);
        Self { baseline }
    }

    fn replace_external_paths(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        let mut wanted: BTreeSet<PathBuf> = paths.into_iter().collect();
        wanted.insert(PathBuf::from(CONFIG_PATH));
        self.baseline.retain(|path, _| wanted.contains(path));
        for path in wanted {
            if !self.baseline.contains_key(&path) {
                self.baseline.insert(path.clone(), file_revision(&path)?);
            }
        }
        Ok(())
    }

    fn has_changed(&self) -> Result<bool> {
        for (path, expected) in &self.baseline {
            if file_revision(path)? != *expected {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn path_changed(&self, path: &Path) -> Result<bool> {
        let Some(expected) = self.baseline.get(path) else {
            return Ok(false);
        };
        Ok(file_revision(path)? != *expected)
    }

    fn rebase_path(&mut self, path: &Path) -> Result<()> {
        if let Some(revision) = self.baseline.get_mut(path) {
            *revision = file_revision(path)?;
        }
        Ok(())
    }

    fn rebase(&mut self) -> Result<()> {
        for (path, revision) in &mut self.baseline {
            *revision = file_revision(path)?;
        }
        Ok(())
    }
}

fn file_revision(path: &Path) -> Result<FileRevision> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(FileRevision::Missing),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    Ok(FileRevision::Content {
        bytes: bytes.len() as u64,
        fingerprint: fingerprint(&bytes),
    })
}

fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use super::{AUTOSAVE_DELAY, AutosaveCoordinator, TrackedFiles};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rapid_edits_coalesce_at_the_trailing_edge() {
        let start = Instant::now();
        let mut autosave = AutosaveCoordinator::default();
        autosave.note_change(start);
        autosave.note_change(start + Duration::from_millis(500));

        assert_eq!(
            autosave.take_due_save(start + AUTOSAVE_DELAY),
            None,
            "the first edit must not publish while a newer edit is settling"
        );
        assert_eq!(
            autosave.take_due_save(start + Duration::from_millis(1_250)),
            Some(2)
        );
    }

    #[test]
    fn closing_the_workbench_flushes_a_pending_revision() {
        let start = Instant::now();
        let mut autosave = AutosaveCoordinator::default();
        autosave.note_change(start);

        autosave.flush_pending(start + Duration::from_millis(10));

        assert_eq!(
            autosave.take_due_save(start + Duration::from_millis(10)),
            Some(1)
        );
    }

    #[test]
    fn stale_completion_never_clears_a_newer_edit() {
        let start = Instant::now();
        let mut autosave = AutosaveCoordinator::default();
        autosave.note_immediate_change(start);
        assert_eq!(autosave.take_due_save(start), Some(1));
        autosave.note_change(start + Duration::from_millis(10));

        autosave.save_succeeded(1, start + Duration::from_millis(20));

        assert!(autosave.is_dirty());
        assert_eq!(
            autosave.take_due_save(start + Duration::from_millis(760)),
            Some(2)
        );
    }

    #[test]
    fn external_change_blocks_normal_saves_until_an_explicit_choice() {
        let start = Instant::now();
        let mut autosave = AutosaveCoordinator::default();
        autosave.note_immediate_change(start);
        assert_eq!(autosave.take_due_save(start), Some(1));

        autosave.external_change_detected(Some(1));

        assert!(autosave.has_external_change());
        assert_eq!(
            autosave.take_due_save(start + Duration::from_secs(60)),
            None
        );
        assert_eq!(autosave.begin_external_overwrite(), Some(1));
        autosave.save_succeeded(1, start + Duration::from_secs(60));
        assert!(!autosave.has_external_change());
        assert!(!autosave.is_dirty());
    }

    #[test]
    fn successful_reload_becomes_the_clean_current_look() {
        let start = Instant::now();
        let mut autosave = AutosaveCoordinator::default();
        autosave.note_change(start);
        autosave.external_change_detected(None);

        assert!(autosave.begin_reload());
        autosave.reload_succeeded();

        assert!(!autosave.has_external_change());
        assert!(!autosave.is_dirty());
    }

    #[test]
    fn tracked_files_detect_same_length_content_changes() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("omv-current-look-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).expect("create test directory");
        let _cleanup = TestDirectory(directory.clone());
        let path = directory.join("external.toml");
        fs::write(&path, "value = 1\n").expect("write first revision");

        let mut tracked = TrackedFiles::new();
        tracked
            .replace_external_paths(vec![path.clone()])
            .expect("track external file");
        assert!(!tracked.has_changed().unwrap());

        fs::write(path, "value = 2\n").expect("write changed revision");
        assert!(tracked.has_changed().unwrap());
    }
}
