//! Atomic local-cache publication outside the presentation thread. A single
//! post-DeferredInit worker accepts one owned encoded checkpoint at a time.
//! It never receives mesh owners, engine pointers, callbacks or world state.
//! Syringe retains loaded modules for process lifetime; the worker is detached
//! and exits with the process (or when its sender is dropped in offline tests).
//! Failures preserve the previous cache and are reported to the frame owner.

use parking_lot::Mutex;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};

/// Immutable serialized input. Moving this buffer transfers all writer input;
/// no decoded arrays or borrowed state are retained across the thread boundary.
pub(super) struct Checkpoint {
    pub(super) bytes: Vec<u8>,
    pub(super) revision: u64,
}

struct Temporary {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    committed: bool,
}

impl Drop for Temporary {
    fn drop(&mut self) {
        self.file.take();
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Checkpoint {
    fn publish(&self, path: &std::path::Path) -> io::Result<()> {
        let mut temporary_path = path.as_os_str().to_owned();
        temporary_path.push(".tmp");
        let mut temporary = Temporary {
            path: temporary_path.into(),
            file: None,
            committed: false,
        };
        temporary.file = Some(std::fs::File::create(&temporary.path)?);
        let Some(file) = temporary.file.as_mut() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        file.write_all(&self.bytes)?;
        file.sync_all()?;
        temporary.file.take();
        std::fs::rename(&temporary.path, path)?;
        temporary.committed = true;
        Ok(())
    }
}

/// Completion observed after all file work and buffer destruction have ended.
pub(super) struct WriteResult {
    pub(super) revision: u64,
    pub(super) error: Option<io::Error>,
    #[cfg(test)]
    pub(super) thread: std::thread::ThreadId,
}

struct State {
    busy: AtomicBool,
    completed: Mutex<Option<WriteResult>>,
}

/// One process-lifetime file writer. Busy admission bounds the channel and
/// encoded storage to one checkpoint; callers consume completion before reuse.
pub(super) struct CacheWriter {
    sender: SyncSender<Checkpoint>,
    state: Arc<State>,
}

impl CacheWriter {
    /// Start only at DeferredInit, before gameplay can request a checkpoint.
    pub(super) fn new(path: &std::path::Path) -> io::Result<Self> {
        // Freeze relative configuration at DeferredInit. A queued write must
        // not follow later process working-directory changes from UI/providers.
        let path = std::path::absolute(path)?;
        let (sender, receiver) = mpsc::sync_channel::<Checkpoint>(1);
        let state = Arc::new(State {
            busy: AtomicBool::new(false),
            completed: Mutex::new(None),
        });
        let worker_state = state.clone();
        let worker = std::thread::Builder::new()
            .name("psycho-cache-io".into())
            .spawn(move || {
                while let Ok(checkpoint) = receiver.recv() {
                    let result = WriteResult {
                        revision: checkpoint.revision,
                        error: checkpoint.publish(&path).err(),
                        #[cfg(test)]
                        thread: std::thread::current().id(),
                    };
                    // Release encoded memory before allowing the next preparation.
                    drop(checkpoint);
                    *worker_state.completed.lock() = Some(result);
                    worker_state.busy.store(false, Ordering::Release);
                }
            })?;
        // Core modules are retained by Syringe; no unload can invalidate this
        // worker's code. No join or filesystem wait belongs on presentation.
        drop(worker);
        Ok(Self { sender, state })
    }

    /// Nonblocking admission. The sender transfers one complete owned buffer.
    pub(super) fn submit(&self, checkpoint: Checkpoint) -> io::Result<()> {
        if self
            .state
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // With busy acquired, no other sender can enqueue and the previous
        // worker has already released this lock before its Release publication.
        if self.state.completed.lock().is_some() {
            self.state.busy.store(false, Ordering::Release);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if let Err(error) = self.sender.try_send(checkpoint) {
            self.state.busy.store(false, Ordering::Release);
            return Err(match error {
                mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                mpsc::TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe,
            }
            .into());
        }
        Ok(())
    }

    /// Atomic fast path while I/O runs; never waits for the writer's lock.
    pub(super) fn busy(&self) -> bool {
        self.state.busy.load(Ordering::Acquire)
    }

    /// Consume completion only after the worker's release publication.
    pub(super) fn take_result(&self) -> Option<WriteResult> {
        if self.busy() {
            return None;
        }
        self.state.completed.lock().take()
    }
}
