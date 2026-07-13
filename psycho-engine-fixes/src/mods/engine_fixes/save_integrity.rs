//! Durable save commits and safe changed-record loading.
//!
//! New Vegas writes a temporary `.fos.tmp`, but its original promotion path
//! ignores short writes, buffered flush failures, `fclose`, backup rotation,
//! and rename results. The hooks below turn the existing save-result check
//! into a real commit boundary. A failed transaction follows the game's own
//! Save Failed branch without publishing an incomplete `.fos`.
//!
//! The factory callsite is intentionally not patched. Other plugins may own
//! that mutable callsite, and wrapping it again can create a hook cycle. The
//! stable factory entry validates vanilla-created files while the activation
//! helper captures the file that the current callsite owner actually chose.
//!
//! Missing masters are a separate load-time failure mode. The engine decodes
//! their changed records to FormID zero, but normally enters first-pass form
//! reconstruction before checking whether a live form exists. We reject those
//! records at that shared boundary so unavailable content cannot publish
//! partially reconstructed state.

use std::{
    ffi::{CStr, CString, c_void},
    mem::size_of,
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, anyhow, ensure};

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::inline::inlinehook::InlineHookContainer,
        memory::validate_memory_range,
        winapi::{
            delete_file_if_exists, file_exists, get_current_thread_id,
            move_file_replace_write_through, open_existing_file_for_flush, replace_file_atomic,
        },
    },
};

use super::patching;

const SAVE_FACTORY_ADDR: usize = 0x0085_0030;
const SAVE_OWNER_ADDR: usize = 0x0085_03B0;
const SAVE_ACTIVATION_ADDR: usize = 0x0085_0EA0;
const SAVE_NULL_BRANCH: usize = 0x0085_0553;
const SAVE_FAILURE_UI: usize = 0x0085_05DF;
const SAVE_STATUS_ADDR: usize = 0x0084_63C0;
const SAVE_DESTROY_ADDR: usize = 0x0085_0330;
const SAVE_WRITE_ADDR: usize = 0x0084_6330;
const SAVE_RESULT_CALL_ADDR: usize = 0x0085_05C6;
const SAVE_RELEASE_ADDR: usize = 0x0085_0100;
const BSFILE_FINALIZE_ADDR: usize = 0x00AA_15A0;
const VANILLA_FCLOSE_ADDR: usize = 0x00EC_9907;
const SAVE_BACKUP_SETTING: usize = 0x011D_E2C8;
const SETTING_VALUE_ADDR: usize = 0x0043_D4D0;

const LOAD_OWNER_ADDR: usize = 0x0084_7DF0;
const LOAD_APPLY_ADDR: usize = 0x0084_9D00;
const BUFFER_READ_ADDR: usize = 0x0086_4820;
const BUFFER_PEEK_ADDR: usize = 0x0086_4A60;
const CHANGED_RECORD_VTABLE: usize = 0x0108_2028;

const SAVE_FILE_BSFILE_OFFSET: usize = 0x104;
const SAVE_MANAGER_PERSISTENT_FILE_OFFSET: usize = 0x20;
const BSFILE_STREAM_OFFSET: usize = 0x24;
const BSFILE_PATH_OFFSET: usize = 0x44;
const SAVELOAD_ERROR_FLAGS_OFFSET: usize = 0x244;
const LOAD_ERROR_FLAG: u32 = 0x80;
const CHANGED_RECORD_REJECTED_FLAG: u32 = 1;
const MAX_ENGINE_PATH: usize = 260;

const FAILURE_SHORT_WRITE: u32 = 1 << 0;
const FAILURE_BUFFER_FLUSH: u32 = 1 << 1;
const FAILURE_CLOSE: u32 = 1 << 2;
const FAILURE_DURABLE_FLUSH: u32 = 1 << 3;
const FAILURE_PROMOTION: u32 = 1 << 4;
const FAILURE_TRACKING: u32 = 1 << 5;

type SaveFactoryFn =
    unsafe extern "thiscall" fn(*mut c_void, *const i8, u8, i32, u32) -> *mut c_void;
type SaveOwnerFn = unsafe extern "thiscall" fn(*mut c_void, *const i8, u32, u8) -> u8;
type SaveActivationFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type SaveStatusFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type SaveDestroyFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
type SaveWriteFn = unsafe extern "thiscall" fn(*mut c_void, *const c_void, u32) -> u32;
type SaveResultFn = unsafe extern "fastcall" fn(*mut c_void) -> u8;
type SaveReleaseFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8);
type BsFileFinalizeFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type FcloseFn = unsafe extern "cdecl" fn(*mut c_void) -> i32;
type SettingValueFn = unsafe extern "thiscall" fn(*mut c_void) -> *const i32;

type LoadOwnerFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8) -> u8;
type LoadApplyFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void, u32) -> u32;
type BufferReadFn = unsafe extern "thiscall" fn(*mut RecordBuffer, *mut c_void, i32);
type BufferPeekFn = unsafe extern "fastcall" fn(*mut RecordBuffer) -> u32;

#[repr(C)]
struct RecordBuffer {
    vtable: usize,
    data: *mut u8,
    size: u32,
    cursor: u32,
}

/// Engine changed-record object used by both load passes.
///
/// The object derives from `RecordBuffer` at offset zero. Ghidra confirms that
/// `form_id` is the decoded runtime identity and bit zero of `flags` is the
/// engine's own second-pass rejection marker.
#[repr(C)]
struct ChangedRecord {
    buffer: RecordBuffer,
    form_id: u32,
    header: [u8; 12],
    payload_size: u32,
    live_form: *mut c_void,
    flags: u32,
}

static SAVE_WRITE_HOOK: LazyLock<InlineHookContainer<SaveWriteFn>> =
    LazyLock::new(InlineHookContainer::new);
static SAVE_FACTORY_HOOK: LazyLock<InlineHookContainer<SaveFactoryFn>> =
    LazyLock::new(InlineHookContainer::new);
static SAVE_OWNER_HOOK: LazyLock<InlineHookContainer<SaveOwnerFn>> =
    LazyLock::new(InlineHookContainer::new);
static SAVE_ACTIVATION_HOOK: LazyLock<InlineHookContainer<SaveActivationFn>> =
    LazyLock::new(InlineHookContainer::new);
static SAVE_RELEASE_HOOK: LazyLock<InlineHookContainer<SaveReleaseFn>> =
    LazyLock::new(InlineHookContainer::new);
static BSFILE_FINALIZE_HOOK: LazyLock<InlineHookContainer<BsFileFinalizeFn>> =
    LazyLock::new(InlineHookContainer::new);
static LOAD_OWNER_HOOK: LazyLock<InlineHookContainer<LoadOwnerFn>> =
    LazyLock::new(InlineHookContainer::new);
static LOAD_APPLY_HOOK: LazyLock<InlineHookContainer<LoadApplyFn>> =
    LazyLock::new(InlineHookContainer::new);
static BUFFER_READ_HOOK: LazyLock<InlineHookContainer<BufferReadFn>> =
    LazyLock::new(InlineHookContainer::new);
static BUFFER_PEEK_HOOK: LazyLock<InlineHookContainer<BufferPeekFn>> =
    LazyLock::new(InlineHookContainer::new);
static FCLOSE_HOOK: LazyLock<InlineHookContainer<FcloseFn>> =
    LazyLock::new(InlineHookContainer::new);

static ACTIVE_SAVE_FILE: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_SAVE_MANAGER: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_BSFILE: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_FILE_STREAM: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_SAVE_THREAD: AtomicU32 = AtomicU32::new(0);
static SAVE_OWNER_THREAD: AtomicU32 = AtomicU32::new(0);
static SAVE_FAILURES: AtomicU32 = AtomicU32::new(0);
static RELEASE_ALREADY_DONE: AtomicUsize = AtomicUsize::new(0);
static SAVE_RESULT_PREDECESSOR: AtomicUsize = AtomicUsize::new(0);

static ACTIVE_LOAD_OWNER: AtomicUsize = AtomicUsize::new(0);
static LOAD_ERROR_WAS_SET: AtomicBool = AtomicBool::new(false);
static LOAD_REJECTED: AtomicBool = AtomicBool::new(false);

static SAVE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static SAVE_COMMITS: AtomicU32 = AtomicU32::new(0);
static SAVE_ABORTS: AtomicU32 = AtomicU32::new(0);
static SHORT_WRITES: AtomicU32 = AtomicU32::new(0);
static CLOSE_FAILURES: AtomicU32 = AtomicU32::new(0);
static LOAD_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static UNRESOLVED_RECORDS: AtomicU32 = AtomicU32::new(0);

pub(super) struct DiagnosticSnapshot {
    pub save_attempts: u32,
    pub save_commits: u32,
    pub save_aborts: u32,
    pub short_writes: u32,
    pub close_failures: u32,
    pub load_rejections: u32,
    pub unresolved_records: u32,
    pub factory_hook: bool,
    pub owner_hook: bool,
    pub activation_hook: bool,
    pub fclose_hook: bool,
    pub load_owner_hook: bool,
    pub result_predecessor: usize,
}

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        save_attempts: SAVE_ATTEMPTS.load(Ordering::Relaxed),
        save_commits: SAVE_COMMITS.load(Ordering::Relaxed),
        save_aborts: SAVE_ABORTS.load(Ordering::Relaxed),
        short_writes: SHORT_WRITES.load(Ordering::Relaxed),
        close_failures: CLOSE_FAILURES.load(Ordering::Relaxed),
        load_rejections: LOAD_REJECTIONS.load(Ordering::Relaxed),
        unresolved_records: UNRESOLVED_RECORDS.load(Ordering::Relaxed),
        factory_hook: SAVE_FACTORY_HOOK.is_enabled(),
        owner_hook: SAVE_OWNER_HOOK.is_enabled(),
        activation_hook: SAVE_ACTIVATION_HOOK.is_enabled(),
        fclose_hook: FCLOSE_HOOK.is_enabled(),
        load_owner_hook: LOAD_OWNER_HOOK.is_enabled(),
        result_predecessor: SAVE_RESULT_PREDECESSOR.load(Ordering::Relaxed),
    }
}

/// Install save commits and safe changed-record loading independently.
///
/// Save support hooks are installed before the transaction activation hook.
/// The load hooks are individually safe: bounded readers reject only malformed
/// buffers, and the apply hook rejects only records the engine cannot resolve.
pub(super) fn install() -> anyhow::Result<()> {
    let save_commit = match install_save_commit_hooks() {
        Ok(()) => true,
        Err(error) => {
            log::warn!("[SAVE] Durable commit unavailable: {error:#}");
            false
        }
    };
    let safe_load = match install_load_containment_hooks() {
        Ok(()) => true,
        Err(error) => {
            log::warn!("[SAVE] Safe changed-record loading is incomplete: {error:#}");
            false
        }
    };
    let factory_validation = match install_factory_validation_hooks() {
        Ok(()) => {
            install_failure_ui_branch();
            true
        }
        Err(error) => {
            log::warn!("[SAVE] Temporary-file factory validation unavailable: {error:#}");
            false
        }
    };

    ensure!(
        save_commit || safe_load || factory_validation,
        "no save-integrity hook group could be activated"
    );
    log::info!(
        "[SAVE] Integrity hooks active: durable_commit={} safe_changed_record_load={} factory_validation={}",
        save_commit,
        safe_load,
        factory_validation
    );
    Ok(())
}

fn install_save_commit_hooks() -> anyhow::Result<()> {
    unsafe {
        SAVE_WRITE_HOOK.init(
            "save_integrity_write_result",
            SAVE_WRITE_ADDR as *mut c_void,
            hook_save_write,
        )?;
        SAVE_ACTIVATION_HOOK.init(
            "save_integrity_activation",
            SAVE_ACTIVATION_ADDR as *mut c_void,
            hook_save_activation,
        )?;
        SAVE_RELEASE_HOOK.init(
            "save_integrity_release",
            SAVE_RELEASE_ADDR as *mut c_void,
            hook_save_release,
        )?;
        BSFILE_FINALIZE_HOOK.init(
            "save_integrity_buffer_finalize",
            BSFILE_FINALIZE_ADDR as *mut c_void,
            hook_bsfile_finalize,
        )?;
        FCLOSE_HOOK.init(
            "save_integrity_fclose_result",
            VANILLA_FCLOSE_ADDR as *mut c_void,
            tracked_fclose,
        )?;
    }

    install_save_result_call()?;
    SAVE_WRITE_HOOK.enable()?;
    SAVE_RELEASE_HOOK.enable()?;
    BSFILE_FINALIZE_HOOK.enable()?;
    FCLOSE_HOOK.enable()?;

    // Activation is last: every hook needed to close, reject, or commit the
    // tracked object is already live when the first transaction can begin.
    SAVE_ACTIVATION_HOOK.enable()?;
    Ok(())
}

fn install_save_result_call() -> anyhow::Result<()> {
    // The predicate itself has unrelated callers. Wrapping only this audited
    // CALL preserves its fastcall manager argument and cannot commit early
    // from another predicate use. A pre-existing direct-call owner is chained.
    let previous = unsafe { patching::relative_call_target(SAVE_RESULT_CALL_ADDR) }
        .context("inspect save-result commit call")?;
    ensure!(
        previous != hook_save_result as *const () as usize,
        "save-result commit call already targets Psycho without a known predecessor"
    );
    let redirected = unsafe {
        patching::redirect_relative_call(SAVE_RESULT_CALL_ADDR, hook_save_result as *mut c_void)
    }
    .context("install save-result commit boundary")?;
    ensure!(
        redirected == previous,
        "save-result call target changed during install"
    );
    SAVE_RESULT_PREDECESSOR.store(previous, Ordering::Release);
    Ok(())
}

fn install_load_containment_hooks() -> anyhow::Result<()> {
    unsafe {
        LOAD_APPLY_HOOK.init(
            "save_integrity_load_apply",
            LOAD_APPLY_ADDR as *mut c_void,
            hook_load_apply,
        )?;
        BUFFER_READ_HOOK.init(
            "save_integrity_buffer_read",
            BUFFER_READ_ADDR as *mut c_void,
            hook_buffer_read,
        )?;
        BUFFER_PEEK_HOOK.init(
            "save_integrity_buffer_peek",
            BUFFER_PEEK_ADDR as *mut c_void,
            hook_buffer_peek,
        )?;
        LOAD_OWNER_HOOK.init(
            "save_integrity_load_owner",
            LOAD_OWNER_ADDR as *mut c_void,
            hook_load_owner,
        )?;
    }

    LOAD_APPLY_HOOK.enable()?;
    BUFFER_READ_HOOK.enable()?;
    BUFFER_PEEK_HOOK.enable()?;

    // The owner hook scopes the aggregate error state and diagnostics. The
    // read and apply hooks remain locally safe if another mod owns this entry.
    LOAD_OWNER_HOOK.enable()?;
    Ok(())
}

fn install_factory_validation_hooks() -> anyhow::Result<()> {
    unsafe {
        SAVE_FACTORY_HOOK.init(
            "save_integrity_factory_validation",
            SAVE_FACTORY_ADDR as *mut c_void,
            hook_save_factory,
        )?;
        SAVE_OWNER_HOOK.init(
            "save_integrity_owner_scope",
            SAVE_OWNER_ADDR as *mut c_void,
            hook_save_owner,
        )?;
    }

    SAVE_FACTORY_HOOK.enable()?;
    // The factory detour is inert until this outer save scope is active.
    SAVE_OWNER_HOOK.enable()?;
    Ok(())
}

fn install_failure_ui_branch() {
    let observed = unsafe { std::slice::from_raw_parts(SAVE_NULL_BRANCH as *const u8, 5) };
    if observed.first().copied() == Some(0xE9) {
        let displacement = i32::from_le_bytes([observed[1], observed[2], observed[3], observed[4]]);
        let target = (SAVE_NULL_BRANCH + 5).wrapping_add_signed(displacement as isize);
        if target != SAVE_FAILURE_UI {
            log::warn!(
                "[SAVE] Null-file UI branch is redirected to 0x{target:08X}; leaving it unchanged"
            );
        }
        return;
    }

    const VANILLA_PREFIX: [u8; 5] = [0x8B, 0x8D, 0xBC, 0xFC, 0xFF];
    if observed != VANILLA_PREFIX {
        log::warn!(
            "[SAVE] Null-file UI branch is owned by another patch; leaving it unchanged bytes={:02X?}",
            observed
        );
        return;
    }

    let displacement = SAVE_FAILURE_UI.wrapping_sub(SAVE_NULL_BRANCH + 5) as i32;
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE9;
    replacement[1..].copy_from_slice(&displacement.to_le_bytes());
    if let Err(error) =
        unsafe { patching::replace_block(SAVE_NULL_BRANCH, &VANILLA_PREFIX, &replacement) }
    {
        log::warn!("[SAVE] Could not connect null-file failure UI: {error:#}");
    }
}

unsafe extern "thiscall" fn hook_save_factory(
    manager: *mut c_void,
    name: *const i8,
    temporary: u8,
    buffer_mode: i32,
    factory_arg: u32,
) -> *mut c_void {
    let Ok(original) = SAVE_FACTORY_HOOK.original() else {
        log::error!("[SAVE] Save factory trampoline is unavailable");
        return ptr::null_mut();
    };
    let file = unsafe { original(manager, name, temporary, buffer_mode, factory_arg) };
    if file.is_null() {
        return file;
    }
    if SAVE_OWNER_THREAD.load(Ordering::Acquire) != get_current_thread_id() {
        return file;
    }

    let status =
        unsafe { FnPtr::<SaveStatusFn>::from_address_unchecked(SAVE_STATUS_ADDR).as_fn()(file) };
    if status == 0 {
        log::error!("[SAVE] Temporary save file failed its engine open/status check");
        destroy_save_file(file);
        return ptr::null_mut();
    }

    file
}

unsafe extern "thiscall" fn hook_save_owner(
    manager: *mut c_void,
    name: *const i8,
    argument: u32,
    show_success: u8,
) -> u8 {
    let Ok(original) = SAVE_OWNER_HOOK.original() else {
        log::error!("[SAVE] Save owner trampoline is unavailable");
        return 0;
    };

    let thread = get_current_thread_id();
    if SAVE_OWNER_THREAD
        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return unsafe { original(manager, name, argument, show_success) };
    }
    let result = unsafe { original(manager, name, argument, show_success) };
    SAVE_OWNER_THREAD.store(0, Ordering::Release);
    if ACTIVE_SAVE_THREAD.load(Ordering::Acquire) == thread {
        log::error!(
            "[SAVE] Save returned without reaching Psycho's commit boundary; transaction tracking cleared"
        );
        clear_save_tracking();
    }
    result
}

unsafe extern "thiscall" fn hook_save_activation(manager: *mut c_void, file: *mut c_void) {
    clear_save_tracking();
    if is_manager_persistent_file(manager, file) {
        let Ok(original) = SAVE_ACTIVATION_HOOK.original() else {
            log::error!("[SAVE] Save activation trampoline is unavailable");
            return;
        };
        unsafe { original(manager, file) };
        return;
    }

    match unsafe { begin_save_tracking(manager, file) } {
        Ok(()) => {
            SAVE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => {
            clear_save_tracking();
            log::warn!(
                "[SAVE] Durable transaction skipped for an unsupported save-file object: {error:#}"
            );
        }
    }

    let Ok(original) = SAVE_ACTIVATION_HOOK.original() else {
        latch_save_failure(FAILURE_TRACKING);
        log::error!("[SAVE] Save activation trampoline is unavailable");
        return;
    };
    unsafe { original(manager, file) };
}

fn is_manager_persistent_file(manager: *mut c_void, file: *mut c_void) -> bool {
    if manager.is_null() || file.is_null() {
        return false;
    }
    let slot = unsafe {
        (manager as *const u8).add(SAVE_MANAGER_PERSISTENT_FILE_OFFSET) as *const *mut c_void
    };
    if validate_memory_range(slot.cast(), size_of::<usize>()).is_err() {
        return false;
    }
    unsafe { ptr::read_unaligned(slot) == file }
}

unsafe fn begin_save_tracking(manager: *mut c_void, file: *mut c_void) -> anyhow::Result<()> {
    ensure!(!file.is_null(), "missing BGSSaveLoadFile");
    validate_memory_range(file, SAVE_FILE_BSFILE_OFFSET + size_of::<usize>())?;
    let bsfile = unsafe {
        ptr::read_unaligned((file as *const u8).add(SAVE_FILE_BSFILE_OFFSET) as *const *mut c_void)
    };
    ensure!(!bsfile.is_null(), "BGSSaveLoadFile has no BSFile");
    validate_memory_range(bsfile, BSFILE_PATH_OFFSET + MAX_ENGINE_PATH)?;
    let stream = unsafe {
        ptr::read_unaligned((bsfile as *const u8).add(BSFILE_STREAM_OFFSET) as *const *mut c_void)
    };
    ensure!(!stream.is_null(), "BSFile has no FILE stream");

    SAVE_FAILURES.store(0, Ordering::Release);
    RELEASE_ALREADY_DONE.store(0, Ordering::Release);
    ACTIVE_SAVE_MANAGER.store(manager as usize, Ordering::Release);
    ACTIVE_BSFILE.store(bsfile as usize, Ordering::Release);
    ACTIVE_FILE_STREAM.store(stream as usize, Ordering::Release);
    ACTIVE_SAVE_THREAD.store(get_current_thread_id(), Ordering::Release);
    ACTIVE_SAVE_FILE.store(file as usize, Ordering::Release);
    Ok(())
}

unsafe extern "thiscall" fn hook_save_write(
    file: *mut c_void,
    data: *const c_void,
    requested: u32,
) -> u32 {
    let Ok(original) = SAVE_WRITE_HOOK.original() else {
        latch_save_failure(FAILURE_TRACKING);
        return 0;
    };
    let written = unsafe { original(file, data, requested) };
    if file as usize == ACTIVE_SAVE_FILE.load(Ordering::Acquire) && written != requested {
        SHORT_WRITES.fetch_add(1, Ordering::Relaxed);
        latch_save_failure(FAILURE_SHORT_WRITE);
    }
    written
}

unsafe extern "fastcall" fn hook_bsfile_finalize(bsfile: *mut c_void) -> u32 {
    let Ok(original) = BSFILE_FINALIZE_HOOK.original() else {
        latch_save_failure(FAILURE_TRACKING);
        return 0;
    };
    let result = unsafe { original(bsfile) };
    if bsfile as usize == ACTIVE_BSFILE.load(Ordering::Acquire) && result == 0 {
        latch_save_failure(FAILURE_BUFFER_FLUSH);
    }
    result
}

unsafe extern "cdecl" fn tracked_fclose(stream: *mut c_void) -> i32 {
    let Ok(original) = FCLOSE_HOOK.original() else {
        latch_save_failure(FAILURE_TRACKING);
        return -1;
    };
    let result = unsafe { original(stream) };
    if stream as usize == ACTIVE_FILE_STREAM.load(Ordering::Acquire) && result != 0 {
        CLOSE_FAILURES.fetch_add(1, Ordering::Relaxed);
        latch_save_failure(FAILURE_CLOSE);
    }
    result
}

unsafe extern "fastcall" fn hook_save_result(manager_state: *mut c_void) -> u8 {
    let predecessor = SAVE_RESULT_PREDECESSOR.load(Ordering::Acquire);
    if predecessor == 0 {
        latch_save_failure(FAILURE_TRACKING);
        return 1;
    }
    let original = unsafe { FnPtr::<SaveResultFn>::from_address_unchecked(predecessor) };
    let vanilla_failure = unsafe { original.as_fn()(manager_state) } != 0;
    let file = ACTIVE_SAVE_FILE.load(Ordering::Acquire);
    if file == 0 || ACTIVE_SAVE_THREAD.load(Ordering::Acquire) != get_current_thread_id() {
        return u8::from(vanilla_failure);
    }

    let manager = ACTIVE_SAVE_MANAGER.load(Ordering::Acquire);
    let paths = unsafe { save_paths(ACTIVE_BSFILE.load(Ordering::Acquire) as *mut c_void) };

    // Close through the complete engine destructor before inspecting or
    // renaming the file. The later vanilla promote call is consumed by the
    // release hook because the object has already been destroyed here.
    let close_result = close_without_promotion(manager as *mut c_void, file as *mut c_void);
    if close_result.is_err() {
        latch_save_failure(FAILURE_TRACKING);
    }

    if vanilla_failure || SAVE_FAILURES.load(Ordering::Acquire) != 0 {
        abort_save(vanilla_failure, paths.as_ref().ok());
        return 1;
    }

    let paths = match paths {
        Ok(paths) => paths,
        Err(error) => {
            latch_save_failure(FAILURE_TRACKING);
            log::error!("[SAVE] Temporary path is invalid: {error:#}");
            abort_save(false, None);
            return 1;
        }
    };

    if let Err(error) = commit_save(&paths) {
        latch_save_failure(FAILURE_PROMOTION);
        log::error!(
            "[SAVE] Commit failed after recovery handling: {error:#} temp={}",
            paths.temp.to_string_lossy()
        );
        abort_save(false, Some(&paths));
        return 1;
    }

    RELEASE_ALREADY_DONE.store(file, Ordering::Release);
    clear_active_save();
    SAVE_COMMITS.fetch_add(1, Ordering::Relaxed);
    log::info!(
        "[SAVE] Durable commit complete: {}",
        paths.final_path.to_string_lossy()
    );
    0
}

unsafe extern "thiscall" fn hook_save_release(
    manager: *mut c_void,
    file: *mut c_void,
    promote: u8,
) {
    if file as usize != 0
        && RELEASE_ALREADY_DONE
            .compare_exchange(file as usize, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        return;
    }

    let Ok(original) = SAVE_RELEASE_HOOK.original() else {
        log::error!("[SAVE] Save-file release trampoline is unavailable");
        return;
    };
    unsafe { original(manager, file, promote) };
}

fn close_without_promotion(manager: *mut c_void, file: *mut c_void) -> anyhow::Result<()> {
    let original = SAVE_RELEASE_HOOK
        .original()
        .context("save release trampoline unavailable")?;
    unsafe { original(manager, file, 0) };
    Ok(())
}

fn destroy_save_file(file: *mut c_void) {
    let destroy = unsafe { FnPtr::<SaveDestroyFn>::from_address_unchecked(SAVE_DESTROY_ADDR) };
    unsafe { destroy.as_fn()(file, 1) };
}

struct SavePaths {
    temp: CString,
    final_path: CString,
}

unsafe fn save_paths(bsfile: *mut c_void) -> anyhow::Result<SavePaths> {
    ensure!(!bsfile.is_null(), "missing BSFile");
    let address = unsafe { (bsfile as *const u8).add(BSFILE_PATH_OFFSET) };
    validate_memory_range(address.cast(), MAX_ENGINE_PATH)?;
    let bytes = unsafe { std::slice::from_raw_parts(address, MAX_ENGINE_PATH) };
    let Some(length) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(anyhow!("BSFile path is not terminated"));
    };
    let temp_bytes = &bytes[..length];
    ensure!(
        temp_bytes.ends_with(b".tmp"),
        "save path does not end in .tmp"
    );
    ensure!(temp_bytes.len() > 4, "empty final save path");

    let temp = CString::new(temp_bytes).context("temporary save path contains NUL")?;
    let final_path = CString::new(&temp_bytes[..temp_bytes.len() - 4])
        .context("final save path contains NUL")?;
    Ok(SavePaths { temp, final_path })
}

fn commit_save(paths: &SavePaths) -> anyhow::Result<()> {
    {
        let temp =
            open_existing_file_for_flush(&paths.temp).context("open completed temporary save")?;
        ensure!(!temp.is_empty()?, "temporary save is empty");
        temp.flush().map_err(|error| {
            latch_save_failure(FAILURE_DURABLE_FLUSH);
            anyhow!(error)
        })?;
    }

    if !file_exists(&paths.final_path)? {
        move_file_replace_write_through(&paths.temp, &paths.final_path)
            .context("promote first save")?;
        return Ok(());
    }

    let backup_count = save_backup_count(paths.final_path.as_bytes().len());
    // ReplaceFile has documented failure modes where the old final has already
    // moved even though the call returns failure. Always request a first backup
    // so that state can be restored. With backups disabled it is transient and
    // removed after a successful replacement.
    let first_backup = if backup_count == 0 {
        let recovery = transaction_backup_path(&paths.final_path)?;
        delete_file_if_exists(&recovery).context("remove stale transaction recovery file")?;
        recovery
    } else {
        let oldest = backup_path(&paths.final_path, backup_count)?;
        delete_file_if_exists(&oldest).context("remove oldest save backup")?;

        for index in (1..backup_count).rev() {
            let source = backup_path(&paths.final_path, index)?;
            if file_exists(&source)? {
                let destination = backup_path(&paths.final_path, index + 1)?;
                move_file_replace_write_through(&source, &destination)
                    .with_context(|| format!("rotate save backup {index}"))?;
            }
        }
        backup_path(&paths.final_path, 1)?
    };

    if let Err(replace_error) =
        replace_file_atomic(&paths.final_path, &paths.temp, Some(&first_backup))
    {
        if let Err(recovery_error) = recover_failed_replace(&paths.final_path, &first_backup) {
            return Err(anyhow!(
                "atomic replacement failed: {replace_error}; recovery also failed: {recovery_error:#}"
            ));
        }
        return Err(anyhow!(replace_error)).context("atomically replace save");
    }
    if backup_count == 0
        && let Err(error) = delete_file_if_exists(&first_backup)
    {
        log::warn!(
            "[SAVE] Final save committed but transient recovery backup could not be removed: {error}"
        );
    }
    Ok(())
}

fn recover_failed_replace(final_path: &CStr, backup: &CStr) -> anyhow::Result<()> {
    if file_exists(final_path)? || !file_exists(backup)? {
        return Ok(());
    }
    move_file_replace_write_through(backup, final_path)
        .context("move transaction backup back to final path")
}

fn save_backup_count(final_path_length: usize) -> usize {
    let getter = unsafe { FnPtr::<SettingValueFn>::from_address_unchecked(SETTING_VALUE_ADDR) };
    let value = unsafe { getter.as_fn()(SAVE_BACKUP_SETTING as *mut c_void) };
    let configured = if !value.is_null() && validate_memory_range(value.cast(), 4).is_ok() {
        unsafe { ptr::read_unaligned(value) }.max(0) as usize
    } else {
        1
    };
    configured.min((MAX_ENGINE_PATH.saturating_sub(1 + final_path_length)) / 4)
}

fn backup_path(final_path: &CStr, index: usize) -> anyhow::Result<CString> {
    ensure!(index != 0, "backup index must be positive");
    let suffix_length = index
        .checked_mul(4)
        .ok_or_else(|| anyhow!("backup suffix overflow"))?;
    let total = final_path
        .to_bytes()
        .len()
        .checked_add(suffix_length)
        .ok_or_else(|| anyhow!("backup path overflow"))?;
    ensure!(total < MAX_ENGINE_PATH, "backup path exceeds engine limit");

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(final_path.to_bytes());
    for _ in 0..index {
        bytes.extend_from_slice(b".bak");
    }
    CString::new(bytes).context("backup path contains NUL")
}

fn transaction_backup_path(final_path: &CStr) -> anyhow::Result<CString> {
    let mut bytes = Vec::with_capacity(final_path.to_bytes().len() + 4);
    bytes.extend_from_slice(final_path.to_bytes());
    bytes.extend_from_slice(b".txn");
    ensure!(
        bytes.len() < MAX_ENGINE_PATH,
        "transaction backup path exceeds engine limit"
    );
    CString::new(bytes).context("transaction backup path contains NUL")
}

fn abort_save(vanilla_failure: bool, paths: Option<&SavePaths>) {
    let failures = SAVE_FAILURES.load(Ordering::Acquire);
    SAVE_ABORTS.fetch_add(1, Ordering::Relaxed);
    log::error!(
        "[SAVE] Save aborted before promotion vanilla_failure={} failure_bits=0x{:02X} temp={}",
        vanilla_failure,
        failures,
        paths.map_or_else(
            || "<unavailable>".into(),
            |paths| paths.temp.to_string_lossy()
        ),
    );
    clear_active_save();
}

fn latch_save_failure(failure: u32) {
    SAVE_FAILURES.fetch_or(failure, Ordering::AcqRel);
}

fn clear_active_save() {
    ACTIVE_SAVE_FILE.store(0, Ordering::Release);
    ACTIVE_SAVE_MANAGER.store(0, Ordering::Release);
    ACTIVE_BSFILE.store(0, Ordering::Release);
    ACTIVE_FILE_STREAM.store(0, Ordering::Release);
    ACTIVE_SAVE_THREAD.store(0, Ordering::Release);
}

fn clear_save_tracking() {
    clear_active_save();
    RELEASE_ALREADY_DONE.store(0, Ordering::Release);
    SAVE_FAILURES.store(0, Ordering::Release);
}

unsafe extern "thiscall" fn hook_load_owner(owner: *mut c_void, file: *mut c_void, mode: u8) -> u8 {
    let Ok(original) = LOAD_OWNER_HOOK.original() else {
        log::error!("[SAVE] Changed-form load owner trampoline is unavailable");
        return 0;
    };
    if owner.is_null()
        || ACTIVE_LOAD_OWNER
            .compare_exchange(0, owner as usize, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return unsafe { original(owner, file, mode) };
    }

    LOAD_REJECTED.store(false, Ordering::Release);
    LOAD_ERROR_WAS_SET.store(load_error_is_set(owner), Ordering::Release);
    let unresolved_before = UNRESOLVED_RECORDS.load(Ordering::Relaxed);
    let result = unsafe { original(owner, file, mode) };

    let rejected = LOAD_REJECTED.swap(false, Ordering::AcqRel);
    if rejected {
        // The engine may already have changed the current form before a nested
        // read fails. There is no rollback contract. The error bit stops its
        // second pass, and the apply hook prevents later first-pass mutations.
        LOAD_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        if !LOAD_ERROR_WAS_SET.load(Ordering::Acquire) {
            set_load_error_flag(owner, false);
        }
        log::error!(
            "[SAVE] Malformed changed-record data rejected before further record application"
        );
    }
    let unresolved = UNRESOLVED_RECORDS
        .load(Ordering::Relaxed)
        .wrapping_sub(unresolved_before);
    if unresolved != 0 {
        log::info!(
            "[SAVE] Skipped {unresolved} changed record(s) whose forms belong to unavailable content"
        );
    }
    ACTIVE_LOAD_OWNER.store(0, Ordering::Release);

    // The decompiler models this engine function as void, but its only caller
    // consumes AL immediately after the call. Zero means missing masters and
    // opens the confirmation menu; nonzero continues or completes the load.
    // Returning after the atomic cleanup without preserving this byte makes a
    // valid load look like a new missing-content decision.
    result
}

unsafe extern "thiscall" fn hook_buffer_read(
    buffer: *mut RecordBuffer,
    destination: *mut c_void,
    length: i32,
) {
    let Ok(original) = BUFFER_READ_HOOK.original() else {
        reject_buffer_read(buffer, "read trampoline unavailable");
        return;
    };
    if changed_record_is_rejected(buffer) {
        return;
    }

    match validate_record_read(buffer, destination, length) {
        Ok(()) => unsafe { original(buffer, destination, length) },
        Err(reason) => reject_buffer_read(buffer, reason),
    }
}

unsafe extern "fastcall" fn hook_buffer_peek(buffer: *mut RecordBuffer) -> u32 {
    let Ok(original) = BUFFER_PEEK_HOOK.original() else {
        reject_buffer_read(buffer, "peek trampoline unavailable");
        return 0;
    };
    if changed_record_is_rejected(buffer) {
        return 0;
    }

    if buffer.is_null() {
        reject_buffer_read(buffer, "invalid record buffer");
        return 0;
    }
    let record = unsafe { &*buffer };
    if record.data.is_null() || record.cursor >= record.size {
        reject_buffer_read(buffer, "peek beyond record buffer");
        return 0;
    }
    let Some(byte_address) = (record.data as usize).checked_add(record.cursor as usize) else {
        reject_buffer_read(buffer, "record tag address overflow");
        return 0;
    };
    let byte = byte_address as *const u8;
    if unsafe { ptr::read(byte) } & 3 == 3 {
        reject_buffer_read(buffer, "reserved record-length tag");
        return 0;
    }
    // Vanilla decodes the tag by calling BUFFER_READ, so the nested hook
    // performs the full payload and spacer check. Repeating it here would put
    // two complete validations on every variable-length field.
    unsafe { original(buffer) }
}

unsafe extern "thiscall" fn hook_load_apply(
    owner: *mut c_void,
    argument: u32,
    record: *mut c_void,
    form_id: u32,
) -> u32 {
    if record.is_null() {
        mark_load_rejected("missing changed-record object");
        return 0;
    }

    let record = record.cast::<ChangedRecord>();

    // A malformed owner/header buffer invalidates the whole load, while a
    // malformed changed record sets the local rejection bit below. Check the
    // shared state once per record here, not for every field copied from it.
    if LOAD_REJECTED.load(Ordering::Acquire) {
        mark_changed_record_rejected(record);
        return 0;
    }
    if changed_record_is_rejected(unsafe { &raw mut (*record).buffer }) {
        return 0;
    }

    // Saved forms supplied by missing masters decode to zero. Save-created
    // dynamic forms retain their 0xFFxxxxxx identity, so this does not reject
    // legitimate reconstruction. Vanilla otherwise calls this mutation owner
    // before its null-form check and can publish state for unavailable content.
    if unsafe { ptr::read_unaligned(&raw const (*record).form_id) } == 0 {
        mark_changed_record_rejected(record);
        UNRESOLVED_RECORDS.fetch_add(1, Ordering::Relaxed);
        return 0;
    }

    let Ok(original) = LOAD_APPLY_HOOK.original() else {
        mark_changed_record_rejected(record);
        mark_load_rejected("record application trampoline unavailable");
        return 0;
    };
    unsafe { original(owner, argument, record.cast(), form_id) }
}

#[inline]
fn validate_record_read(
    buffer: *mut RecordBuffer,
    destination: *mut c_void,
    length: i32,
) -> Result<(), &'static str> {
    // Ghidra shows that the RecordBuffer object and its data allocation are
    // created and bound by the engine; the save controls only their contents
    // and encoded lengths. VirtualQuery cannot pin either allocation against a
    // lifetime bug, and calling it for every tiny field made all loads much
    // slower. The engine-owned size is the authoritative copy boundary.
    if buffer.is_null() {
        return Err("invalid record buffer");
    }
    if length < 0 {
        return Err("negative record read length");
    }
    let length = length as usize;
    if length != 0 && destination.is_null() {
        return Err("null record read destination");
    }

    let record = unsafe { &*buffer };
    if record.data.is_null() {
        return Err("null record data");
    }
    let cursor = record.cursor as usize;
    let size = record.size as usize;
    let Some(spacer_index) = cursor.checked_add(length) else {
        return Err("record read overflow");
    };
    if spacer_index >= size {
        return Err("record read exceeds payload");
    }
    let Some(spacer_address) = (record.data as usize).checked_add(spacer_index) else {
        return Err("record spacer address overflow");
    };
    if unsafe { ptr::read(spacer_address as *const u8) } != b'|' {
        return Err("record spacer mismatch");
    }
    Ok(())
}

fn reject_buffer_read(buffer: *mut RecordBuffer, reason: &'static str) {
    if !buffer.is_null() {
        // The buffer is engine-owned. Moving its cursor to the end makes every
        // later read fail locally without a global atomic on the valid path.
        let size = unsafe { ptr::read_unaligned(&raw const (*buffer).size) };
        unsafe { ptr::write_unaligned(&raw mut (*buffer).cursor, size) };
        if is_changed_record(buffer) {
            mark_changed_record_rejected(buffer.cast());
        }
    }
    mark_load_rejected(reason);
}

#[inline]
fn is_changed_record(buffer: *mut RecordBuffer) -> bool {
    if buffer.is_null() {
        return false;
    }
    unsafe { ptr::read_unaligned(&raw const (*buffer).vtable) == CHANGED_RECORD_VTABLE }
}

#[inline]
fn changed_record_is_rejected(buffer: *mut RecordBuffer) -> bool {
    if !is_changed_record(buffer) {
        return false;
    }
    let record = buffer.cast::<ChangedRecord>();
    unsafe { ptr::read_unaligned(&raw const (*record).flags) & CHANGED_RECORD_REJECTED_FLAG != 0 }
}

#[inline]
fn mark_changed_record_rejected(record: *mut ChangedRecord) {
    let flags = unsafe { ptr::read_unaligned(&raw const (*record).flags) };
    unsafe {
        ptr::write_unaligned(
            &raw mut (*record).flags,
            flags | CHANGED_RECORD_REJECTED_FLAG,
        )
    };
}

fn mark_load_rejected(reason: &'static str) {
    if !LOAD_REJECTED.swap(true, Ordering::AcqRel) {
        let owner = ACTIVE_LOAD_OWNER.load(Ordering::Acquire) as *mut c_void;
        if !owner.is_null() {
            set_load_error_flag(owner, true);
        }
        log::error!("[SAVE] Rejected malformed changed-record buffer: {reason}");
    }
}

fn load_error_is_set(owner: *mut c_void) -> bool {
    let flags = unsafe { (owner as *mut u8).add(SAVELOAD_ERROR_FLAGS_OFFSET) as *mut u32 };
    if validate_memory_range(flags.cast(), 4).is_err() {
        return false;
    }
    unsafe { ptr::read_unaligned(flags) & LOAD_ERROR_FLAG != 0 }
}

fn set_load_error_flag(owner: *mut c_void, enabled: bool) {
    let flags = unsafe { (owner as *mut u8).add(SAVELOAD_ERROR_FLAGS_OFFSET) as *mut u32 };
    if validate_memory_range(flags.cast(), 4).is_err() {
        return;
    }
    let current = unsafe { ptr::read_unaligned(flags) };
    let next = if enabled {
        current | LOAD_ERROR_FLAG
    } else {
        current & !LOAD_ERROR_FLAG
    };
    unsafe { ptr::write_unaligned(flags, next) };
}
