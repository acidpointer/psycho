//! Durable save commits and safe changed-record loading.
//!
//! New Vegas writes a temporary `.fos.tmp`, but its original promotion path
//! ignores short writes, buffered flush failures, `fclose`, backup rotation,
//! and rename results. The hooks below turn the existing save-result check
//! into a real commit boundary. A failed transaction follows the game's own
//! Save Failed branch without publishing an incomplete `.fos`.
//!
//! The physical header uses the save buffer's per-write spacer framing. Every
//! scalar write is followed by `|`. A string is encoded as a `u16` length
//! write and, only when that length is nonzero, a separate payload write.
//! Consequently an empty string has one spacer while a nonempty string has
//! two. One parser primitive owns that framing rule so individual fields
//! cannot accidentally disagree. Commit validation first reads the fixed
//! header lead, derives the exact current-format header length, and then reads
//! that complete bounded envelope from a handle that excludes writers and
//! deletion. This avoids both guessed prefix limits and path-based races while
//! the completed file is being validated.
//!
//! Promotion uses a separately flushed copy of the old final as its rollback
//! image, followed by one same-volume `MoveFileEx` replacement. If a
//! compatibility layer rejects destination replacement while leaving the
//! final intact, promotion falls back to the engine's two
//! vacant-destination rename shape. It does not use `ReplaceFile`: that API
//! adds a metadata-merge/delete transaction which is absent from the engine
//! and fails under the reporter's Proton/MO2 path. `.txn` is always the
//! transient rollback copy; after success it is either deleted or renamed to
//! `.bak`. A later save first restores it if an interrupted promotion left the
//! final name absent.
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
//!
//! Dynamic actor containers have a second pre-mutation boundary. Character
//! load calls vanilla inventory reconstruction through two direct calls in the
//! supported executable. Before either call, Psycho validates an `FFxxxxxx`
//! actor base and its complete `TESContainer` through allocator metadata and
//! loaded-form registry identity. A corrupt live container is never detached
//! or partially repaired; its changed record and the whole load are rejected
//! before vanilla can dereference the malformed list.

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
        hook::{
            callsite::Rel32CallHookContainer, inline::inlinehook::InlineHookContainer,
            transaction::ModificationTransaction,
        },
        memory::validate_memory_range,
        winapi::{
            DurableFile, copy_file_new, delete_file_if_exists, file_exists,
            flush_instructions_cache, get_current_thread_id, move_file_replace_write_through,
            move_file_write_through, open_existing_file_for_flush, virtual_alloc_rwx,
        },
    },
};
use parking_lot::Mutex;

use super::{actor_container_guard, patching};

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
const PLAYER_LOAD_ADDR: usize = 0x0095_6F70;
const ACTOR_INVENTORY_LOAD_FIRST_CALL_ADDR: usize = 0x0056_2B8C;
const ACTOR_INVENTORY_LOAD_SECOND_CALL_ADDR: usize = 0x0056_2B98;
const ACTOR_INVENTORY_LOAD_FIRST_PREFIX_ADDR: usize = 0x0056_2B83;
const ACTOR_INVENTORY_LOAD_FIRST_PREFIX: &[u8] =
    &[0x85, 0xC9, 0x74, 0x0C, 0x6A, 0x00, 0x8B, 0x4D, 0xD8];
const ACTOR_INVENTORY_LOAD_BETWEEN_ADDR: usize = 0x0056_2B91;
const ACTOR_INVENTORY_LOAD_BETWEEN: &[u8] = &[0xEB, 0x0A, 0x6A, 0x01, 0x8B, 0x4D, 0xD8];
const ACTOR_INVENTORY_LOAD_SECOND_SUFFIX_ADDR: usize = 0x0056_2B9D;
const ACTOR_INVENTORY_LOAD_SECOND_SUFFIX: &[u8] = &[0xEB, 0x12];
const SAVE_VERSION_ADDR: usize = 0x008D_F040;
const SAVELOAD_SINGLETON: usize = 0x011D_E45C;
const CHANGED_RECORD_VTABLE: usize = 0x0108_2028;
const LOAD_BASE_FORM_GUARD_ADDR: usize = 0x0084_9DE6;
const LOAD_BASE_FORM_ID_ADDR: usize = 0x0084_E3A0;
const LOAD_BASE_FORM_COMPARE_ADDR: usize = 0x0084_9DED;
const LOAD_BASE_FORM_MISMATCH_ADDR: usize = 0x0084_9DF2;
const LOAD_BASE_FORM_GUARD_BYTES: [u8; 7] = [0x8B, 0xC8, 0xE8, 0xB3, 0x45, 0x00, 0x00];

const SAVE_FILE_BSFILE_OFFSET: usize = 0x104;
const SAVE_MANAGER_PERSISTENT_FILE_OFFSET: usize = 0x20;
const BSFILE_STREAM_OFFSET: usize = 0x24;
const BSFILE_PATH_OFFSET: usize = 0x44;
const SAVELOAD_ERROR_FLAGS_OFFSET: usize = 0x244;
const LOAD_ERROR_FLAG: u32 = 0x80;
const CHANGED_RECORD_REJECTED_FLAG: u32 = 1;
const MAX_ENGINE_PATH: usize = 260;
const SAVE_MAGIC: &[u8; 11] = b"FO3SAVEGAME";
const SAVE_HEADER_LEAD_SIZE: usize = SAVE_MAGIC.len() + size_of::<u32>();
const CURRENT_SAVE_VERSION: u32 = 0x30;
const HEADER_U32_FIELD_COUNT: usize = 5;
const HEADER_STRING_FIELD_COUNT: usize = 4;
const FRAMED_U32_SIZE: usize = size_of::<u32>() + 1;
const FRAMED_LANGUAGE_SIZE: usize = 64 + 1;
const MAX_FRAMED_STRING_SIZE: usize = size_of::<u16>() + 1 + u16::MAX as usize + 1;
// Version 0x30 has five framed u32 values, one optional language block, and
// four u16-length strings. This is the exact largest header its reader can
// consume, so it bounds cold-path allocation without rejecting a valid field.
const MAX_CURRENT_SAVE_HEADER_SIZE: usize = HEADER_U32_FIELD_COUNT * FRAMED_U32_SIZE
    + FRAMED_LANGUAGE_SIZE
    + HEADER_STRING_FIELD_COUNT * MAX_FRAMED_STRING_SIZE;

const PLAYER_SINGLETON: usize = 0x011D_EA3C;
const TES_OBJECT_REFR_BASE_FORM_OFFSET: usize = 0x20;
const PLAYER_SPEED_VALUE_INDEX: usize = 21;
const PLAYER_VALUE_ARRAY_OFFSETS: [usize; 3] = [0x244, 0x378, 0x4B0];
const PLAYER_SPEED_VALUE_OFFSETS: [usize; 3] = [
    PLAYER_VALUE_ARRAY_OFFSETS[0] + PLAYER_SPEED_VALUE_INDEX * size_of::<f32>(),
    PLAYER_VALUE_ARRAY_OFFSETS[1] + PLAYER_SPEED_VALUE_INDEX * size_of::<f32>(),
    PLAYER_VALUE_ARRAY_OFFSETS[2] + PLAYER_SPEED_VALUE_INDEX * size_of::<f32>(),
];

const FAILURE_SHORT_WRITE: u32 = 1 << 0;
const FAILURE_BUFFER_FLUSH: u32 = 1 << 1;
const FAILURE_CLOSE: u32 = 1 << 2;
const FAILURE_DURABLE_FLUSH: u32 = 1 << 3;
const FAILURE_PROMOTION: u32 = 1 << 4;
const FAILURE_TRACKING: u32 = 1 << 5;
const FAILURE_STRUCTURE: u32 = 1 << 6;
const FAILURE_STATE_MUTATION: u32 = 1 << 7;

type SaveFactoryFn =
    unsafe extern "thiscall" fn(*mut c_void, *const i8, u8, i32, u32) -> *mut c_void;
type SaveOwnerFn = unsafe extern "thiscall" fn(*mut c_void, *const i8, u32, u8) -> u8;
type SaveActivationFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type SaveStatusFn = unsafe extern "fastcall" fn(*mut c_void) -> u8;
type SaveDestroyFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
type SaveWriteFn = unsafe extern "thiscall" fn(*mut c_void, *const c_void, u32) -> u32;
type SaveResultFn = unsafe extern "fastcall" fn(*mut c_void) -> u8;
type SaveReleaseFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8);
type BsFileFinalizeFn = unsafe extern "fastcall" fn(*mut c_void) -> u8;
type FcloseFn = unsafe extern "cdecl" fn(*mut c_void) -> i32;
type SettingValueFn = unsafe extern "thiscall" fn(*mut c_void) -> *const i32;

type LoadOwnerFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8) -> u8;
type LoadApplyFn = unsafe extern "thiscall" fn(*mut c_void, u32, *mut c_void, u32) -> u32;
type BufferReadFn = unsafe extern "thiscall" fn(*mut RecordBuffer, *mut c_void, i32);
type BufferPeekFn = unsafe extern "fastcall" fn(*mut RecordBuffer) -> u32;
type PlayerLoadFn = unsafe extern "thiscall" fn(*mut c_void, u32, u32);
type ActorInventoryLoadFn = unsafe extern "thiscall" fn(*mut c_void, u8);
type SaveVersionFn = unsafe extern "fastcall" fn(*mut c_void) -> u8;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlayerSpeedSnapshot {
    player: usize,
    values: [u32; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActorInventoryLoadError {
    NullCharacter,
    NullBaseForm,
    InvalidContainer(actor_container_guard::LiveActorContainerError),
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
static PLAYER_LOAD_HOOK: LazyLock<InlineHookContainer<PlayerLoadFn>> =
    LazyLock::new(InlineHookContainer::new);
static ACTOR_INVENTORY_LOAD_FIRST_CALL_HOOK: LazyLock<
    Rel32CallHookContainer<ActorInventoryLoadFn>,
> = LazyLock::new(Rel32CallHookContainer::new);
static ACTOR_INVENTORY_LOAD_SECOND_CALL_HOOK: LazyLock<
    Rel32CallHookContainer<ActorInventoryLoadFn>,
> = LazyLock::new(Rel32CallHookContainer::new);
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
static SAVE_SPEED_SNAPSHOT: Mutex<Option<PlayerSpeedSnapshot>> = Mutex::new(None);

static ACTIVE_LOAD_OWNER: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_CHANGED_RECORD: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_LOAD_THREAD: AtomicU32 = AtomicU32::new(0);
static LOAD_REJECTED: AtomicBool = AtomicBool::new(false);

static SAVE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static SAVE_COMMITS: AtomicU32 = AtomicU32::new(0);
static SAVE_ABORTS: AtomicU32 = AtomicU32::new(0);
static SHORT_WRITES: AtomicU32 = AtomicU32::new(0);
static CLOSE_FAILURES: AtomicU32 = AtomicU32::new(0);
static STRUCTURE_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static STATE_MUTATIONS: AtomicU32 = AtomicU32::new(0);
static LOAD_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static PLAYER_LOAD_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static ACTOR_CONTAINER_LOAD_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static UNRESOLVED_RECORDS: AtomicU32 = AtomicU32::new(0);
static MISSING_BASE_FORM_RECORDS: AtomicU32 = AtomicU32::new(0);

/// Point-in-time counters and hook state consumed by the engine-fix dashboard.
///
/// Counters are process-lifetime totals. Hook booleans describe the current
/// installation state, while `result_predecessor` identifies the callable that
/// Psycho preserved at the shared save-result callsite.
pub(super) struct DiagnosticSnapshot {
    /// Save transactions that reached Psycho's activation boundary.
    pub save_attempts: u32,
    /// Save transactions durably promoted to their final `.fos` path.
    pub save_commits: u32,
    /// Save transactions rejected before promotion.
    pub save_aborts: u32,
    /// Tracked physical writes that returned fewer bytes than requested.
    pub short_writes: u32,
    /// Tracked CRT close operations that reported failure.
    pub close_failures: u32,
    /// Completed temporary files rejected by envelope validation.
    pub structure_rejections: u32,
    /// Save transactions rejected because the PlayerCharacter canary changed.
    pub state_mutations: u32,
    /// Whole-load transactions rejected as malformed.
    pub load_rejections: u32,
    /// PlayerCharacter records rejected before their mutation owner ran.
    pub player_load_rejections: u32,
    /// Character records rejected before corrupt dynamic inventory traversal.
    pub actor_container_load_rejections: u32,
    /// Changed records skipped because their source content was unavailable.
    pub unresolved_records: u32,
    /// Whether the stable temporary-file factory hook is active.
    pub factory_hook: bool,
    /// Whether the outer save-owner scope hook is active.
    pub owner_hook: bool,
    /// Whether the save activation and tracking hook is active.
    pub activation_hook: bool,
    /// Whether tracked CRT close results are being observed.
    pub fclose_hook: bool,
    /// Whether the whole-load transaction owner hook is active.
    pub load_owner_hook: bool,
    /// Whether PlayerCharacter record preflight is active.
    pub player_load_hook: bool,
    /// Whether the mode-zero Character inventory-load callsite guard is active.
    pub actor_container_load_first_hook: bool,
    /// Whether the mode-one Character inventory-load callsite guard is active.
    pub actor_container_load_second_hook: bool,
    /// Original target preserved from the shared save-result callsite.
    pub result_predecessor: usize,
}

/// Capture the current save-integrity diagnostics without resetting counters.
pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        save_attempts: SAVE_ATTEMPTS.load(Ordering::Relaxed),
        save_commits: SAVE_COMMITS.load(Ordering::Relaxed),
        save_aborts: SAVE_ABORTS.load(Ordering::Relaxed),
        short_writes: SHORT_WRITES.load(Ordering::Relaxed),
        close_failures: CLOSE_FAILURES.load(Ordering::Relaxed),
        structure_rejections: STRUCTURE_REJECTIONS.load(Ordering::Relaxed),
        state_mutations: STATE_MUTATIONS.load(Ordering::Relaxed),
        load_rejections: LOAD_REJECTIONS.load(Ordering::Relaxed),
        player_load_rejections: PLAYER_LOAD_REJECTIONS.load(Ordering::Relaxed),
        actor_container_load_rejections: ACTOR_CONTAINER_LOAD_REJECTIONS.load(Ordering::Relaxed),
        unresolved_records: UNRESOLVED_RECORDS.load(Ordering::Relaxed),
        factory_hook: SAVE_FACTORY_HOOK.is_enabled(),
        owner_hook: SAVE_OWNER_HOOK.is_enabled(),
        activation_hook: SAVE_ACTIVATION_HOOK.is_enabled(),
        fclose_hook: FCLOSE_HOOK.is_enabled(),
        load_owner_hook: LOAD_OWNER_HOOK.is_enabled(),
        player_load_hook: PLAYER_LOAD_HOOK.is_enabled(),
        actor_container_load_first_hook: ACTOR_INVENTORY_LOAD_FIRST_CALL_HOOK.is_enabled(),
        actor_container_load_second_hook: ACTOR_INVENTORY_LOAD_SECOND_CALL_HOOK.is_enabled(),
        result_predecessor: SAVE_RESULT_PREDECESSOR.load(Ordering::Relaxed),
    }
}

/// Install the complete save-integrity boundary as one owned transaction.
///
/// No transaction-producing owner is enabled until every supporting hook and
/// fixed patch site has been prepared. A failure restores every activation
/// that this module still owns instead of leaving a partial integrity policy.
pub(super) fn install() -> anyhow::Result<()> {
    actor_container_guard::prepare_validation();
    initialize_hooks()?;

    let result_predecessor = install_save_result_call()?;
    let base_form_guard = match install_missing_base_form_guard() {
        Ok(replacement) => replacement,
        Err(error) => {
            rollback_save_result_call(result_predecessor);
            return Err(error);
        }
    };

    let mut transaction = ModificationTransaction::new();
    let activation = (|| -> anyhow::Result<()> {
        transaction.enable_inline(&SAVE_WRITE_HOOK)?;
        transaction.enable_inline(&SAVE_RELEASE_HOOK)?;
        transaction.enable_inline(&BSFILE_FINALIZE_HOOK)?;
        transaction.enable_inline(&FCLOSE_HOOK)?;

        transaction.enable_inline(&LOAD_APPLY_HOOK)?;
        transaction.enable_inline(&BUFFER_READ_HOOK)?;
        transaction.enable_inline(&BUFFER_PEEK_HOOK)?;
        transaction.enable_inline(&PLAYER_LOAD_HOOK)?;
        transaction.enable_callsite(&ACTOR_INVENTORY_LOAD_FIRST_CALL_HOOK)?;
        transaction.enable_callsite(&ACTOR_INVENTORY_LOAD_SECOND_CALL_HOOK)?;

        transaction.enable_inline(&SAVE_FACTORY_HOOK)?;

        // Owner hooks are last. Their complete support graph is active before
        // a save or load can enter the integrity boundary.
        transaction.enable_inline(&SAVE_ACTIVATION_HOOK)?;
        transaction.enable_inline(&LOAD_OWNER_HOOK)?;
        transaction.enable_inline(&SAVE_OWNER_HOOK)?;
        Ok(())
    })();
    if let Err(error) = activation {
        drop(transaction);
        rollback_missing_base_form_guard(&base_form_guard);
        rollback_save_result_call(result_predecessor);
        return Err(error).context("activate complete save-integrity transaction");
    }
    transaction.commit();

    install_failure_ui_branch();
    log::info!("[SAVE] Complete save/write/load integrity transaction active");
    Ok(())
}

fn initialize_hooks() -> anyhow::Result<()> {
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
        PLAYER_LOAD_HOOK.init(
            "save_integrity_player_load_preflight",
            PLAYER_LOAD_ADDR as *mut c_void,
            hook_player_load,
        )?;
        // These context fingerprints prove the Character*, byte argument, and
        // branch layout around both calls. The callsite containers separately
        // capture and chain the current direct targets, allowing a compatible
        // predecessor without accepting an unrelated instruction role.
        patching::verify_bytes(
            ACTOR_INVENTORY_LOAD_FIRST_PREFIX_ADDR,
            ACTOR_INVENTORY_LOAD_FIRST_PREFIX,
        )?;
        patching::verify_bytes(
            ACTOR_INVENTORY_LOAD_BETWEEN_ADDR,
            ACTOR_INVENTORY_LOAD_BETWEEN,
        )?;
        patching::verify_bytes(
            ACTOR_INVENTORY_LOAD_SECOND_SUFFIX_ADDR,
            ACTOR_INVENTORY_LOAD_SECOND_SUFFIX,
        )?;
        ACTOR_INVENTORY_LOAD_FIRST_CALL_HOOK.init(
            "save_integrity_actor_inventory_load_first",
            ACTOR_INVENTORY_LOAD_FIRST_CALL_ADDR as *mut c_void,
            hook_actor_inventory_load_first,
        )?;
        ACTOR_INVENTORY_LOAD_SECOND_CALL_HOOK.init(
            "save_integrity_actor_inventory_load_second",
            ACTOR_INVENTORY_LOAD_SECOND_CALL_ADDR as *mut c_void,
            hook_actor_inventory_load_second,
        )?;
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
    Ok(())
}

fn install_save_result_call() -> anyhow::Result<usize> {
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
    Ok(previous)
}

fn rollback_save_result_call(predecessor: usize) {
    let wrapper = hook_save_result as *const () as usize;
    let current = unsafe { patching::relative_call_target(SAVE_RESULT_CALL_ADDR) };
    let result = match current {
        Ok(current) if current == wrapper => unsafe {
            patching::redirect_relative_call(SAVE_RESULT_CALL_ADDR, predecessor as *mut c_void)
        },
        Ok(current) => {
            log::error!(
                "[SAVE] Cannot restore result call after failed install; ownership moved to 0x{current:08X}"
            );
            return;
        }
        Err(error) => {
            log::error!(
                "[SAVE] Cannot inspect result call during failed-install rollback: {error:#}"
            );
            return;
        }
    };
    match result {
        Ok(previous) if previous == wrapper => {
            SAVE_RESULT_PREDECESSOR.store(0, Ordering::Release);
        }
        Ok(previous) => {
            log::error!("[SAVE] Result-call rollback displaced unexpected target 0x{previous:08X}");
        }
        Err(error) => {
            log::error!("[SAVE] Result-call rollback failed: {error:#}");
        }
    }
}

fn install_missing_base_form_guard() -> anyhow::Result<[u8; LOAD_BASE_FORM_GUARD_BYTES.len()]> {
    let stub = virtual_alloc_rwx(64).context("allocate changed-record base-form guard")?;
    let stub_addr = stub as usize;
    let mut code = Vec::with_capacity(64);

    code.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); // jnz valid base form
    let valid_jump_displacement = 4;

    code.extend_from_slice(&[0xFF, 0x75, 0xB0]); // push dword ptr [ebp-0x50]
    code.extend_from_slice(&[0xFF, 0x75, 0x0C]); // push dword ptr [ebp+0x0c]
    code.push(0xE8); // call log_missing_base_form
    code.extend_from_slice(&rel32(
        stub_addr + code.len() + 4,
        log_missing_base_form as *const () as usize,
    ));
    code.extend_from_slice(&[0x83, 0xC4, 0x08]); // add esp, 8
    code.push(0xE9); // jmp vanilla mismatch path
    code.extend_from_slice(&rel32(
        stub_addr + code.len() + 4,
        LOAD_BASE_FORM_MISMATCH_ADDR,
    ));

    let valid_base_form = stub_addr + code.len();
    code[valid_jump_displacement..valid_jump_displacement + 4].copy_from_slice(&rel32(
        stub_addr + valid_jump_displacement + 4,
        valid_base_form,
    ));
    code.extend_from_slice(&[0x8B, 0xC8]); // mov ecx, eax
    code.push(0xE8); // call TESForm::GetFormID
    code.extend_from_slice(&rel32(stub_addr + code.len() + 4, LOAD_BASE_FORM_ID_ADDR));
    code.push(0xE9); // resume vanilla comparison
    code.extend_from_slice(&rel32(
        stub_addr + code.len() + 4,
        LOAD_BASE_FORM_COMPARE_ADDR,
    ));

    ensure!(
        code.len() <= 64,
        "changed-record base-form guard stub overflow"
    );
    unsafe { ptr::copy_nonoverlapping(code.as_ptr(), stub.cast::<u8>(), code.len()) };
    flush_instructions_cache(stub, code.len()).context("flush changed-record base-form guard")?;

    let mut replacement = [0x90; LOAD_BASE_FORM_GUARD_BYTES.len()];
    replacement[0] = 0xE9;
    replacement[1..5].copy_from_slice(&rel32(LOAD_BASE_FORM_GUARD_ADDR + 5, stub_addr));
    unsafe {
        patching::replace_block(
            LOAD_BASE_FORM_GUARD_ADDR,
            &LOAD_BASE_FORM_GUARD_BYTES,
            &replacement,
        )
    }
    .context("install changed-record null base-form guard")?;

    log::info!(
        "[SAVE] Changed-record null base-form guard active at 0x{:08X}",
        LOAD_BASE_FORM_GUARD_ADDR,
    );
    Ok(replacement)
}

fn rollback_missing_base_form_guard(replacement: &[u8; LOAD_BASE_FORM_GUARD_BYTES.len()]) {
    if let Err(error) = unsafe {
        patching::replace_block(
            LOAD_BASE_FORM_GUARD_ADDR,
            replacement,
            &LOAD_BASE_FORM_GUARD_BYTES,
        )
    } {
        log::error!("[SAVE] Changed-record guard rollback failed: {error:#}");
    }
}

unsafe extern "cdecl" fn log_missing_base_form(record: *const ChangedRecord, expected: u32) {
    let record_form_id = if record.is_null() {
        0
    } else {
        unsafe { ptr::read_unaligned(&raw const (*record).form_id) }
    };
    let total = MISSING_BASE_FORM_RECORDS.fetch_add(1, Ordering::Relaxed) + 1;
    UNRESOLVED_RECORDS.fetch_add(1, Ordering::Relaxed);
    if total == 1 || total.is_power_of_two() {
        log::warn!(
            "[SAVE] Changed record rejected: missing base form total={} record=0x{:08X} form_id=0x{:08X} expected=0x{:08X}",
            total,
            record as usize,
            record_form_id,
            expected,
        );
    }
}

fn rel32(src_after: usize, dst: usize) -> [u8; 4] {
    let displacement = (dst as isize).wrapping_sub(src_after as isize) as i32;
    displacement.to_le_bytes()
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
        SAVE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        SAVE_ABORTS.fetch_add(1, Ordering::Relaxed);
        log::error!("[SAVE] Concurrent or reentrant save rejected before serialization");
        return 0;
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

    SAVE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    match unsafe { begin_save_tracking(manager, file) } {
        Ok(()) => {}
        Err(error) => {
            clear_save_tracking();
            latch_save_failure(FAILURE_TRACKING);
            ACTIVE_SAVE_MANAGER.store(manager as usize, Ordering::Release);
            ACTIVE_SAVE_THREAD.store(get_current_thread_id(), Ordering::Release);
            ACTIVE_SAVE_FILE.store(file as usize, Ordering::Release);
            log::error!(
                "[SAVE] Save-file tracking is invalid; transaction will fail closed: {error:#}"
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
    match capture_player_speed() {
        Ok(snapshot) => *SAVE_SPEED_SNAPSHOT.lock() = Some(snapshot),
        Err(error) => {
            *SAVE_SPEED_SNAPSHOT.lock() = None;
            STATE_MUTATIONS.fetch_add(1, Ordering::Relaxed);
            latch_save_failure(FAILURE_STATE_MUTATION);
            log::error!("[SAVE] Player speed canary is unavailable: {error:#}");
        }
    }
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
    if file as usize == ACTIVE_SAVE_FILE.load(Ordering::Acquire) {
        if written != requested {
            SHORT_WRITES.fetch_add(1, Ordering::Relaxed);
            latch_save_failure(FAILURE_SHORT_WRITE);
        }
    }
    written
}

fn capture_player_speed() -> anyhow::Result<PlayerSpeedSnapshot> {
    let singleton = PLAYER_SINGLETON as *const *mut c_void;
    validate_memory_range(singleton.cast(), size_of::<usize>())
        .context("validate PlayerCharacter singleton")?;
    let player = unsafe { ptr::read_unaligned(singleton) };
    ensure!(!player.is_null(), "PlayerCharacter singleton is null");

    let required = PLAYER_SPEED_VALUE_OFFSETS[2]
        .checked_add(size_of::<u32>())
        .context("PlayerCharacter speed range overflow")?;
    validate_memory_range(player, required).context("validate PlayerCharacter speed arrays")?;

    let mut values = [0; 3];
    for (index, offset) in PLAYER_SPEED_VALUE_OFFSETS.iter().copied().enumerate() {
        let address = unsafe { (player as *const u8).add(offset).cast::<u32>() };
        let bits = unsafe { ptr::read_unaligned(address) };
        ensure!(
            f32::from_bits(bits).is_finite(),
            "PlayerCharacter SpeedMult slot {index} is not finite"
        );
        values[index] = bits;
    }
    Ok(PlayerSpeedSnapshot {
        player: player as usize,
        values,
    })
}

fn validate_player_speed_unchanged() -> anyhow::Result<()> {
    let expected = SAVE_SPEED_SNAPSHOT
        .lock()
        .as_ref()
        .copied()
        .context("player speed canary was not captured")?;
    let observed = capture_player_speed()?;
    ensure!(
        observed.player == expected.player,
        "PlayerCharacter singleton changed during save"
    );
    ensure!(
        observed.values == expected.values,
        "PlayerCharacter SpeedMult modifiers changed during save: before={:08X?} after={:08X?}",
        expected.values,
        observed.values
    );
    Ok(())
}

unsafe extern "fastcall" fn hook_bsfile_finalize(bsfile: *mut c_void) -> u8 {
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

    if SAVE_FAILURES.load(Ordering::Acquire) & FAILURE_STATE_MUTATION == 0
        && let Err(error) = validate_player_speed_unchanged()
    {
        STATE_MUTATIONS.fetch_add(1, Ordering::Relaxed);
        latch_save_failure(FAILURE_STATE_MUTATION);
        log::error!("[SAVE] Player state changed inside save transaction: {error:#}");
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

struct HeaderCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> HeaderCursor<'a> {
    fn at(bytes: &'a [u8], position: usize) -> anyhow::Result<Self> {
        ensure!(
            position <= bytes.len(),
            "save header cursor begins beyond captured envelope"
        );
        Ok(Self { bytes, position })
    }

    fn take_unframed(&mut self, length: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("save header offset overflow")?;
        ensure!(end <= self.bytes.len(), "truncated save header");
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    /// Consume one complete low-level read from the physical save buffer.
    ///
    /// `0x00864820` advances over the requested payload and exactly one
    /// trailing spacer for every read operation. Keeping both actions in this
    /// primitive prevents scalar, block, and string parsing from acquiring
    /// subtly different framing rules.
    fn framed(&mut self, length: usize, field: &'static str) -> anyhow::Result<&'a [u8]> {
        let payload_offset = self.position;
        let value = self
            .take_unframed(length)
            .with_context(|| format!("read {field} payload at offset {payload_offset}"))?;
        let offset = self.position;
        let found = self
            .take_unframed(1)
            .with_context(|| format!("read separator after {field} at offset {offset}"))?[0];
        ensure!(
            found == b'|',
            "save header separator mismatch after {field} at offset {offset}: expected 0x7C, found 0x{found:02X}"
        );
        Ok(value)
    }

    fn framed_u16(&mut self, field: &'static str) -> anyhow::Result<u16> {
        let bytes: [u8; 2] = self
            .framed(size_of::<u16>(), field)?
            .try_into()
            .expect("fixed-size read");
        Ok(u16::from_le_bytes(bytes))
    }

    fn framed_u32(&mut self, field: &'static str) -> anyhow::Result<u32> {
        let bytes: [u8; 4] = self
            .framed(size_of::<u32>(), field)?
            .try_into()
            .expect("fixed-size read");
        Ok(u32::from_le_bytes(bytes))
    }

    fn spacer_follows(&self, length: usize, field: &'static str) -> anyhow::Result<bool> {
        let offset = self
            .position
            .checked_add(length)
            .context("save header lookahead overflow")?;
        let found = self
            .bytes
            .get(offset)
            .with_context(|| format!("truncated save header while locating {field} separator"))?;
        Ok(*found == b'|')
    }

    /// Consume one string using the engine's compound buffer encoding.
    ///
    /// The length and payload are separate buffered writes, and each performed
    /// write owns one trailing spacer. Both `0x00865E70` (writer) and
    /// `0x008649A0` (reader) skip the payload operation when the encoded length
    /// is zero, so an empty string must not consume a second spacer.
    fn string(&mut self, field: &'static str) -> anyhow::Result<()> {
        let length = usize::from(self.framed_u16(field)?);
        if length == 0 {
            return Ok(());
        }
        self.framed(length, field)?;
        Ok(())
    }
}

fn current_save_header_end(prefix: &[u8], file_length: u64) -> anyhow::Result<usize> {
    ensure!(
        prefix.len() >= SAVE_HEADER_LEAD_SIZE,
        "truncated save header lead"
    );
    ensure!(
        &prefix[..SAVE_MAGIC.len()] == SAVE_MAGIC,
        "invalid save magic"
    );
    let header_size = u32::from_le_bytes(
        prefix[SAVE_MAGIC.len()..SAVE_HEADER_LEAD_SIZE]
            .try_into()
            .expect("fixed-size header lead"),
    ) as usize;
    ensure!(
        header_size <= MAX_CURRENT_SAVE_HEADER_SIZE,
        "save header length {header_size} exceeds current-format maximum {MAX_CURRENT_SAVE_HEADER_SIZE}"
    );
    let header_end = SAVE_HEADER_LEAD_SIZE
        .checked_add(header_size)
        .context("save header end overflow")?;
    ensure!(
        header_end as u64 <= file_length,
        "save header extends beyond physical file"
    );
    Ok(header_end)
}

fn validate_save_envelope(header: &[u8], file_length: u64) -> anyhow::Result<()> {
    let header_end = current_save_header_end(header, file_length)?;
    ensure!(
        header_end <= header.len(),
        "save header exceeds captured envelope"
    );
    // Do not let malformed length-prefixed fields consume screenshot bytes
    // merely because the captured prefix extends beyond the encoded header.
    let mut cursor = HeaderCursor::at(&header[..header_end], SAVE_HEADER_LEAD_SIZE)?;

    ensure!(
        cursor.framed_u32("format version")? == CURRENT_SAVE_VERSION,
        "unexpected save format version"
    );

    // FalloutNV.exe's two physical-file readers at 0x0084D8C0 and 0x0084DAB0
    // use this exact version-0x30 discriminator. If the next u32 is followed by
    // a separator, it is screenshot width and the optional 64-byte language
    // block is absent; otherwise the readers consume that block and one more
    // separator first. The omitted form defaults to ENGLISH. Mirror the
    // accepting reader contract rather than assuming every compatible writer
    // emits the language block.
    if !cursor.spacer_follows(size_of::<u32>(), "screenshot width")? {
        cursor.framed(64, "language block")?;
    }

    let width = cursor.framed_u32("screenshot width")?;
    let height = cursor.framed_u32("screenshot height")?;
    cursor.framed_u32("save index")?;
    cursor.string("player name")?;
    cursor.string("player karma")?;
    cursor.framed_u32("player level")?;
    cursor.string("player location")?;
    cursor.string("play time")?;

    ensure!(
        cursor.position == header_end,
        "save header size does not match encoded fields"
    );
    ensure!(
        width != 0 && height != 0,
        "empty save screenshot dimensions"
    );
    // The physical reader multiplies these u32 values in 32-bit registers
    // before advancing over the RGB image (0x0084DA34-0x0084DA45). Reject
    // arithmetic that would wrap the consumer to an earlier body boundary.
    // There is intentionally no policy-sized cap: high-resolution screenshots
    // are valid when their exact 32-bit size fits inside the physical file.
    let screenshot_size = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(3))
        .context("save screenshot size overflow")?;
    let body_start = u64::try_from(header_end)
        .context("save header position overflow")?
        .checked_add(u64::from(screenshot_size))
        .context("save body position overflow")?;
    ensure!(
        file_length > body_start,
        "save ends before its changed-record body"
    );
    Ok(())
}

fn read_completed_save_envelope(
    temp: &mut DurableFile,
    file_length: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut lead = [0; SAVE_HEADER_LEAD_SIZE];
    let lead_length = temp
        .read_prefix(&mut lead)
        .context("read temporary save header lead")?;
    ensure!(
        lead_length == lead.len(),
        "truncated save header lead: read {lead_length} of {} bytes",
        lead.len()
    );

    let header_end = current_save_header_end(&lead, file_length)?;
    let mut envelope = vec![0; header_end];
    let envelope_length = temp
        .read_prefix(&mut envelope)
        .context("read complete temporary save header")?;
    ensure!(
        envelope_length == envelope.len(),
        "truncated save header: read {envelope_length} of {} bytes",
        envelope.len()
    );
    Ok(envelope)
}

fn commit_save(paths: &SavePaths) -> anyhow::Result<()> {
    let backup_count = save_backup_count(paths.final_path.as_bytes().len());
    let transaction_backup = transaction_backup_path(&paths.final_path);

    // A process can stop after replacement starts but before the transient
    // rollback copy is cleaned up. Recover a missing final before validating
    // the next temporary file: even a malformed new save must not prevent
    // restoration of the previously flushed good save.
    //
    // A maximum-length first-save path may have no room for ".txn". No prior
    // rollback copy can exist in that case, and promotion does not need one
    // until a final exists, so defer that path-length error to preparation.
    if let Ok(recovery) = transaction_backup.as_deref() {
        let mut filesystem = WindowsSavePromotionFileSystem;
        reconcile_transaction_recovery(&mut filesystem, &paths.final_path, recovery)?;
    }

    {
        let mut temp =
            open_existing_file_for_flush(&paths.temp).context("open completed temporary save")?;
        let file_length = temp.len().context("read temporary save length")?;
        let validation = (|| {
            ensure!(file_length != 0, "temporary save is empty");
            let envelope = read_completed_save_envelope(&mut temp, file_length)?;
            validate_save_envelope(&envelope, file_length)
        })();
        if let Err(error) = validation {
            STRUCTURE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            latch_save_failure(FAILURE_STRUCTURE);
            return Err(error).context("validate completed save envelope");
        }
        temp.flush().map_err(|error| {
            latch_save_failure(FAILURE_DURABLE_FLUSH);
            anyhow!(error)
        })?;
    }

    let mut filesystem = WindowsSavePromotionFileSystem;
    promote_save(&mut filesystem, paths, backup_count, transaction_backup)
}

trait SavePromotionFileSystem {
    fn exists(&mut self, path: &CStr) -> anyhow::Result<bool>;
    fn delete_if_exists(&mut self, path: &CStr) -> anyhow::Result<()>;
    fn move_new_write_through(&mut self, source: &CStr, destination: &CStr) -> anyhow::Result<()>;
    fn move_replace_write_through(
        &mut self,
        source: &CStr,
        destination: &CStr,
    ) -> anyhow::Result<()>;
    fn copy_and_flush(&mut self, source: &CStr, destination: &CStr) -> anyhow::Result<()>;
}

struct WindowsSavePromotionFileSystem;

impl SavePromotionFileSystem for WindowsSavePromotionFileSystem {
    fn exists(&mut self, path: &CStr) -> anyhow::Result<bool> {
        file_exists(path).map_err(Into::into)
    }

    fn delete_if_exists(&mut self, path: &CStr) -> anyhow::Result<()> {
        delete_file_if_exists(path).map_err(Into::into)
    }

    fn move_new_write_through(&mut self, source: &CStr, destination: &CStr) -> anyhow::Result<()> {
        move_file_write_through(source, destination).map_err(Into::into)
    }

    fn move_replace_write_through(
        &mut self,
        source: &CStr,
        destination: &CStr,
    ) -> anyhow::Result<()> {
        move_file_replace_write_through(source, destination).map_err(Into::into)
    }

    fn copy_and_flush(&mut self, source: &CStr, destination: &CStr) -> anyhow::Result<()> {
        copy_file_new(source, destination).context("copy old final to recovery path")?;
        let recovery =
            open_existing_file_for_flush(destination).context("open copied save recovery image")?;
        recovery.flush().context("flush copied save recovery image")
    }
}

fn reconcile_transaction_recovery<F: SavePromotionFileSystem>(
    filesystem: &mut F,
    final_path: &CStr,
    recovery: &CStr,
) -> anyhow::Result<()> {
    let final_exists = filesystem.exists(final_path)?;
    if !filesystem.exists(recovery)? {
        return Ok(());
    }

    if final_exists {
        // If replacement committed, final is the new save; if it did not, final
        // is still the old save. Either image is complete. A transient copy
        // alongside it is stale, not authoritative.
        filesystem
            .delete_if_exists(recovery)
            .context("remove stale transaction recovery file")
    } else {
        filesystem
            .move_new_write_through(recovery, final_path)
            .context("restore final save from interrupted transaction")
    }
}

fn promote_save<F: SavePromotionFileSystem>(
    filesystem: &mut F,
    paths: &SavePaths,
    backup_count: usize,
    transaction_backup: anyhow::Result<CString>,
) -> anyhow::Result<()> {
    if !filesystem.exists(&paths.final_path)? {
        filesystem
            .move_new_write_through(&paths.temp, &paths.final_path)
            .context("promote first save")?;
        return Ok(());
    }

    let recovery = transaction_backup?;
    filesystem
        .delete_if_exists(&recovery)
        .context("remove stale transaction recovery file")?;

    if backup_count != 0 {
        let oldest = backup_path(&paths.final_path, backup_count)?;
        filesystem
            .delete_if_exists(&oldest)
            .context("remove oldest save backup")?;

        for index in (1..backup_count).rev() {
            let source = backup_path(&paths.final_path, index)?;
            if filesystem.exists(&source)? {
                let destination = backup_path(&paths.final_path, index + 1)?;
                filesystem
                    .move_new_write_through(&source, &destination)
                    .with_context(|| format!("rotate save backup {index}"))?;
            }
        }
    }

    // Copying, reopening, and flushing the old final before replacement makes
    // the rollback image independent from rename behavior. This is the key
    // distinction from ReplaceFileA: promotion performs only the ordinary
    // same-volume rename family used by the engine and leaves an
    // already-durable old image outside that operation.
    if let Err(error) = filesystem.copy_and_flush(&paths.final_path, &recovery) {
        let cleanup = filesystem.delete_if_exists(&recovery);
        return match cleanup {
            Ok(()) => Err(error).context("prepare durable save recovery image"),
            Err(cleanup_error) => Err(anyhow!(
                "prepare durable save recovery image: {error:#}; partial recovery cleanup also failed: {cleanup_error:#}"
            )),
        };
    }

    if let Err(replacement_error) =
        filesystem.move_replace_write_through(&paths.temp, &paths.final_path)
    {
        if filesystem.exists(&paths.final_path)? {
            if !filesystem.exists(&paths.temp)? {
                // A consumed source plus an extant destination is the
                // postcondition of a committed rename, even if a compatibility
                // layer reports an error afterward. Do not run the fallback:
                // it would move the newly committed final out of place while
                // looking for a temporary source that no longer exists.
                log::warn!(
                    "[SAVE] Replacement reported failure after consuming the temporary file; treating the extant final as committed: {replacement_error:#}"
                );
            } else {
                // Some compatibility layers implement the engine's ordinary
                // rename path but not destination replacement. Once the direct
                // atomic form proves unavailable, fall back to the exact two
                // vacant-destination rename shape used by 0x00850100. The
                // already flushed `.txn` bounds its crash window: after the
                // first rename, the old save remains recoverable at that path.
                if let Err(fallback_error) =
                    promote_with_vacant_destination(filesystem, paths, &recovery)
                {
                    if let Err(recovery_error) =
                        recover_failed_promotion(filesystem, &paths.final_path, &recovery)
                    {
                        return Err(anyhow!(
                            "direct replacement failed: {replacement_error:#}; compatible rename fallback failed: {fallback_error:#}; recovery also failed: {recovery_error:#}"
                        ));
                    }
                    return Err(anyhow!(
                        "direct replacement failed: {replacement_error:#}; compatible rename fallback failed: {fallback_error:#}"
                    ));
                }
                log::warn!(
                    "[SAVE] Direct replacement was unavailable; committed through the recoverable engine-compatible rename sequence: {replacement_error:#}"
                );
            }
        } else {
            if let Err(recovery_error) =
                recover_failed_promotion(filesystem, &paths.final_path, &recovery)
            {
                return Err(anyhow!(
                    "save replacement failed: {replacement_error:#}; recovery also failed: {recovery_error:#}"
                ));
            }
            return Err(replacement_error).context("replace final save");
        }
    }

    let recovery_cleanup = if backup_count == 0 {
        filesystem.delete_if_exists(&recovery)
    } else {
        let first_backup = backup_path(&paths.final_path, 1)?;
        filesystem.move_new_write_through(&recovery, &first_backup)
    };
    if let Err(error) = recovery_cleanup {
        // The commit point is the successful temporary-to-final replacement.
        // Failing the later backup-name cleanup must not report Save Failed
        // after a new final has already been published. The durable `.txn`
        // remains recoverable and will be reconciled on the next transaction.
        log::warn!(
            "[SAVE] Final save committed but its recovery backup could not be finalized: {error:#}"
        );
    }
    Ok(())
}

fn promote_with_vacant_destination<F: SavePromotionFileSystem>(
    filesystem: &mut F,
    paths: &SavePaths,
    recovery: &CStr,
) -> anyhow::Result<()> {
    filesystem
        .delete_if_exists(recovery)
        .context("clear copied recovery before compatible rename")?;
    filesystem
        .move_new_write_through(&paths.final_path, recovery)
        .context("move old final to transaction recovery path")?;

    if let Err(promotion_error) = filesystem.move_new_write_through(&paths.temp, &paths.final_path)
    {
        if let Err(recovery_error) =
            recover_failed_promotion(filesystem, &paths.final_path, recovery)
        {
            return Err(anyhow!(
                "move temporary save to vacant final path: {promotion_error:#}; recovery also failed: {recovery_error:#}"
            ));
        }
        return Err(promotion_error).context("move temporary save to vacant final path");
    }
    Ok(())
}

fn recover_failed_promotion<F: SavePromotionFileSystem>(
    filesystem: &mut F,
    final_path: &CStr,
    recovery: &CStr,
) -> anyhow::Result<()> {
    if filesystem.exists(final_path)? || !filesystem.exists(recovery)? {
        return Ok(());
    }
    filesystem
        .move_new_write_through(recovery, final_path)
        .context("move durable recovery image back to final path")
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
    *SAVE_SPEED_SNAPSHOT.lock() = None;
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
    if owner.is_null() {
        LOAD_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        log::error!("[SAVE] Load rejected because its owner is null");
        return 0;
    }
    if ACTIVE_LOAD_OWNER
        .compare_exchange(0, owner as usize, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        LOAD_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        set_load_error_flag(owner, true);
        log::error!("[SAVE] Concurrent or reentrant load rejected before form mutation");
        return 0;
    }
    // Publish the owner thread before the native load begins. Character load
    // can also run for unrelated engine work; the callsite guard must never
    // borrow this transaction's changed-record pointer from another thread.
    ACTIVE_LOAD_THREAD.store(get_current_thread_id(), Ordering::Release);

    crate::mods::diagnostics::mark_load_site(
        crate::mods::diagnostics::LoadSite::ChangedFormOwnerEnter,
    );
    ACTIVE_CHANGED_RECORD.store(0, Ordering::Release);
    LOAD_REJECTED.store(false, Ordering::Release);
    let unresolved_before = UNRESOLVED_RECORDS.load(Ordering::Relaxed);
    let result = unsafe { original(owner, file, mode) };
    crate::mods::diagnostics::mark_load_site(
        crate::mods::diagnostics::LoadSite::ChangedFormOwnerExit,
    );

    let rejected = LOAD_REJECTED.swap(false, Ordering::AcqRel);
    if rejected {
        // A rejection is terminal. Clearing this bit here used to erase the
        // malformed-read decision and allowed the owner to report success.
        LOAD_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        set_load_error_flag(owner, true);
        log::error!("[SAVE] Malformed save data rejected; load owner forced to failure");
    }
    let unresolved = UNRESOLVED_RECORDS
        .load(Ordering::Relaxed)
        .wrapping_sub(unresolved_before);
    if unresolved != 0 {
        log::info!(
            "[SAVE] Skipped {unresolved} changed record(s) whose forms belong to unavailable content"
        );
    }
    ACTIVE_CHANGED_RECORD.store(0, Ordering::Release);
    ACTIVE_LOAD_THREAD.store(0, Ordering::Release);
    ACTIVE_LOAD_OWNER.store(0, Ordering::Release);

    // The decompiler models this engine function as void, but its only caller
    // consumes AL immediately after the call. Zero means missing masters and
    // opens the confirmation menu; nonzero continues or completes the load.
    // Returning after the atomic cleanup without preserving this byte makes a
    // valid load look like a new missing-content decision. A malformed load is
    // different: the owner must not publish its original success byte.
    if rejected { 0 } else { result }
}

unsafe extern "thiscall" fn hook_player_load(player: *mut c_void, argument: u32, mode: u32) {
    let Ok(original) = PLAYER_LOAD_HOOK.original() else {
        mark_load_rejected("PlayerCharacter load trampoline unavailable");
        return;
    };
    if ACTIVE_LOAD_OWNER.load(Ordering::Acquire) != 0
        && let Err(error) = validate_player_load_speed_block(player)
    {
        PLAYER_LOAD_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        log::error!("[SAVE] PlayerCharacter actor-value preflight failed: {error:#}");
        mark_load_rejected("invalid PlayerCharacter actor-value block");
        return;
    }
    unsafe { original(player, argument, mode) };
}

unsafe extern "thiscall" fn hook_actor_inventory_load_first(character: *mut c_void, mode: u8) {
    unsafe {
        hook_actor_inventory_load(
            &ACTOR_INVENTORY_LOAD_FIRST_CALL_HOOK,
            "first",
            character,
            mode,
        )
    };
}

unsafe extern "thiscall" fn hook_actor_inventory_load_second(character: *mut c_void, mode: u8) {
    unsafe {
        hook_actor_inventory_load(
            &ACTOR_INVENTORY_LOAD_SECOND_CALL_HOOK,
            "second",
            character,
            mode,
        )
    };
}

unsafe fn hook_actor_inventory_load(
    hook: &'static Rel32CallHookContainer<ActorInventoryLoadFn>,
    phase: &'static str,
    character: *mut c_void,
    mode: u8,
) {
    let Ok(original) = hook.original() else {
        if active_load_runs_on_current_thread() {
            mark_load_rejected("Character inventory load predecessor unavailable");
        }
        log::error!("[ACTOR_CONTAINER] Character inventory load {phase} predecessor unavailable");
        return;
    };

    let preflight = if active_load_runs_on_current_thread() {
        unsafe { preflight_actor_inventory_load(character) }
    } else {
        // Character load has callers outside changed-record application. They
        // do not own a transaction that can roll back partial mutation, so the
        // focused save-integrity policy must leave them on their predecessor.
        Ok(())
    };

    if let Err(error) = run_actor_inventory_load(preflight, || unsafe { original(character, mode) })
    {
        let record = mark_active_changed_record_rejected();
        let total = ACTOR_CONTAINER_LOAD_REJECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
        if total == 1 || total.is_power_of_two() {
            log::error!(
                "[ACTOR_CONTAINER] rejected corrupt live actor container before Character inventory load: phase={phase} mode={mode} character=0x{:08X} record=0x{record:08X} issue={error:?} total={total}",
                character as usize,
            );
        }
        // Returning from this callsite skips only the crash-producing
        // inventory owner. The enclosing Character loader unwinds normally,
        // while the latched owner error prevents its partial state from being
        // reported as a successful load. Live inventory is never detached.
        mark_load_rejected("invalid dynamic actor container");
    }
}

fn run_actor_inventory_load<E>(preflight: Result<(), E>, original: impl FnOnce()) -> Result<(), E> {
    preflight?;
    original();
    Ok(())
}

fn active_load_runs_on_current_thread() -> bool {
    if ACTIVE_LOAD_OWNER.load(Ordering::Acquire) == 0 {
        return false;
    }
    let thread = ACTIVE_LOAD_THREAD.load(Ordering::Acquire);
    thread != 0 && thread == get_current_thread_id()
}

unsafe fn preflight_actor_inventory_load(
    character: *mut c_void,
) -> Result<(), ActorInventoryLoadError> {
    if character.is_null() {
        return Err(ActorInventoryLoadError::NullCharacter);
    }

    // The exact native callsites place their live Character `this` pointer in
    // ECX and immediately call the predecessor. That caller-owned lifetime is
    // the proof for this one embedded read; using a page-readability probe here
    // would neither prove object identity nor pin the Character against reuse.
    let base_form = unsafe {
        ptr::read_unaligned(
            character
                .cast::<u8>()
                .add(TES_OBJECT_REFR_BASE_FORM_OFFSET)
                .cast::<*mut c_void>(),
        )
    };
    if base_form.is_null() {
        return Err(ActorInventoryLoadError::NullBaseForm);
    }

    actor_container_guard::validate_live_actor_container(base_form)
        .map_err(ActorInventoryLoadError::InvalidContainer)
}

fn mark_active_changed_record_rejected() -> usize {
    let record = ACTIVE_CHANGED_RECORD.load(Ordering::Acquire) as *mut ChangedRecord;
    if record.is_null() || !is_changed_record(unsafe { &raw mut (*record).buffer }) {
        return 0;
    }

    // LOAD_APPLY_HOOK owns this record for the duration of the predecessor
    // call. Marking the engine's native rejection bit preserves its later-pass
    // behavior in addition to the whole-load error latched below.
    mark_changed_record_rejected(record);
    record as usize
}

fn player_speed_block_layout(version: u8) -> Option<(usize, usize, usize)> {
    if !(31..90).contains(&version) {
        return None;
    }
    let (array_size, array_count) = if version < 49 {
        (0x130usize, 2usize)
    } else if version < 59 {
        (0x130usize, 3usize)
    } else {
        (0x134usize, 3usize)
    };
    let minimum_size = size_of::<u16>()
        .checked_add(array_size.checked_mul(array_count)?)?
        .checked_add(size_of::<u32>())?;
    Some((array_size, array_count, minimum_size))
}

fn player_block_within_record(
    record_data: usize,
    record_size: usize,
    cursor: usize,
    block_size: usize,
) -> bool {
    let Some(record_end) = record_data.checked_add(record_size) else {
        return false;
    };
    let Some(block_end) = cursor
        .checked_add(4)
        .and_then(|address| address.checked_add(block_size))
    else {
        return false;
    };
    cursor >= record_data && block_end <= record_end
}

fn validate_player_load_speed_block(player: *mut c_void) -> anyhow::Result<()> {
    ensure!(!player.is_null(), "PlayerCharacter load target is null");
    let player_singleton = PLAYER_SINGLETON as *const *mut c_void;
    validate_memory_range(player_singleton.cast(), size_of::<usize>())
        .context("validate PlayerCharacter singleton")?;
    ensure!(
        unsafe { ptr::read_unaligned(player_singleton) } == player,
        "PlayerCharacter load target does not match singleton"
    );

    let manager_singleton = SAVELOAD_SINGLETON as *const *mut c_void;
    validate_memory_range(manager_singleton.cast(), size_of::<usize>())
        .context("validate TESSaveLoadGame singleton")?;
    let manager = unsafe { ptr::read_unaligned(manager_singleton) };
    ensure!(!manager.is_null(), "TESSaveLoadGame singleton is null");

    let version_getter =
        unsafe { FnPtr::<SaveVersionFn>::from_address_unchecked(SAVE_VERSION_ADDR) };
    let version = unsafe { version_getter.as_fn()(manager) };
    let Some((array_size, array_count, minimum_size)) = player_speed_block_layout(version) else {
        return Ok(());
    };

    let cursor_slot = unsafe { (manager as *const u8).add(0x14).cast::<*const u8>() };
    validate_memory_range(cursor_slot.cast(), size_of::<usize>())
        .context("validate save cursor slot")?;
    let cursor = unsafe { ptr::read_unaligned(cursor_slot) };
    ensure!(!cursor.is_null(), "save cursor is null");
    validate_memory_range(cursor.cast(), 4 + size_of::<u16>())
        .context("validate PlayerCharacter block prefix")?;
    ensure!(
        unsafe { std::slice::from_raw_parts(cursor, 4) } == b"KOLB",
        "PlayerCharacter block marker mismatch"
    );

    let size_address = unsafe { cursor.add(4).cast::<u16>() };
    let block_size = usize::from(unsafe { ptr::read_unaligned(size_address) });
    ensure!(
        block_size >= minimum_size,
        "PlayerCharacter block is too short: {block_size} < {minimum_size}"
    );

    let record = ACTIVE_CHANGED_RECORD.load(Ordering::Acquire) as *mut ChangedRecord;
    ensure!(
        !record.is_null(),
        "active PlayerCharacter changed record is unavailable"
    );
    validate_memory_range(record.cast(), size_of::<ChangedRecord>())
        .context("validate active PlayerCharacter changed record")?;
    ensure!(
        is_changed_record(unsafe { &raw mut (*record).buffer }),
        "active PlayerCharacter record has an unexpected layout"
    );
    let record_data = unsafe { ptr::read_unaligned(&raw const (*record).buffer.data) } as usize;
    let record_size =
        usize::try_from(unsafe { ptr::read_unaligned(&raw const (*record).buffer.size) })
            .context("changed-record size overflow")?;
    ensure!(record_data != 0, "active changed-record payload is null");
    ensure!(
        player_block_within_record(record_data, record_size, cursor as usize, block_size),
        "PlayerCharacter block exceeds changed-record payload"
    );
    validate_memory_range(size_address.cast(), block_size)
        .context("validate complete PlayerCharacter actor-value block")?;

    let payload = unsafe { cursor.add(4 + size_of::<u16>()) };
    for array_index in 0..array_count {
        let speed_offset = array_index
            .checked_mul(array_size)
            .and_then(|offset| offset.checked_add(PLAYER_SPEED_VALUE_INDEX * size_of::<f32>()))
            .context("PlayerCharacter SpeedMult offset overflow")?;
        let value = unsafe { ptr::read_unaligned(payload.add(speed_offset).cast::<u32>()) };
        ensure!(
            f32::from_bits(value).is_finite(),
            "PlayerCharacter SpeedMult slot {array_index} is not finite"
        );
    }
    Ok(())
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
    ACTIVE_CHANGED_RECORD.store(record as usize, Ordering::Release);
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

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::HashMap};

    use super::*;

    #[derive(Default)]
    struct MockPromotionFileSystem {
        files: HashMap<Vec<u8>, Vec<u8>>,
        fail_copy: bool,
        fail_atomic_replacement_preserving_final: bool,
        fail_atomic_replacement_after_commit: bool,
        fail_promotion_after_removing_final: bool,
    }

    impl MockPromotionFileSystem {
        fn key(path: &CStr) -> Vec<u8> {
            path.to_bytes().to_vec()
        }

        fn put(&mut self, path: &CStr, contents: &[u8]) {
            self.files.insert(Self::key(path), contents.to_vec());
        }

        fn contents(&self, path: &CStr) -> Option<&[u8]> {
            self.files.get(&Self::key(path)).map(Vec::as_slice)
        }

        fn move_file(&mut self, source: &CStr, destination: &CStr) -> anyhow::Result<()> {
            let contents = self
                .files
                .remove(&Self::key(source))
                .context("mock move source is missing")?;
            self.files.insert(Self::key(destination), contents);
            Ok(())
        }
    }

    impl SavePromotionFileSystem for MockPromotionFileSystem {
        fn exists(&mut self, path: &CStr) -> anyhow::Result<bool> {
            Ok(self.files.contains_key(&Self::key(path)))
        }

        fn delete_if_exists(&mut self, path: &CStr) -> anyhow::Result<()> {
            self.files.remove(&Self::key(path));
            Ok(())
        }

        fn move_new_write_through(
            &mut self,
            source: &CStr,
            destination: &CStr,
        ) -> anyhow::Result<()> {
            ensure!(
                !self.files.contains_key(&Self::key(destination)),
                "mock vacant-destination move found an existing destination"
            );
            self.move_file(source, destination)
        }

        fn move_replace_write_through(
            &mut self,
            source: &CStr,
            destination: &CStr,
        ) -> anyhow::Result<()> {
            if self.fail_atomic_replacement_after_commit {
                self.move_file(source, destination)?;
                return Err(anyhow!("injected post-commit replacement error"));
            }
            if self.fail_atomic_replacement_preserving_final {
                return Err(anyhow!("injected unsupported atomic replacement"));
            }
            if self.fail_promotion_after_removing_final
                && source.to_bytes().ends_with(b".tmp")
                && !destination.to_bytes().ends_with(b".tmp")
            {
                // Use a deliberately pessimistic failure model: the primitive
                // has removed the destination but returns failure before
                // consuming the source. Recovery must republish the old copy
                // even if a compatibility layer violates normal rename
                // failure expectations.
                self.files.remove(&Self::key(destination));
                return Err(anyhow!("injected promotion failure"));
            }

            self.move_file(source, destination)
        }

        fn copy_and_flush(&mut self, source: &CStr, destination: &CStr) -> anyhow::Result<()> {
            if self.fail_copy {
                return Err(anyhow!("injected recovery-copy failure"));
            }
            ensure!(
                !self.files.contains_key(&Self::key(destination)),
                "mock copy destination already exists"
            );
            let contents = self
                .files
                .get(&Self::key(source))
                .context("mock copy source is missing")?
                .clone();
            self.files.insert(Self::key(destination), contents);
            Ok(())
        }
    }

    fn mock_save_paths() -> SavePaths {
        SavePaths {
            temp: CString::new("quicksave.fos.tmp").unwrap(),
            final_path: CString::new("quicksave.fos").unwrap(),
        }
    }

    #[test]
    fn interrupted_transaction_restores_old_final_before_next_commit() {
        let paths = mock_save_paths();
        let recovery = transaction_backup_path(&paths.final_path).unwrap();
        let mut filesystem = MockPromotionFileSystem::default();
        filesystem.put(&recovery, b"old-good-save");

        reconcile_transaction_recovery(&mut filesystem, &paths.final_path, &recovery).unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"old-good-save".as_slice())
        );
        assert_eq!(filesystem.contents(&recovery), None);
    }

    #[test]
    fn completed_transaction_discards_stale_recovery_when_final_exists() {
        let paths = mock_save_paths();
        let recovery = transaction_backup_path(&paths.final_path).unwrap();
        let mut filesystem = MockPromotionFileSystem::default();
        filesystem.put(&paths.final_path, b"new-save");
        filesystem.put(&recovery, b"old-good-save");

        reconcile_transaction_recovery(&mut filesystem, &paths.final_path, &recovery).unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"new-save".as_slice())
        );
        assert_eq!(filesystem.contents(&recovery), None);
    }

    #[test]
    fn promotion_flushes_old_final_to_configured_backup_before_replacement() {
        let paths = mock_save_paths();
        let backup = backup_path(&paths.final_path, 1).unwrap();
        let mut filesystem = MockPromotionFileSystem::default();
        filesystem.put(&paths.temp, b"new-save");
        filesystem.put(&paths.final_path, b"old-good-save");
        filesystem.put(&backup, b"older-save");

        promote_save(
            &mut filesystem,
            &paths,
            1,
            transaction_backup_path(&paths.final_path),
        )
        .unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"new-save".as_slice())
        );
        assert_eq!(
            filesystem.contents(&backup),
            Some(b"old-good-save".as_slice())
        );
    }

    #[test]
    fn first_save_does_not_require_a_transaction_backup_path() {
        let paths = mock_save_paths();
        let mut filesystem = MockPromotionFileSystem::default();
        filesystem.put(&paths.temp, b"first-save");

        promote_save(
            &mut filesystem,
            &paths,
            0,
            Err(anyhow!("path has no room for transaction suffix")),
        )
        .unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"first-save".as_slice())
        );
        assert_eq!(filesystem.contents(&paths.temp), None);
    }

    #[test]
    fn configured_backup_rotation_preserves_every_available_generation() {
        let paths = mock_save_paths();
        let first_backup = backup_path(&paths.final_path, 1).unwrap();
        let second_backup = backup_path(&paths.final_path, 2).unwrap();
        let mut filesystem = MockPromotionFileSystem::default();
        filesystem.put(&paths.temp, b"new-save");
        filesystem.put(&paths.final_path, b"old-good-save");
        filesystem.put(&first_backup, b"older-save");
        filesystem.put(&second_backup, b"oldest-save");

        promote_save(
            &mut filesystem,
            &paths,
            2,
            transaction_backup_path(&paths.final_path),
        )
        .unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"new-save".as_slice())
        );
        assert_eq!(
            filesystem.contents(&first_backup),
            Some(b"old-good-save".as_slice())
        );
        assert_eq!(
            filesystem.contents(&second_backup),
            Some(b"older-save".as_slice())
        );
    }

    #[test]
    fn promotion_failure_recovers_when_final_name_disappears() {
        let paths = mock_save_paths();
        let recovery = transaction_backup_path(&paths.final_path).unwrap();
        let mut filesystem = MockPromotionFileSystem {
            fail_promotion_after_removing_final: true,
            ..Default::default()
        };
        filesystem.put(&paths.temp, b"new-save");
        filesystem.put(&paths.final_path, b"old-good-save");

        let error = promote_save(&mut filesystem, &paths, 0, Ok(recovery.clone()))
            .expect_err("injected replacement failure must abort the transaction")
            .to_string();

        assert!(error.contains("replace final save"));
        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"old-good-save".as_slice())
        );
        assert_eq!(
            filesystem.contents(&paths.temp),
            Some(b"new-save".as_slice())
        );
        assert_eq!(filesystem.contents(&recovery), None);
    }

    #[test]
    fn unavailable_atomic_replacement_uses_recoverable_engine_rename_sequence() {
        let paths = mock_save_paths();
        let recovery = transaction_backup_path(&paths.final_path).unwrap();
        let mut filesystem = MockPromotionFileSystem {
            fail_atomic_replacement_preserving_final: true,
            ..Default::default()
        };
        filesystem.put(&paths.temp, b"new-save");
        filesystem.put(&paths.final_path, b"old-good-save");

        promote_save(&mut filesystem, &paths, 0, Ok(recovery.clone())).unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"new-save".as_slice())
        );
        assert_eq!(filesystem.contents(&paths.temp), None);
        assert_eq!(filesystem.contents(&recovery), None);
    }

    #[test]
    fn post_commit_error_does_not_move_new_final_back_out_of_place() {
        let paths = mock_save_paths();
        let recovery = transaction_backup_path(&paths.final_path).unwrap();
        let mut filesystem = MockPromotionFileSystem {
            fail_atomic_replacement_after_commit: true,
            ..Default::default()
        };
        filesystem.put(&paths.temp, b"new-save");
        filesystem.put(&paths.final_path, b"old-good-save");

        promote_save(&mut filesystem, &paths, 0, Ok(recovery.clone())).unwrap();

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"new-save".as_slice())
        );
        assert_eq!(filesystem.contents(&paths.temp), None);
        assert_eq!(filesystem.contents(&recovery), None);
    }

    #[test]
    fn recovery_copy_failure_cannot_remove_existing_final() {
        let paths = mock_save_paths();
        let mut filesystem = MockPromotionFileSystem {
            fail_copy: true,
            ..Default::default()
        };
        filesystem.put(&paths.temp, b"new-save");
        filesystem.put(&paths.final_path, b"old-good-save");

        promote_save(
            &mut filesystem,
            &paths,
            0,
            transaction_backup_path(&paths.final_path),
        )
        .expect_err("a missing durable rollback image must abort promotion");

        assert_eq!(
            filesystem.contents(&paths.final_path),
            Some(b"old-good-save".as_slice())
        );
        assert_eq!(
            filesystem.contents(&paths.temp),
            Some(b"new-save".as_slice())
        );
    }

    fn push_string(fields: &mut Vec<u8>, value: &[u8]) {
        fields.extend_from_slice(&(value.len() as u16).to_le_bytes());
        fields.push(b'|');
        if !value.is_empty() {
            fields.extend_from_slice(value);
            fields.push(b'|');
        }
    }

    fn current_header_with_strings(
        width: u32,
        height: u32,
        language_block: bool,
        strings: [&[u8]; 4],
    ) -> Vec<u8> {
        let mut fields = Vec::new();
        fields.extend_from_slice(&CURRENT_SAVE_VERSION.to_le_bytes());
        fields.push(b'|');
        if language_block {
            fields.extend_from_slice(&[0; 64]);
            fields.push(b'|');
        }
        fields.extend_from_slice(&width.to_le_bytes());
        fields.push(b'|');
        fields.extend_from_slice(&height.to_le_bytes());
        fields.push(b'|');
        fields.extend_from_slice(&7u32.to_le_bytes());
        fields.push(b'|');
        push_string(&mut fields, strings[0]);
        push_string(&mut fields, strings[1]);
        fields.extend_from_slice(&20u32.to_le_bytes());
        fields.push(b'|');
        push_string(&mut fields, strings[2]);
        push_string(&mut fields, strings[3]);

        let mut header = Vec::new();
        header.extend_from_slice(SAVE_MAGIC);
        header.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        header.extend_from_slice(&fields);
        header
    }

    fn current_header(width: u32, height: u32, language_block: bool) -> Vec<u8> {
        current_header_with_strings(
            width,
            height,
            language_block,
            [b"Courier", b"Mojave", b"Goodsprings", b"00.10.00"],
        )
    }

    #[test]
    fn current_save_envelope_accepts_both_engine_header_layouts() {
        for language_block in [true, false] {
            let header = current_header(320, 180, language_block);
            let file_length = header.len() as u64 + 320 * 180 * 3 + 1;
            validate_save_envelope(&header, file_length).unwrap();
        }
    }

    #[test]
    fn current_save_envelope_accepts_empty_engine_string_fields() {
        let defaults: [&[u8]; 4] = [b"Courier", b"Neutral", b"Goodsprings", b"00.10.00"];
        for language_block in [true, false] {
            for empty_mask in 0..(1 << defaults.len()) {
                let mut strings = defaults;
                for (index, string) in strings.iter_mut().enumerate() {
                    if empty_mask & (1 << index) != 0 {
                        *string = b"";
                    }
                }
                let header = current_header_with_strings(320, 180, language_block, strings);
                let file_length = header.len() as u64 + 320 * 180 * 3 + 1;

                if language_block && empty_mask == 1 {
                    assert_eq!(&header[100..106], &[0, 0, b'|', 7, 0, b'|']);
                }
                validate_save_envelope(&header, file_length).unwrap();
            }
        }
    }

    #[test]
    fn header_cursor_matches_independent_engine_string_branch_fixtures() {
        // These literal byte fixtures deliberately do not use push_string.
        // They keep the parser test independent from the convenience builder
        // used by the full-envelope tests.
        let empty_then_scalar = [0, 0, b'|', 7, 0, 0, 0, b'|'];
        let mut cursor = HeaderCursor::at(&empty_then_scalar, 0).unwrap();
        cursor.string("empty string").unwrap();
        assert_eq!(cursor.position, 3);
        assert_eq!(cursor.framed_u32("following scalar").unwrap(), 7);
        assert_eq!(cursor.position, empty_then_scalar.len());

        let nonempty_then_empty = [3, 0, b'|', b'a', b'b', b'c', b'|', 0, 0, b'|'];
        let mut cursor = HeaderCursor::at(&nonempty_then_empty, 0).unwrap();
        cursor.string("nonempty string").unwrap();
        assert_eq!(cursor.position, 7);
        cursor.string("following empty string").unwrap();
        assert_eq!(cursor.position, nonempty_then_empty.len());
    }

    #[test]
    fn current_save_envelope_accepts_metadata_larger_than_legacy_prefix() {
        let large_name = vec![b'X'; 4096];
        let header = current_header_with_strings(
            320,
            180,
            true,
            [
                large_name.as_slice(),
                b"Neutral",
                b"Goodsprings",
                b"00.10.00",
            ],
        );
        let file_length = header.len() as u64 + 320 * 180 * 3 + 1;

        assert!(header.len() > 2048);
        assert_eq!(
            current_save_header_end(&header[..SAVE_HEADER_LEAD_SIZE], file_length).unwrap(),
            header.len()
        );
        validate_save_envelope(&header, file_length).unwrap();
    }

    #[test]
    fn current_save_header_bound_matches_schema_and_rejects_larger_claims() {
        assert_eq!(MAX_CURRENT_SAVE_HEADER_SIZE, 262_246);
        let maximum_string = vec![b'X'; u16::MAX as usize];
        let maximum_header = current_header_with_strings(
            1,
            1,
            true,
            [
                maximum_string.as_slice(),
                maximum_string.as_slice(),
                maximum_string.as_slice(),
                maximum_string.as_slice(),
            ],
        );
        assert_eq!(
            maximum_header.len(),
            SAVE_HEADER_LEAD_SIZE + MAX_CURRENT_SAVE_HEADER_SIZE
        );
        validate_save_envelope(&maximum_header, maximum_header.len() as u64 + 4).unwrap();

        let mut lead = SAVE_MAGIC.to_vec();
        lead.extend_from_slice(&((MAX_CURRENT_SAVE_HEADER_SIZE + 1) as u32).to_le_bytes());

        let error = current_save_header_end(&lead, u64::MAX)
            .expect_err("a header larger than every current-format field must be rejected")
            .to_string();
        assert!(error.contains("exceeds current-format maximum"));
    }

    #[test]
    fn save_envelope_uses_engine_screenshot_arithmetic_not_policy_cap() {
        let header = current_header(8192, 4096, true);
        let screenshot_size = 8192u64 * 4096 * 3;
        assert!(screenshot_size > 64 * 1024 * 1024);
        validate_save_envelope(&header, header.len() as u64 + screenshot_size + 1).unwrap();

        let overflowing = current_header(u32::MAX, u32::MAX, true);
        let error = validate_save_envelope(&overflowing, u64::MAX)
            .expect_err("dimensions that wrap the engine's u32 RGB size must be rejected")
            .to_string();
        assert!(error.contains("screenshot size overflow"));
    }

    #[test]
    fn save_envelope_rejects_missing_nonempty_string_payload_separator() {
        let mut header = current_header(320, 180, true);
        let separator = header
            .windows(b"Courier|".len())
            .position(|window| window == b"Courier|")
            .expect("player name must be present in the test header")
            + b"Courier".len();
        header[separator] = 0;

        let error = validate_save_envelope(&header, u64::MAX)
            .expect_err("nonempty string without a trailing separator must be rejected")
            .to_string();
        assert!(error.contains("player name"));
    }

    #[test]
    fn save_envelope_rejects_bad_magic() {
        let mut header = current_header(320, 180, true);
        header[0] = b'X';
        assert!(validate_save_envelope(&header, u64::MAX).is_err());
    }

    #[test]
    fn save_envelope_rejects_inconsistent_header_size() {
        let mut header = current_header(320, 180, true);
        let encoded = u32::from_le_bytes(header[11..15].try_into().unwrap());
        header[11..15].copy_from_slice(&(encoded + 1).to_le_bytes());
        header.push(0);
        assert!(validate_save_envelope(&header, u64::MAX).is_err());
    }

    #[test]
    fn save_envelope_separator_error_identifies_field_and_offset() {
        let mut header = current_header(320, 180, false);
        let height_separator = SAVE_MAGIC.len() + size_of::<u32>() * 4 + 2;
        header[height_separator] = 0;

        let error = validate_save_envelope(&header, u64::MAX)
            .expect_err("invalid height separator must reject the envelope")
            .to_string();
        assert!(error.contains("screenshot height"));
        assert!(error.contains(&format!("offset {height_separator}")));
        assert!(error.contains("found 0x00"));
    }

    #[test]
    fn save_envelope_rejects_missing_changed_record_body() {
        let header = current_header(320, 180, true);
        let screenshot_end = header.len() as u64 + 320 * 180 * 3;
        assert!(validate_save_envelope(&header, screenshot_end).is_err());
    }

    #[test]
    fn player_speed_layout_matches_versioned_actor_arrays() {
        assert_eq!(player_speed_block_layout(30), None);
        assert_eq!(player_speed_block_layout(31), Some((0x130, 2, 614)));
        assert_eq!(player_speed_block_layout(48), Some((0x130, 2, 614)));
        assert_eq!(player_speed_block_layout(49), Some((0x130, 3, 918)));
        assert_eq!(player_speed_block_layout(59), Some((0x134, 3, 930)));
        assert_eq!(player_speed_block_layout(90), None);
    }

    #[test]
    fn actor_inventory_preflight_suppresses_only_rejected_calls() {
        let calls = Cell::new(0);
        let rejected = run_actor_inventory_load(Err("corrupt"), || calls.set(calls.get() + 1));
        assert_eq!(rejected, Err("corrupt"));
        assert_eq!(calls.get(), 0);

        let accepted = run_actor_inventory_load::<()>(Ok(()), || calls.set(calls.get() + 1));
        assert_eq!(accepted, Ok(()));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn actor_inventory_callsite_fingerprints_cover_both_abis_in_order() {
        assert_eq!(
            ACTOR_INVENTORY_LOAD_FIRST_PREFIX_ADDR + ACTOR_INVENTORY_LOAD_FIRST_PREFIX.len(),
            ACTOR_INVENTORY_LOAD_FIRST_CALL_ADDR,
        );
        assert_eq!(
            ACTOR_INVENTORY_LOAD_FIRST_CALL_ADDR + 5,
            ACTOR_INVENTORY_LOAD_BETWEEN_ADDR,
        );
        assert_eq!(
            ACTOR_INVENTORY_LOAD_BETWEEN_ADDR + ACTOR_INVENTORY_LOAD_BETWEEN.len(),
            ACTOR_INVENTORY_LOAD_SECOND_CALL_ADDR,
        );
        assert_eq!(
            ACTOR_INVENTORY_LOAD_SECOND_CALL_ADDR + 5,
            ACTOR_INVENTORY_LOAD_SECOND_SUFFIX_ADDR,
        );
    }

    #[test]
    fn player_block_must_fit_changed_record_payload() {
        assert!(player_block_within_record(0x1000, 1024, 0x1010, 614));
        assert!(!player_block_within_record(0x1000, 620, 0x1010, 614));
        assert!(!player_block_within_record(0x1000, 1024, 0x0ff0, 614));
        assert!(!player_block_within_record(
            usize::MAX - 4,
            16,
            usize::MAX - 4,
            614,
        ));
    }
}
