//! Dynamic-actor `TESContainer` validation and retirement guard.
//!
//! Save-load replacement can retire runtime TESNPC/TESCreature forms through
//! the shared TESActorBase destructor at 0x005F77B0. Vanilla then clears the
//! embedded TESContainer list and trusts every FormCount and successor node.
//! Under gheap stress, one captured runtime actor reached that boundary with
//! an image vtable in the list head and a contemporaneous +5 interior free.
//!
//! This cold guard validates the complete list against the active allocator's
//! ownership contract before vanilla observes it. Gheap and Windows heaps have
//! exact live state. Vanilla SBM exposes exact cell geometry, per-page live
//! counts, and stable free-list links but no per-cell bitmap, so remaining
//! candidate fields receive the same complete structural validation before
//! acceptance. Nested forms must also resolve back to the same address through
//! the engine's live-form registry. No OS readability probe is used. Valid
//! lists are untouched. A corrupt list on an FFxxxxxx actor is detached as one
//! unit; its uncertain allocations are deliberately leaked rather than
//! dereferenced, repaired, or freed. The owning actor is already retiring, so
//! no live behavior remains.
//!
//! The save-integrity boundary also reuses the same complete validator before
//! vanilla expands a live Character's base inventory. That path never detaches
//! or repairs the container: a live actor still owns meaningful inventory, so
//! corruption must reject the whole load transaction instead. The live check
//! proves the dynamic actor base through allocator metadata and the loaded-form
//! registry before reading its embedded container head.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use libc::c_void;
use libpsycho::{ffi::fnptr::FnPtr, os::windows::hook::transaction::ModificationTransaction};

use super::statics;
use crate::mods::heap_replacer::{
    AllocatorMode,
    allocation_state::{self, AllocationState},
    current_mode, heap_validate,
};

const TESFORM_REF_ID_OFFSET: usize = 0x0C;
const TESFORM_TYPE_OFFSET: usize = 0x04;
const TESACTORBASE_CONTAINER_HEAD_OFFSET: usize = 0x68;
const FORM_COUNT_FORM_OFFSET: usize = 0x04;
const FORM_COUNT_EXTRA_OFFSET: usize = 0x08;
const FORM_COUNT_SIZE: usize = 0x0C;
const LIST_NODE_DATA_OFFSET: usize = 0x00;
const LIST_NODE_NEXT_OFFSET: usize = 0x04;
const LIST_NODE_SIZE: usize = 0x08;
const ENGINE_WORD_SIZE: usize = 4;
const TESFORM_MINIMUM_SIZE: usize = 0x10;
const TESACTORBASE_MINIMUM_SIZE: usize = TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_SIZE;
const TESNPC_FORM_TYPE: u8 = 0x2A;
const TESCREATURE_FORM_TYPE: u8 = 0x2B;
const DYNAMIC_FORM_ID_PREFIX: u32 = 0xFF00_0000;
const MAX_CONTAINER_ITEMS: usize = 65_536;
const LOADED_FORM_RESOLVER_ADDR: usize = 0x0048_39C0;

type LoadedFormResolverFn = unsafe extern "C" fn(u32) -> *mut c_void;

static DETACHED_DYNAMIC_ACTOR_CONTAINERS: AtomicU64 = AtomicU64::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllocationRole {
    FormCount,
    ContainerExtraData,
    ListNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContainerIssue {
    HeadShape {
        data: usize,
        next: usize,
    },
    Allocation {
        role: AllocationRole,
        ptr: usize,
        minimum: usize,
        state: AllocationState,
    },
    InvalidForm {
        form_count: usize,
        form: usize,
    },
    EmptyNode {
        node: usize,
    },
    Cycle {
        node: usize,
    },
    WalkLimit {
        limit: usize,
    },
}

/// Evidence returned when a live actor base cannot safely expose its
/// `TESContainer` to vanilla.
///
/// Fields remain private so callers cannot make recovery policy from partial
/// state. The save-integrity owner records the complete `Debug` value and
/// rejects the transaction; only this module interprets allocator details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LiveActorContainerError {
    actor: usize,
    ref_id: Option<u32>,
    head_data: Option<usize>,
    head_next: Option<usize>,
    issue: LiveActorContainerIssue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveActorContainerIssue {
    NullActor,
    ActorAllocation(AllocationState),
    UnexpectedDynamicType { type_id: u8 },
    RegistryMismatch { resolved: usize },
    Container(ContainerIssue),
}

/// Prepare allocator ownership classification used by both guard boundaries.
///
/// Initialization is idempotent. Save integrity calls this even when the
/// retirement hook is disabled so live-load validation never depends on an
/// unrelated configuration switch having populated the Windows heap cache.
pub(super) fn prepare_validation() {
    heap_validate::init_heap_cache();
}

pub(super) fn install() -> anyhow::Result<()> {
    prepare_validation();
    unsafe {
        statics::ACTOR_BASE_DTOR_HOOK.init(
            "actor_base_dtor_container_guard",
            statics::ACTOR_BASE_DTOR_ADDR as *mut c_void,
            hook_actor_base_dtor,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::ACTOR_BASE_DTOR_HOOK)?;
    transaction.commit();
    INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[ACTOR_CONTAINER] Dynamic actor retirement guard active ({})",
        current_mode().map_or("allocator pending", AllocatorMode::name),
    );
    Ok(())
}

pub(super) fn is_installed() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

pub unsafe extern "thiscall" fn hook_actor_base_dtor(actor: *mut c_void) {
    if let Some((ref_id, head_data, head_next, issue)) = unsafe { corrupt_dynamic_container(actor) }
    {
        unsafe { detach_container_head(actor) };
        log_detachment(actor, ref_id, head_data, head_next, issue);
    }

    match statics::ACTOR_BASE_DTOR_HOOK.original() {
        Ok(original) => unsafe { original(actor) },
        Err(error) => log::error!(
            "[ACTOR_CONTAINER] TESActorBase destructor trampoline missing: {:?}",
            error,
        ),
    }
}

unsafe fn corrupt_dynamic_container(
    actor: *mut c_void,
) -> Option<(u32, usize, usize, ContainerIssue)> {
    if actor.is_null() {
        return None;
    }

    let actor_addr = actor as usize;
    let ref_id = unsafe { read_owned_actor_word(actor_addr, TESFORM_REF_ID_OFFSET)? } as u32;
    if !is_dynamic_form_id(ref_id) {
        return None;
    }

    if current_mode() == Some(AllocatorMode::GheapAndScrapHeap)
        && !matches!(
            allocation_state::allocation_state(actor.cast_const()),
            AllocationState::Live { usable_size, .. }
                if usable_size >= TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_SIZE
        )
    {
        return None;
    }

    let head_data =
        unsafe { read_owned_actor_word(actor_addr, TESACTORBASE_CONTAINER_HEAD_OFFSET)? };
    let head_next = unsafe {
        read_owned_actor_word(
            actor_addr,
            TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_NEXT_OFFSET,
        )?
    };

    let result = validate_container(
        head_data,
        head_next,
        MAX_CONTAINER_ITEMS,
        allocation_state::read_allocation_words,
        valid_runtime_form,
    );
    result
        .err()
        .map(|issue| (ref_id, head_data, head_next, issue))
}

/// Validate a live actor base before vanilla traverses its container.
///
/// Static actor bases are intentionally outside this focused guard. Dynamic
/// `FFxxxxxx` TESNPC/TESCreature forms must be exact allocator-owned objects,
/// resolve back to the same address through the engine form registry, and own
/// a completely valid container list. The function performs no repair and is
/// suitable only while the native caller owns the actor base's lifetime.
pub(super) fn validate_live_actor_container(
    actor: *mut c_void,
) -> Result<(), LiveActorContainerError> {
    validate_live_actor_container_with(
        actor as usize,
        allocation_state::read_allocation_words,
        |ref_id| {
            let resolve = unsafe {
                FnPtr::<LoadedFormResolverFn>::from_address_unchecked(LOADED_FORM_RESOLVER_ADDR)
            }
            .as_fn();
            unsafe { resolve(ref_id) as usize }
        },
        |head_data, head_next| {
            validate_container(
                head_data,
                head_next,
                MAX_CONTAINER_ITEMS,
                allocation_state::read_allocation_words,
                valid_runtime_form,
            )
        },
    )
}

fn validate_live_actor_container_with(
    actor: usize,
    mut read_actor_words: impl FnMut(
        usize,
        usize,
        &[usize],
        &mut [usize],
    ) -> Result<(), AllocationState>,
    mut resolve_form: impl FnMut(u32) -> usize,
    validate_actor_container: impl FnOnce(usize, usize) -> Result<(), ContainerIssue>,
) -> Result<(), LiveActorContainerError> {
    if actor == 0 {
        return Err(LiveActorContainerError {
            actor,
            ref_id: None,
            head_data: None,
            head_next: None,
            issue: LiveActorContainerIssue::NullActor,
        });
    }

    // One allocator-owned snapshot covers identity and the embedded list head.
    // This matters for vanilla SBM, where the pool lock must remain held from
    // classification through the reads to exclude concurrent page purge.
    let mut actor_fields = [0usize; 4];
    if let Err(state) = read_actor_words(
        actor,
        TESACTORBASE_MINIMUM_SIZE,
        &[
            TESFORM_TYPE_OFFSET,
            TESFORM_REF_ID_OFFSET,
            TESACTORBASE_CONTAINER_HEAD_OFFSET,
            TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_NEXT_OFFSET,
        ],
        &mut actor_fields,
    ) {
        return Err(LiveActorContainerError {
            actor,
            ref_id: None,
            head_data: None,
            head_next: None,
            issue: LiveActorContainerIssue::ActorAllocation(state),
        });
    }

    let [type_word, ref_id_word, head_data, head_next] = actor_fields;
    let ref_id = ref_id_word as u32;
    if !is_dynamic_form_id(ref_id) {
        return Ok(());
    }

    let type_id = type_word as u8;
    if !matches!(type_id, TESNPC_FORM_TYPE | TESCREATURE_FORM_TYPE) {
        return Err(LiveActorContainerError {
            actor,
            ref_id: Some(ref_id),
            head_data: Some(head_data),
            head_next: Some(head_next),
            issue: LiveActorContainerIssue::UnexpectedDynamicType { type_id },
        });
    }

    let resolved = resolve_form(ref_id);
    if resolved != actor {
        return Err(LiveActorContainerError {
            actor,
            ref_id: Some(ref_id),
            head_data: Some(head_data),
            head_next: Some(head_next),
            issue: LiveActorContainerIssue::RegistryMismatch { resolved },
        });
    }

    validate_actor_container(head_data, head_next).map_err(|issue| LiveActorContainerError {
        actor,
        ref_id: Some(ref_id),
        head_data: Some(head_data),
        head_next: Some(head_next),
        issue: LiveActorContainerIssue::Container(issue),
    })
}

fn is_dynamic_form_id(ref_id: u32) -> bool {
    ref_id & DYNAMIC_FORM_ID_PREFIX == DYNAMIC_FORM_ID_PREFIX
}

fn validate_container(
    head_data: usize,
    head_next: usize,
    item_limit: usize,
    mut read_words: impl FnMut(usize, usize, &[usize], &mut [usize]) -> Result<(), AllocationState>,
    mut valid_form: impl FnMut(usize) -> bool,
) -> Result<(), ContainerIssue> {
    if head_data == 0 {
        return if head_next == 0 {
            Ok(())
        } else {
            Err(ContainerIssue::HeadShape {
                data: head_data,
                next: head_next,
            })
        };
    }

    validate_form_count(head_data, &mut read_words, &mut valid_form)?;

    let mut tortoise = head_next;
    let mut hare = head_next;
    let mut power = 1usize;
    let mut distance = 0usize;
    let mut visited = 1usize;

    while hare != 0 {
        if visited >= item_limit {
            return Err(ContainerIssue::WalkLimit { limit: item_limit });
        }

        let mut node_fields = [0usize; 2];
        read_allocation_fields(
            AllocationRole::ListNode,
            hare,
            LIST_NODE_SIZE,
            &[LIST_NODE_DATA_OFFSET, LIST_NODE_NEXT_OFFSET],
            &mut node_fields,
            &mut read_words,
        )?;
        let [data, next] = node_fields;
        if data == 0 {
            return Err(ContainerIssue::EmptyNode { node: hare });
        }
        validate_form_count(data, &mut read_words, &mut valid_form)?;

        hare = next;
        visited += 1;
        distance += 1;
        if hare != 0 && hare == tortoise {
            return Err(ContainerIssue::Cycle { node: hare });
        }
        if distance == power {
            tortoise = hare;
            power = power.saturating_mul(2);
            distance = 0;
        }
    }

    Ok(())
}

fn validate_form_count(
    form_count: usize,
    read_words: &mut impl FnMut(usize, usize, &[usize], &mut [usize]) -> Result<(), AllocationState>,
    valid_form: &mut impl FnMut(usize) -> bool,
) -> Result<(), ContainerIssue> {
    let mut form_count_fields = [0usize; 2];
    read_allocation_fields(
        AllocationRole::FormCount,
        form_count,
        FORM_COUNT_SIZE,
        &[FORM_COUNT_FORM_OFFSET, FORM_COUNT_EXTRA_OFFSET],
        &mut form_count_fields,
        read_words,
    )?;
    let [form, extra] = form_count_fields;

    if !valid_form(form) {
        return Err(ContainerIssue::InvalidForm { form_count, form });
    }
    if extra != 0 {
        read_allocation_fields(
            AllocationRole::ContainerExtraData,
            extra,
            FORM_COUNT_SIZE,
            &[],
            &mut [],
            read_words,
        )?;
    }
    Ok(())
}

fn read_allocation_fields(
    role: AllocationRole,
    ptr: usize,
    minimum: usize,
    offsets: &[usize],
    output: &mut [usize],
    read_words: &mut impl FnMut(usize, usize, &[usize], &mut [usize]) -> Result<(), AllocationState>,
) -> Result<(), ContainerIssue> {
    read_words(ptr, minimum, offsets, output).map_err(|state| ContainerIssue::Allocation {
        role,
        ptr,
        minimum,
        state,
    })
}

unsafe fn detach_container_head(actor: *mut c_void) {
    let head = unsafe {
        actor
            .cast::<u8>()
            .add(TESACTORBASE_CONTAINER_HEAD_OFFSET)
            .cast::<u32>()
    };
    unsafe {
        ptr::write_unaligned(head, 0);
        ptr::write_unaligned(head.add(1), 0);
    }
}

/// Read an embedded word while the native destructor owns the actor.
///
/// This path is entered with a live `this` pointer and runs before any actor
/// subobject is destroyed. An OS readability probe here would add Wine SEH
/// setup to every actor-base destructor, including the ordinary non-dynamic
/// rejection path. Separately allocated list members remain fully validated.
unsafe fn read_owned_actor_word(actor: usize, offset: usize) -> Option<usize> {
    let address = actor.checked_add(offset)?;
    Some(unsafe { ptr::read_unaligned(address as *const u32) as usize })
}

fn valid_runtime_form(form: usize) -> bool {
    valid_registered_form(form, allocation_state::read_allocation_words, |ref_id| {
        let resolve = unsafe {
            FnPtr::<LoadedFormResolverFn>::from_address_unchecked(LOADED_FORM_RESOLVER_ADDR)
        }
        .as_fn();
        unsafe { resolve(ref_id) as usize }
    })
}

fn valid_registered_form(
    form: usize,
    mut read_words: impl FnMut(usize, usize, &[usize], &mut [usize]) -> Result<(), AllocationState>,
    mut resolve_form: impl FnMut(u32) -> usize,
) -> bool {
    if form == 0 || form & (ENGINE_WORD_SIZE - 1) != 0 {
        return false;
    }
    let mut form_fields = [0usize; 1];
    if read_words(
        form,
        TESFORM_MINIMUM_SIZE,
        &[TESFORM_REF_ID_OFFSET],
        &mut form_fields,
    )
    .is_err()
    {
        return false;
    }
    let ref_id = form_fields[0] as u32;
    resolve_form(ref_id) == form
}

fn log_detachment(
    actor: *mut c_void,
    ref_id: u32,
    head_data: usize,
    head_next: usize,
    issue: ContainerIssue,
) {
    let total = DETACHED_DYNAMIC_ACTOR_CONTAINERS.fetch_add(1, Ordering::Relaxed) + 1;
    if crate::mods::diagnostics::should_log_power_of_two(total) {
        log::warn!(
            "[ACTOR_CONTAINER] detached corrupt retiring dynamic actor container: actor=0x{:08X} ref_id={:08X} head_data=0x{:08X} head_next=0x{:08X} issue={:?} total={}",
            actor as usize,
            ref_id,
            head_data,
            head_next,
            issue,
            total,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::mods::heap_replacer::allocation_state::{AllocationTier, InvalidAllocationReason};

    struct FakeContainer {
        words: BTreeMap<usize, usize>,
        allocations: BTreeMap<usize, AllocationState>,
        forms: BTreeSet<usize>,
    }

    impl FakeContainer {
        fn new() -> Self {
            Self {
                words: BTreeMap::new(),
                allocations: BTreeMap::new(),
                forms: BTreeSet::new(),
            }
        }

        fn live(&mut self, ptr: usize, size: usize) {
            self.allocations.insert(
                ptr,
                AllocationState::Live {
                    tier: AllocationTier::GheapPool,
                    usable_size: size,
                },
            );
        }

        fn form_count(&mut self, ptr: usize, form: usize, extra: usize) {
            self.live(ptr, FORM_COUNT_SIZE);
            self.words.insert(ptr + FORM_COUNT_FORM_OFFSET, form);
            self.words.insert(ptr + FORM_COUNT_EXTRA_OFFSET, extra);
            self.forms.insert(form);
        }

        fn node(&mut self, ptr: usize, data: usize, next: usize) {
            self.live(ptr, LIST_NODE_SIZE);
            self.words.insert(ptr + LIST_NODE_DATA_OFFSET, data);
            self.words.insert(ptr + LIST_NODE_NEXT_OFFSET, next);
        }

        fn validate(
            &self,
            head_data: usize,
            head_next: usize,
            item_limit: usize,
        ) -> Result<(), ContainerIssue> {
            validate_container(
                head_data,
                head_next,
                item_limit,
                |ptr, minimum, offsets, output| {
                    let state = self
                        .allocations
                        .get(&ptr)
                        .copied()
                        .unwrap_or(AllocationState::Unowned);
                    if !matches!(
                        state,
                        AllocationState::Live { usable_size, .. }
                            | AllocationState::PlausibleVanillaPool { usable_size }
                            if usable_size >= minimum
                    ) || offsets.len() != output.len()
                    {
                        return Err(state);
                    }
                    for (offset, slot) in offsets.iter().zip(output) {
                        let Some(word) = ptr
                            .checked_add(*offset)
                            .and_then(|address| self.words.get(&address).copied())
                        else {
                            return Err(state);
                        };
                        *slot = word;
                    }
                    Ok(())
                },
                |form| self.forms.contains(&form),
            )
        }
    }

    #[test]
    fn accepts_empty_and_complete_multi_item_lists() {
        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0);
        fake.form_count(0x1100, 0x9010, 0x3000);
        fake.live(0x3000, FORM_COUNT_SIZE);
        fake.node(0x2000, 0x1100, 0);

        assert_eq!(fake.validate(0, 0, MAX_CONTAINER_ITEMS), Ok(()));
        assert_eq!(fake.validate(0x1000, 0x2000, MAX_CONTAINER_ITEMS), Ok(()));
    }

    #[test]
    fn rejects_captured_live_load_successor_before_form_dereference() {
        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0);
        // The August 15 crash completed the embedded-head entry, read this
        // successor node, and then faulted on its 0x452BEF94 FormCount data.
        // Model the node as readable so this rejects the nested allocation,
        // not merely the address chosen for the node itself.
        fake.node(0x9000_0000, 0x452B_EF94, 0);

        assert!(matches!(
            fake.validate(0x1000, 0x9000_0000, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Allocation {
                role: AllocationRole::FormCount,
                ptr: 0x452B_EF94,
                state: AllocationState::Unowned,
                ..
            })
        ));
    }

    #[test]
    fn live_validation_bypasses_non_dynamic_actor_containers() {
        let actor = 0x7000;
        assert_eq!(
            validate_live_actor_container_with(
                actor,
                |ptr, minimum, offsets, output| {
                    assert_eq!(ptr, actor);
                    assert_eq!(minimum, TESACTORBASE_MINIMUM_SIZE);
                    assert_eq!(
                        offsets,
                        [
                            TESFORM_TYPE_OFFSET,
                            TESFORM_REF_ID_OFFSET,
                            TESACTORBASE_CONTAINER_HEAD_OFFSET,
                            TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_NEXT_OFFSET,
                        ]
                    );
                    output.copy_from_slice(&[TESNPC_FORM_TYPE as usize, 0x0100_1234, 1, 2]);
                    Ok(())
                },
                |_| panic!("static forms must not pay for a registry lookup"),
                |_, _| panic!("static forms are outside dynamic-container validation"),
            ),
            Ok(())
        );
    }

    #[test]
    fn live_validation_requires_dynamic_actor_type_and_registry_identity() {
        let actor = 0x7000;
        let read_dynamic = |_: usize,
                            _: usize,
                            _: &[usize],
                            output: &mut [usize]|
         -> Result<(), AllocationState> {
            output.copy_from_slice(&[TESNPC_FORM_TYPE as usize, 0xFF00_185C, 0x1000, 0x2000]);
            Ok(())
        };

        assert_eq!(
            validate_live_actor_container_with(
                actor,
                read_dynamic,
                |ref_id| (ref_id == 0xFF00_185C).then_some(actor).unwrap_or(0),
                |head_data, head_next| {
                    assert_eq!((head_data, head_next), (0x1000, 0x2000));
                    Ok(())
                },
            ),
            Ok(())
        );

        let registry_error = validate_live_actor_container_with(
            actor,
            read_dynamic,
            |_| actor + 4,
            |_, _| panic!("an unregistered actor must not expose its container"),
        )
        .expect_err("registry mismatch must reject a dynamic actor");
        assert!(matches!(
            registry_error.issue,
            LiveActorContainerIssue::RegistryMismatch { resolved } if resolved == actor + 4
        ));

        let type_error = validate_live_actor_container_with(
            actor,
            |_, _, _, output| {
                output.copy_from_slice(&[0x34, 0xFF00_185C, 0x1000, 0x2000]);
                Ok(())
            },
            |_| panic!("wrong dynamic type must fail before registry lookup"),
            |_, _| panic!("wrong dynamic type must not expose its container"),
        )
        .expect_err("non-actor dynamic form must be rejected");
        assert!(matches!(
            type_error.issue,
            LiveActorContainerIssue::UnexpectedDynamicType { type_id: 0x34 }
        ));
    }

    #[test]
    fn rejects_observed_image_pointer_and_interior_node_states() {
        let fake = FakeContainer::new();
        assert!(matches!(
            fake.validate(0x0101_7720, 0, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Allocation {
                role: AllocationRole::FormCount,
                ptr: 0x0101_7720,
                state: AllocationState::Unowned,
                ..
            })
        ));

        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0);
        fake.allocations.insert(
            0xD0AC_000D,
            AllocationState::InvalidOwned {
                tier: AllocationTier::GheapPool,
                reason: InvalidAllocationReason::Interior {
                    allocation_start: 0xD0AC_0008,
                    offset: 5,
                    usable_size: LIST_NODE_SIZE,
                },
            },
        );
        assert!(matches!(
            fake.validate(0x1000, 0xD0AC_000D, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Allocation {
                role: AllocationRole::ListNode,
                ptr: 0xD0AC_000D,
                state: AllocationState::InvalidOwned {
                    tier: AllocationTier::GheapPool,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn rejects_free_undersized_and_invalid_nested_allocations() {
        let mut fake = FakeContainer::new();
        fake.allocations.insert(
            0x1000,
            AllocationState::InvalidOwned {
                tier: AllocationTier::GheapPool,
                reason: InvalidAllocationReason::Free {
                    usable_size: FORM_COUNT_SIZE,
                },
            },
        );
        assert!(matches!(
            fake.validate(0x1000, 0, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Allocation {
                role: AllocationRole::FormCount,
                ..
            })
        ));

        fake.allocations.insert(
            0x1000,
            AllocationState::Live {
                tier: AllocationTier::GheapPool,
                usable_size: LIST_NODE_SIZE,
            },
        );
        assert!(matches!(
            fake.validate(0x1000, 0, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Allocation {
                role: AllocationRole::FormCount,
                ..
            })
        ));

        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0x3000);
        fake.allocations.insert(
            0x3000,
            AllocationState::InvalidOwned {
                tier: AllocationTier::GheapBlock,
                reason: InvalidAllocationReason::OwnedUnknown,
            },
        );
        assert!(matches!(
            fake.validate(0x1000, 0, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Allocation {
                role: AllocationRole::ContainerExtraData,
                ..
            })
        ));
    }

    #[test]
    fn rejects_cycles_and_bounded_walk_overflow() {
        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0);
        fake.form_count(0x1100, 0x9010, 0);
        fake.form_count(0x1200, 0x9020, 0);
        fake.node(0x2000, 0x1100, 0x2100);
        fake.node(0x2100, 0x1200, 0x2000);
        assert!(matches!(
            fake.validate(0x1000, 0x2000, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::Cycle { .. })
        ));

        fake.node(0x2100, 0x1200, 0);
        assert_eq!(
            fake.validate(0x1000, 0x2000, 2),
            Err(ContainerIssue::WalkLimit { limit: 2 })
        );
    }

    #[test]
    fn detachment_clears_both_embedded_head_words() {
        let mut head = [0x0101_7720u32, 0xD0AC_000D];
        let actor_offset = TESACTORBASE_CONTAINER_HEAD_OFFSET / ENGINE_WORD_SIZE;
        let mut actor_words = vec![0u32; actor_offset + 2];
        actor_words[actor_offset..].copy_from_slice(&head);

        unsafe { detach_container_head(actor_words.as_mut_ptr().cast()) };
        head.copy_from_slice(&actor_words[actor_offset..]);

        assert_eq!(head, [0, 0]);
    }

    #[test]
    fn runtime_form_filter_is_exactly_ff_prefixed() {
        assert!(is_dynamic_form_id(0xFF00_0000));
        assert!(is_dynamic_form_id(0xFFFF_FFFF));
        assert!(!is_dynamic_form_id(0xFEFF_FFFF));
        assert!(!is_dynamic_form_id(0x00FF_FFFF));
    }

    #[test]
    fn registered_form_validation_requires_live_storage_and_registry_identity() {
        let form = 0x9000;
        let ref_id = 0x0100_1234;

        assert!(valid_registered_form(
            form,
            |ptr, minimum, offsets, output| {
                assert_eq!(ptr, form);
                assert_eq!(minimum, TESFORM_MINIMUM_SIZE);
                assert_eq!(offsets, [TESFORM_REF_ID_OFFSET]);
                output[0] = ref_id;
                Ok(())
            },
            |id| (id == ref_id as u32).then_some(form).unwrap_or(0),
        ));
        assert!(!valid_registered_form(
            form,
            |_, _, _, _| Err(AllocationState::Unowned),
            |_| panic!("unowned form must not be resolved"),
        ));
        assert!(!valid_registered_form(
            form,
            |_, _, _, output| {
                output[0] = ref_id;
                Ok(())
            },
            |_| form + 4,
        ));
    }

    #[test]
    fn native_owned_actor_fields_support_unaligned_direct_reads() {
        let mut storage = vec![0u8; TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_SIZE + 1];
        let actor = unsafe { storage.as_mut_ptr().add(1) };
        unsafe {
            ptr::write_unaligned(actor.add(TESFORM_REF_ID_OFFSET).cast::<u32>(), 0xFF00_2E2B);
            ptr::write_unaligned(
                actor.add(TESACTORBASE_CONTAINER_HEAD_OFFSET).cast::<u32>(),
                0x0101_7720,
            );
            ptr::write_unaligned(
                actor
                    .add(TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_NEXT_OFFSET)
                    .cast::<u32>(),
                0xD0AC_000D,
            );
        }

        assert_eq!(
            unsafe { read_owned_actor_word(actor as usize, TESFORM_REF_ID_OFFSET) },
            Some(0xFF00_2E2B),
        );
        assert_eq!(
            unsafe { read_owned_actor_word(actor as usize, TESACTORBASE_CONTAINER_HEAD_OFFSET) },
            Some(0x0101_7720),
        );
        assert_eq!(
            unsafe {
                read_owned_actor_word(
                    actor as usize,
                    TESACTORBASE_CONTAINER_HEAD_OFFSET + LIST_NODE_NEXT_OFFSET,
                )
            },
            Some(0xD0AC_000D),
        );
    }

    #[test]
    fn structurally_valid_vanilla_pool_list_is_accepted() {
        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0);
        fake.form_count(0x1100, 0x9010, 0);
        fake.node(0x2000, 0x1100, 0);
        for ptr in [0x1000, 0x1100] {
            fake.allocations.insert(
                ptr,
                AllocationState::PlausibleVanillaPool {
                    usable_size: FORM_COUNT_SIZE,
                },
            );
        }
        fake.allocations.insert(
            0x2000,
            AllocationState::PlausibleVanillaPool {
                usable_size: LIST_NODE_SIZE,
            },
        );

        assert_eq!(fake.validate(0x1000, 0x2000, MAX_CONTAINER_ITEMS), Ok(()));
    }

    #[test]
    fn plausible_vanilla_pool_cells_still_require_valid_structure() {
        let mut fake = FakeContainer::new();
        fake.form_count(0x1000, 0x9000, 0);
        fake.allocations.insert(
            0x1000,
            AllocationState::PlausibleVanillaPool {
                usable_size: FORM_COUNT_SIZE,
            },
        );
        fake.node(0x2000, 0, 0);
        fake.allocations.insert(
            0x2000,
            AllocationState::PlausibleVanillaPool {
                usable_size: LIST_NODE_SIZE,
            },
        );

        assert_eq!(
            fake.validate(0x1000, 0x2000, MAX_CONTAINER_ITEMS),
            Err(ContainerIssue::EmptyNode { node: 0x2000 })
        );
    }
}
