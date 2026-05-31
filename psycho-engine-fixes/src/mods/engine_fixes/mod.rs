//! Standalone engine fixes.
//!
//! This module is for game contract fixes that are useful independent of
//! which heap allocator is active. Allocator mechanics and allocator-only
//! safety still live under `heap_replacer`.

use libc::c_void;

use crate::config::EngineFixesConfig;

mod display;
mod entrydata;
mod extraownership;
mod havok;
mod linkedrefs;
mod memset;
mod navmesh;
mod statics;
mod types;

pub fn install(config: &EngineFixesConfig) -> anyhow::Result<()> {
    install_display_alt_tab(config)?;
    install_navmesh_low_pointer(config)?;
    install_entrydata_invalid_form(config)?;
    install_extraownership_invalid_owner(config)?;
    install_linked_ref_children_stale_list(config)?;
    install_havok_guards(config)?;
    install_memset_null_dst(config)?;

    Ok(())
}

pub fn observe_event(kind: u32) {
    display::observe_event(kind);
}

fn install_display_alt_tab(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.display_alt_tab {
        log::info!("[DISPLAY] Alt-tab fix disabled by config");
        return Ok(());
    }

    if let Err(err) = display::install_display_hooks() {
        log::warn!("[DISPLAY] Alt-tab fix disabled: {}", err);
    }

    Ok(())
}

fn install_navmesh_low_pointer(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.navmesh_low_pointer_guard {
        log::info!("[NAVMESH] Low pointer guard disabled by config");
        return Ok(());
    }

    statics::NAVMESH_NAME_HELPER_HOOK.init(
        "navmesh_name_helper_guard",
        statics::NAVMESH_NAME_HELPER_ADDR as *mut c_void,
        navmesh::hook_navmesh_name_helper,
    )?;
    statics::NAVMESH_NAME_HELPER_HOOK.enable()?;
    log::info!("[NAVMESH] Low pointer guard active");
    Ok(())
}

fn install_entrydata_invalid_form(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.entrydata_invalid_form_guard {
        log::info!("[ENTRYDATA] Invalid form guard disabled by config");
        return Ok(());
    }

    statics::ENTRYDATA_LIST_SAVE_HOOK.init(
        "entrydata_list_save_guard",
        statics::ENTRYDATA_LIST_SAVE_ADDR as *mut c_void,
        entrydata::hook_entrydata_list_save,
    )?;
    statics::ENTRYDATA_LOAD_HOOK.init(
        "entrydata_load_guard",
        statics::ENTRYDATA_LOAD_ADDR as *mut c_void,
        entrydata::hook_entrydata_load,
    )?;
    statics::ENTRYDATA_LIST_SAVE_HOOK.enable()?;
    statics::ENTRYDATA_LOAD_HOOK.enable()?;
    log::info!("[ENTRYDATA] Invalid form guard active");
    Ok(())
}

fn install_extraownership_invalid_owner(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.extraownership_invalid_owner_guard {
        log::info!("[EXTRAOWNERSHIP] Invalid owner guard disabled by config");
        return Ok(());
    }

    statics::BASE_EXTRA_LIST_GET_BY_TYPE_HOOK.init(
        "base_extra_list_get_by_type_ownership_guard",
        statics::BASE_EXTRA_LIST_GET_BY_TYPE_ADDR as *mut c_void,
        extraownership::hook_base_extra_list_get_by_type,
    )?;
    statics::BASE_EXTRA_LIST_GET_BY_TYPE_HOOK.enable()?;
    extraownership::install_load_hook()?;
    log::info!("[EXTRAOWNERSHIP] Invalid owner guard active");
    Ok(())
}

fn install_linked_ref_children_stale_list(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.linked_ref_children_stale_list_guard {
        log::info!("[LINKED_REFS] Stale child-list guard disabled by config");
        return Ok(());
    }

    linkedrefs::install_remove_guard()?;
    log::info!("[LINKED_REFS] Stale child-list guard active");
    Ok(())
}

fn install_havok_guards(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if config.havok_add_entity_batch_null_guard {
        statics::HAVOK_ADD_ENTITY_BATCH_HOOK.init(
            "havok_add_entity_batch_null_guard",
            statics::HAVOK_ADD_ENTITY_BATCH_ADDR as *mut c_void,
            havok::hook_havok_add_entity_batch,
        )?;
        statics::HAVOK_ADD_ENTITY_BATCH_HOOK.enable()?;
        log::info!("[HAVOK] Add-entity batch NULL guard active");
    }

    if config.havok_pending_add_null_guard {
        statics::HAVOK_PENDING_ADD_FLUSH_HOOK.init(
            "havok_pending_add_null_guard",
            statics::HAVOK_PENDING_ADD_FLUSH_ADDR as *mut c_void,
            havok::hook_havok_pending_add_flush,
        )?;
        statics::HAVOK_PENDING_ADD_FLUSH_HOOK.enable()?;
        havok::install_pending_add_loop_null_guard()?;
        log::info!("[HAVOK] Pending-add NULL guard active");
    }

    if config.havok_narrowphase_invalid_pair_guard {
        statics::HAVOK_NARROWPHASE_ADD_AGENTS_HOOK.init(
            "havok_narrowphase_invalid_pair_guard",
            statics::HAVOK_NARROWPHASE_ADD_AGENTS_ADDR as *mut c_void,
            havok::hook_havok_narrowphase_add_agents,
        )?;
        statics::HAVOK_NARROWPHASE_ADD_AGENTS_HOOK.enable()?;
        log::info!("[HAVOK] Narrowphase invalid-pair guard active");
    }

    if config.havok_post_add_null_entity_guard {
        statics::HAVOK_ENTITY_POST_ADD_HOOK.init(
            "havok_post_add_null_entity_guard",
            statics::HAVOK_ENTITY_POST_ADD_ADDR as *mut c_void,
            havok::hook_havok_entity_post_add,
        )?;
        statics::HAVOK_ENTITY_POST_ADD_HOOK.enable()?;
        log::info!("[HAVOK] Post-add NULL entity guard active");
    }

    Ok(())
}

fn install_memset_null_dst(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.memset_null_dst_guard {
        log::info!("[CRT] _memset NULL-dst guard disabled by config");
        return Ok(());
    }

    statics::MEMSET_HOOK.init(
        "memset_null_dst_guard",
        statics::MEMSET_ADDR as *mut c_void,
        memset::hook_memset,
    )?;
    statics::MEMSET_HOOK.enable()?;
    log::info!("[CRT] _memset NULL-dst guard active");
    Ok(())
}
