fn main() {
    const COMMANDS: &[&str] = &[
        "unlock_vault",
        "lock_vault",
        "memory_status",
        "memory_pair_begin",
        "memory_pair_complete",
        "memory_pair_cancel",
        "memory_disconnect",
        "memory_list_review",
        "memory_approve",
        "memory_reject",
        "memory_set_pinned",
        "memory_forget",
        "memory_relearn",
        "memory_set_paused",
        "memory_exclude_scope",
        "list_notes",
        "get_note",
        "save_note",
        "create_note",
        "search_notes",
        "get_backlinks",
        "get_knowledge_graph",
        "list_property_rows",
        "desktop_sync_execute",
        "desktop_sync_cancel",
    ];
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build Tauri application metadata");
}
