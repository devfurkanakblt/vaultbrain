fn main() {
    const COMMANDS: &[&str] = &[
        "unlock_vault",
        "lock_vault",
        "list_notes",
        "get_note",
        "save_note",
        "create_note",
        "search_notes",
        "get_backlinks",
        "get_knowledge_graph",
        "list_property_rows",
    ];
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build Tauri application metadata");
}
