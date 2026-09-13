fn main() {
    if std::env::args().skip(1).any(|arg| arg == "--memory-client") {
        std::process::exit(vault_brain_desktop_lib::run_memory_client());
    }
    vault_brain_desktop_lib::run();
}
