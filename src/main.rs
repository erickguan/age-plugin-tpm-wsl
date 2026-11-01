fn main() {
    if let Err(error) = age_plugin_tpm_wsl::cli::run() {
        eprintln!("age-plugin-tpm-wsl: {error}");
        std::process::exit(1);
    }
}
