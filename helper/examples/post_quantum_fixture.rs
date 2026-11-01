//! Uninstalled, feature-gated fixture for disposable native client validation.
//! Shared implementation is compiled from production source; only storage
//! selection and explicit administrative controls are fixture-specific.
#[cfg(windows)]
#[allow(dead_code)] // Shared classical adapter supplies statuses and native test controls.
#[path = "../src/cng.rs"]
mod cng;
#[cfg(windows)]
#[allow(dead_code)] // The fixture uses only the shared post-quantum request dispatcher.
#[path = "../src/key_format.rs"]
mod key_format;
#[cfg(windows)]
#[allow(dead_code, unused_imports)] // Fixture does not use the production entry/re-export.
#[path = "../src/post_quantum/mod.rs"]
mod post_quantum;

#[cfg_attr(not(windows), allow(dead_code))] // Linux executes pure authority tests only.
#[path = "post_quantum_fixture/arguments.rs"]
mod arguments;
#[cfg(windows)]
#[path = "post_quantum_fixture/protocol.rs"]
mod protocol;
#[cfg(windows)]
#[path = "post_quantum_fixture/storage.rs"]
mod storage;

#[cfg(windows)]
fn run() -> post_quantum::lifecycle::Outcome<()> {
    use arguments::{Arguments, Mode};
    use std::io::Write;
    let arguments = Arguments::parse(&std::env::args().skip(1).collect::<Vec<_>>())?;
    let location = storage::IsolatedLocation(&arguments.namespace);
    if arguments.mode == Mode::Serve {
        return protocol::serve(&arguments, &location);
    }
    let report = match arguments.mode {
        Mode::PrepareRoot => location.prepare()?,
        Mode::Absence => location.absence()?,
        Mode::RemoveRoot => location.remove_root()?,
        Mode::Serve => unreachable!("served above"),
    };
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| "public report encoding failed")?;
    writeln!(output).map_err(|_| "public report output interrupted".into())
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("post-quantum-fixture: {}", error.message);
        std::process::exit(if error.cleanup_failed { 97 } else { 1 });
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("post-quantum-fixture requires Windows; Linux builds test public authority only");
    std::process::exit(1);
}
