//! `issen` binary — a thin shim over the `issen_cli` library so the binary and
//! every library-linked test harness share one code path and one parser registry.

fn main() -> std::process::ExitCode {
    issen_cli::run()
}
