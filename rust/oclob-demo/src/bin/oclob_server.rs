#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = oclob_demo::server::run_from_env() {
        eprintln!("OCLOB demo server stopped: {error}");
        std::process::exit(1);
    }
}
