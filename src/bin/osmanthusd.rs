fn main() -> std::process::ExitCode {
    match osmanthus_guard::linux_daemon::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("osmanthusd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
