//! Runs the same synthetic probe as the production privacy CLI.
fn main() -> std::process::ExitCode {
    match mitigate_egress::self_test::run(&std::env::temp_dir()) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("closed report")
            );
            if report.passed {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(2)
        }
    }
}
