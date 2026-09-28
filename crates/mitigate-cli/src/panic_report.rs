//! Dependencies may panic while handling local content. The executable owns the
//! process-wide hook; libraries must not replace an embedder's hook implicitly.
use std::io::{self, Write};

pub(crate) fn install() {
    std::panic::set_hook(Box::new(|_| {
        let _ = writeln!(
            io::stderr(),
            "Runtime internal failure. Diagnostic content was withheld. Restart and report the operation that failed."
        );
    }));
}

#[cfg(test)]
mod tests {
    #[test]
    fn panic_fixture() {
        if let Ok(value) = std::env::var("MITIGATE_TEST_PANIC") {
            super::install();
            panic!("{value}");
        }
    }

    #[test]
    fn dependency_panic_never_prints_payload_or_backtrace() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "panic_report::tests::panic_fixture",
                "--nocapture",
            ])
            .env("MITIGATE_TEST_PANIC", "private-panic-payload-canary")
            .env("RUST_BACKTRACE", "full")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stderr.contains("Diagnostic content was withheld"));
        assert!(!stderr.contains("private-panic-payload-canary"));
        assert!(!stdout.contains("private-panic-payload-canary"));
        assert!(!stderr.contains("stack backtrace"));
    }
}
