//! Failure-only bounded projection of the synthetic gateway's local status.
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) async fn worker_status(reader: impl AsyncRead + Unpin) -> Vec<&'static str> {
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_millis(500),
        reader.take(4096).read_to_end(&mut bytes),
    )
    .await;
    messages(&bytes)
}

fn messages(bytes: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let Some((complete, _)) = text.rsplit_once('\n') else {
        return Vec::new();
    };
    complete.lines()
        .take(16)
        .filter_map(|line| match line {
            "Mitigate: sync capture ready." => Some("ready"),
            "Mitigate: sync capture is paused or needs explicit resume." => Some("paused"),
            "Mitigate: sync capture unavailable; inspect the original profile, queue and catalog." => Some("unavailable"),
            "Mitigate: optional sync metadata was dropped; inspect queue capacity and local storage." => Some("dropped"),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn only_exact_status_lines_escape_within_byte_and_line_bounds() {
        let ready = "Mitigate: sync capture ready.";
        assert_eq!(messages(format!("{ready}\n").as_bytes()), ["ready"]);
        assert!(messages(ready.as_bytes()).is_empty());
        assert!(messages(format!("{ready} private-canary").as_bytes()).is_empty());
        assert!(messages(b"private-canary").is_empty());
        assert!(messages(("ignored\n".repeat(16) + ready + "\n").as_bytes()).is_empty());
        assert!(messages(("x".repeat(4096) + "\n" + ready + "\n").as_bytes()).is_empty());
        assert!(messages(&[0xff, 0xfe]).is_empty());
        assert_eq!(messages(b"Mitigate: sync capture is paused or needs explicit resume.\nMitigate: sync capture unavailable; inspect the original profile, queue and catalog.\nMitigate: optional sync metadata was dropped; inspect queue capacity and local storage.\n"), ["paused", "unavailable", "dropped"]);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_status_stream_is_bounded_and_preserves_complete_fixed_lines() {
        let (reader, mut writer) = tokio::io::duplex(256);
        writer
            .write_all(b"Mitigate: sync capture ready.\nprivate-canary")
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        assert_eq!(worker_status(reader).await, ["ready"]);
        assert_eq!(started.elapsed(), Duration::from_millis(500));
        drop(writer);
    }
}
