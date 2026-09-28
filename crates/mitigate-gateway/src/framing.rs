//! Cancellation-safe, bounded newline framing; partial reads live on the reader.
use crate::Error;
use serde_json::Value;
use std::time::Duration;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout, timeout_at},
};

pub(crate) const MAX_FRAME: usize = 1_048_576;
const MAX_SESSION_BYTES: usize = 268_435_456;
pub(crate) struct Reader<R> {
    input: R,
    partial: Vec<u8>,
    deadline: Option<Instant>,
    received: usize,
}
impl<R: AsyncBufRead + Unpin> Reader<R> {
    pub fn new(input: R) -> Self {
        Self {
            input,
            partial: Vec::new(),
            deadline: None,
            received: 0,
        }
    }
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, Error> {
        loop {
            let buffer = match self.deadline {
                Some(deadline) => timeout_at(deadline, self.input.fill_buf())
                    .await
                    .map_err(|_| Error::Timeout)?,
                None => self.input.fill_buf().await,
            }
            .map_err(|_| Error::Disconnected)?;
            if buffer.is_empty() {
                return if self.partial.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::Disconnected)
                };
            }
            self.deadline
                .get_or_insert_with(|| Instant::now() + Duration::from_secs(10));
            let end = buffer.iter().position(|b| *b == b'\n');
            let count = end.map_or(buffer.len(), |i| i + 1);
            self.received += count;
            if self.partial.len() + count > MAX_FRAME || self.received > MAX_SESSION_BYTES {
                return Err(Error::Limit);
            }
            self.partial.extend_from_slice(&buffer[..count]);
            self.input.consume(count);
            if end.is_some() {
                self.deadline = None;
                return Ok(Some(std::mem::take(&mut self.partial)));
            }
        }
    }
}
pub(crate) async fn write(
    output: &mut (impl AsyncWrite + Unpin),
    value: Value,
) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| Error::Protocol)?;
    // A service is trusted code, but its response contains untrusted upstream data.
    if bytes.len() >= MAX_FRAME || mitigate_json::parse(&bytes).is_err() {
        return Err(Error::Limit);
    }
    bytes.push(b'\n');
    timeout(Duration::from_secs(5), async {
        output.write_all(&bytes).await?;
        output.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|_| Error::Disconnected)
}
