//! Bounded enrollment input with no echo and exact terminal-mode restoration.
//! Only this synchronous CLI operation changes terminal state. Keyboard Ctrl-C
//! is data while reading, so cancellation unwinds normally before any native key
//! is created. Forced process termination cannot promise terminal restoration.
use mitigate_secrets::Secret;
use std::io::{self, IsTerminal, Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub(crate) enum Error {
    Unavailable,
    Cancelled,
    Invalid,
    Restore,
}

pub(crate) fn enrollment_code() -> Result<Secret, Error> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(Error::Unavailable);
    }
    let mut mode = Mode::hide().map_err(|_| Error::Unavailable)?;
    let result = (|| {
        // Change mode before inviting a paste; never briefly echo input between
        // characters or fall back to an ordinary echoed line reader.
        let mut terminal = io::stderr().lock();
        terminal
            .write_all(b"Paste enrollment code (hidden): ")
            .map_err(|_| Error::Unavailable)?;
        terminal.flush().map_err(|_| Error::Unavailable)?;
        read_code(io::stdin().lock())
    })();
    let restored = mode.restore();
    let _ = writeln!(io::stderr().lock());
    restored.map_err(|_| Error::Restore)?;
    result
}

fn read_code(mut reader: impl Read) -> Result<Secret, Error> {
    let mut code = Zeroizing::new([0u8; 85]);
    let mut byte = Zeroizing::new([0u8; 1]);
    let mut length = 0;
    let mut invalid = false;
    loop {
        reader.read_exact(&mut *byte).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                Error::Cancelled
            } else {
                Error::Unavailable
            }
        })?;
        match byte[0] {
            3 | 4 => return Err(Error::Cancelled),
            b'\r' | b'\n' => break,
            8 | 127 => {
                if length > 0 {
                    length -= 1;
                    code[length].zeroize();
                }
            }
            21 => {
                code.zeroize();
                length = 0;
                invalid = false;
            }
            value if value.is_ascii_graphic() && length < code.len() => {
                code[length] = value;
                length += 1;
            }
            // Drain invalid/oversized pasted input through Enter while echo is
            // still disabled. Never restore echo halfway through a long paste.
            _ => invalid = true,
        }
    }
    if invalid || length != code.len() {
        return Err(Error::Invalid);
    }
    Secret::from_bytes(code.to_vec()).map_err(|_| Error::Invalid)
}

#[cfg(unix)]
struct Mode(Option<rustix::termios::Termios>);
#[cfg(unix)]
impl Mode {
    fn hide() -> io::Result<Self> {
        use rustix::{
            stdio::stdin,
            termios::{OptionalActions, tcgetattr, tcsetattr},
        };
        let original = tcgetattr(stdin())?;
        let mut hidden = original.clone();
        hidden.make_raw();
        tcsetattr(stdin(), OptionalActions::Now, &hidden)?;
        Ok(Self(Some(original)))
    }
    fn restore(&mut self) -> io::Result<()> {
        if let Some(original) = &self.0 {
            // Flush any unread terminal input before echo is restored.
            rustix::termios::tcsetattr(
                rustix::stdio::stdin(),
                rustix::termios::OptionalActions::Flush,
                original,
            )?;
            self.0 = None;
        }
        Ok(())
    }
}

#[cfg(windows)]
struct Mode {
    console: crossterm_winapi::ConsoleMode,
    original: Option<u32>,
}
#[cfg(windows)]
impl Mode {
    fn hide() -> io::Result<Self> {
        let console =
            crossterm_winapi::ConsoleMode::from(crossterm_winapi::Handle::input_handle()?);
        let original = console.mode()?;
        // Win32 ENABLE_PROCESSED_INPUT, ENABLE_LINE_INPUT, ENABLE_ECHO_INPUT.
        // Preserve every other bit, then restore the exact original mask.
        console.set_mode(original & !0x0007)?;
        Ok(Self {
            console,
            original: Some(original),
        })
    }
    fn restore(&mut self) -> io::Result<()> {
        if let Some(original) = self.original {
            self.console.set_mode(original)?;
            self.original = None;
        }
        Ok(())
    }
}
impl Drop for Mode {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Vec<u8> {
        format!(
            "mcp1:00000000-0000-4000-8000-000000000001:{}",
            "A".repeat(43)
        )
        .into_bytes()
    }
    #[test]
    fn hidden_input_is_bounded_correctable_and_cancelled_without_partial_secrets() {
        for ending in *b"\r\n" {
            let mut input = valid();
            input.push(ending);
            assert!(read_code(input.as_slice()).is_ok());
        }
        let mut corrected = vec![b'x', 127];
        corrected.extend(valid());
        corrected.push(b'\r');
        assert!(read_code(corrected.as_slice()).is_ok());
        let mut cleared = vec![b'x'; 500];
        cleared.push(21);
        cleared.extend(valid());
        cleared.push(b'\r');
        assert!(read_code(cleared.as_slice()).is_ok());
        for cancel in [3, 4] {
            let mut input = valid();
            input.push(cancel);
            assert!(matches!(read_code(input.as_slice()), Err(Error::Cancelled)));
        }
        for input in [
            b"secret-canary\r".to_vec(),
            vec![b'x'; 10000],
            [valid(), b" \r".to_vec()].concat(),
            [valid(), b"x\x7f\r".to_vec()].concat(),
        ] {
            assert!(read_code(input.as_slice()).is_err());
        }
        let mut oversized = io::Cursor::new([vec![b'x'; 10000], b"\r".to_vec()].concat());
        assert!(matches!(read_code(&mut oversized), Err(Error::Invalid)));
        assert_eq!(oversized.position(), 10001);
    }
}
