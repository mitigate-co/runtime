# ADR 0030: Hidden enrollment input

Status: Accepted for explicit interactive enrollment.

## Decision

Default enrollment start to a hidden terminal prompt. Keep `--stdin` for secure
pipe producers and require it with JSON output. Accept no code argument, secret
environment fallback, plaintext intermediate file or echoed-read fallback.

Hold the original terminal mode in a scoped owner, disable echo/canonical input
and keyboard signal generation before displaying the prompt, and restore the exact
original state before persistence. Ctrl-C/Ctrl-D return cancellation normally.
Backspace erases a byte; Ctrl-U clears entry. A fixed 85-byte zeroizing buffer
accepts ASCII code bytes; invalid/oversized input drains to Enter while echo remains
off. All errors are fixed and contain no rejected input or provider diagnostics.

Restoration failure prevents enrollment and requests closing the terminal. Drop
also attempts restoration for unwind/error paths, but SIGKILL/abort/OS failure
cannot be repaired by an in-process guard. This does not claim that std/OS buffers
are zeroized or protect against a same-user memory reader or hostile terminal.

## Dependency review (2026-09-28)

Rust std exposes terminal detection and input but no safe terminal-mode control.
Reuse the existing pinned `rustix` 1.1.5 on Unix, enabling `stdio` and `termios`.
Its safe API wraps native termios and restores the exact original structure with
unread input flushing. It is Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT,
actively maintained in the existing graph, with no network/telemetry operation.

On Windows use `crossterm_winapi` 0.9.1 (MIT), only its safe `Handle::input_handle`
and `ConsoleMode` API. This is a small established wrapper still used by Crossterm
0.29.0; its release cadence is slow and updates require continued review. The
borrowed standard handle is not closed. Preserve the complete original console
mask, clearing only processed, line and echo input while reading. Do not use the
wrapper's other screen-buffer, input-record or raw-handle APIs.

The lockfile adds four package versions: the wrapper, `winapi` 0.3.9
(MIT OR Apache-2.0), and its two GNU-target import packages at 0.4.0. No existing
version changes. The GNU import packages are not part of the MSVC build. Native
FFI and unsafe code remain upstream in the reviewed wrappers; Mitigate's module
retains `unsafe_code = forbid`. No process execution, event reactor, signal-hook
framework, clipboard access or new cryptography is added. These APIs run only
during explicit enrollment, outside local MCP calls. No binary-size or latency
claim is made before release measurement.

Source review rejected an ordinary password-line helper whose Ctrl-C path raises
a terminating signal before its restoration guard can unwind. A whole terminal
event library was unnecessary for one bounded ASCII code. The focused mode wrapper
plus std input keeps this behavior visible and directly testable.

The fresh advisory scan passed all 314 locked external packages. All-feature
license/source/bans checks passed with existing reviewed duplicate warnings;
advisory absence is not a security audit. PTY/ConPTY fixtures verify real mode
restoration and secret-free output; no fixture changes a user's terminal/keychain.

References: [rustix termios](https://docs.rs/rustix/1.1.5/rustix/termios/index.html),
[Windows mode contract](https://learn.microsoft.com/en-us/windows/console/setconsolemode),
[wrapper source](https://github.com/crossterm-rs/crossterm-winapi),
[ConPTY lifecycle](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session).
