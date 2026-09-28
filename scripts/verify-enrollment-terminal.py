"""Actual hidden-input CLI through POSIX PTY / Windows ConPTY; synthetic only."""
import contextlib
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time


def native_mode():
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.argtypes = [ctypes.c_uint32]
        kernel.GetStdHandle.restype = ctypes.c_void_p
        kernel.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        value = ctypes.c_uint32()
        if not kernel.GetConsoleMode(kernel.GetStdHandle(-10), ctypes.byref(value)):
            raise RuntimeError("Fixture console mode unavailable")
        return value.value
    import termios
    return termios.tcgetattr(0)


def child(cli, state):
    if os.name == "nt":
        # A CI host may have redirected standard handles even while attaching a
        # new ConPTY. Bind this synthetic child explicitly to its private console.
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.SetStdHandle.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        sys.stdin = open("CONIN$", "r", encoding="utf-8")
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        for number, stream in [(-10, sys.stdin), (-11, sys.stdout), (-12, sys.stderr)]:
            if not kernel.SetStdHandle(number, msvcrt.get_osfhandle(stream.fileno())):
                raise RuntimeError("Fixture console binding failed")
    before = native_mode()
    result = subprocess.run([cli, "enroll", "start", "--platform", "https://mitigate.example", "--state", state], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, check=False)
    assert result.returncode == 2, "Fixture must stop before native storage/network"
    assert native_mode() == before, "Terminal mode was not restored exactly"
    assert not Path(state).exists(), "Rejected prompt created state"
    print("TERMINAL_RESTORED", flush=True)


class Capture:
    def __init__(self, read):
        self.data = bytearray()
        self.changed = threading.Event()
        self.failure = None

        def collect():
            try:
                while True:
                    chunk = read()
                    if not chunk:
                        break
                    if len(self.data) + len(chunk) > 65536:
                        raise RuntimeError("Fixture output exceeded its bound")
                    self.data.extend(chunk)
                    self.changed.set()
            except OSError:
                pass  # PTY hangup after the child exits.
            except Exception:
                self.failure = "Fixture capture failed"
            finally:
                self.changed.set()

        self.thread = threading.Thread(target=collect, daemon=True)
        self.thread.start()

    def expect(self, text):
        deadline = time.monotonic() + 15
        while text not in self.data:
            if self.failure or time.monotonic() >= deadline:
                raise RuntimeError("Expected terminal fixture response missing")
            self.changed.wait(0.05)
            self.changed.clear()


@contextlib.contextmanager
def posix_terminal(arguments):
    import pty
    master, slave = pty.openpty()
    process = None
    capture = None
    try:
        process = subprocess.Popen(arguments, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        capture = Capture(lambda: os.read(master, 4096))

        def send(data):
            while data:
                data = data[os.write(master, data):]

        yield capture, send, lambda: process.wait(timeout=15)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(slave)
        if capture:
            capture.thread.join(timeout=5)
        os.close(master)
        if capture and capture.thread.is_alive():
            raise RuntimeError("Terminal fixture capture did not stop")


@contextlib.contextmanager
def windows_terminal(arguments):
    # Standard Win32 ConPTY host pattern. The synthetic child receives real
    # console handles without opening a visible window or installing a package.
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class Coord(ctypes.Structure):
        _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

    class Startup(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                    ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                    ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                    ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD),
                    ("wShowWindow", w.WORD), ("cbReserved2", w.WORD), ("lpReserved2", ctypes.c_void_p),
                    ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

    class ExtendedStartup(ctypes.Structure):
        _fields_ = [("StartupInfo", Startup), ("attributes", ctypes.c_void_p)]

    class ProcessInfo(ctypes.Structure):
        _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]

    kernel.CreatePipe.argtypes = [ctypes.POINTER(w.HANDLE), ctypes.POINTER(w.HANDLE), ctypes.c_void_p, w.DWORD]
    kernel.CreatePseudoConsole.argtypes = [Coord, w.HANDLE, w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    kernel.CreatePseudoConsole.restype = ctypes.c_long
    kernel.ClosePseudoConsole.argtypes = [w.HANDLE]
    kernel.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t)]
    kernel.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(ProcessInfo)]
    kernel.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel.CloseHandle.argtypes = [w.HANDLE]

    def check(value):
        if not value:
            raise RuntimeError("Native terminal fixture operation failed")

    input_read, input_write, output_read, output_write, console = [w.HANDLE() for _ in range(5)]
    process = ProcessInfo()
    attributes = None
    attributes_ready = False
    capture = None
    try:
        check(kernel.CreatePipe(ctypes.byref(input_read), ctypes.byref(input_write), None, 0))
        check(kernel.CreatePipe(ctypes.byref(output_read), ctypes.byref(output_write), None, 0))
        check(kernel.CreatePseudoConsole(Coord(120, 30), input_read, output_write, 0, ctypes.byref(console)) == 0)
        size = ctypes.c_size_t()
        kernel.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        check(size.value > 0)
        attributes = ctypes.create_string_buffer(size.value)
        check(kernel.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)))
        attributes_ready = True
        check(kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020016, console, ctypes.sizeof(console), None, None))
        startup = ExtendedStartup()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(arguments))
        check(kernel.CreateProcessW(None, command, None, None, False, 0x00080000, None, None, ctypes.byref(startup), ctypes.byref(process)))
        kernel.CloseHandle(input_read)
        kernel.CloseHandle(output_write)
        input_read, output_write = w.HANDLE(), w.HANDLE()

        def read():
            buffer = ctypes.create_string_buffer(4096)
            count = w.DWORD()
            if not kernel.ReadFile(output_read, buffer, len(buffer), ctypes.byref(count), None):
                return b""
            return buffer.raw[:count.value]

        capture = Capture(read)

        def send(data):
            while data:
                count = w.DWORD()
                check(kernel.WriteFile(input_write, data, len(data), ctypes.byref(count), None))
                check(count.value > 0)
                data = data[count.value:]

        def wait():
            check(kernel.WaitForSingleObject(process.process, 15000) == 0)
            result = w.DWORD()
            check(kernel.GetExitCodeProcess(process.process, ctypes.byref(result)))
            return result.value

        yield capture, send, wait
    finally:
        if process.process:
            if kernel.WaitForSingleObject(process.process, 0) != 0:
                kernel.TerminateProcess(process.process, 2)
                kernel.WaitForSingleObject(process.process, 5000)
        if console:
            kernel.ClosePseudoConsole(console)
        if attributes_ready:
            kernel.DeleteProcThreadAttributeList(attributes)
        for handle in [process.thread, process.process, input_read, input_write, output_write]:
            if handle:
                kernel.CloseHandle(handle)
        if capture:
            capture.thread.join(timeout=5)
        if output_read:
            kernel.CloseHandle(output_read)
        if capture and capture.thread.is_alive():
            raise RuntimeError("Terminal fixture capture did not stop")


def verify(cli):
    code = b"mcp1:00000000-0000-4000-8000-000000000001:" + b"A" * 43
    native_path = b"Use an enrollment file in your private local state directory."
    invalid = b"Paste one complete enrollment code"
    cancelled = b"Enrollment cancelled."
    scenarios = [
        (code + b"\r", native_path),
        (b"x\x7f" + code + b"\r", native_path),
        (b"x" * 500 + b"\x15" + code + b"\r", native_path),
        (code + b"x" * 10000 + b"\r", invalid),
        (code[:60] + b"\x03", cancelled),
        (code[:60] + b"\x04", cancelled),
        (b"secret-canary\r", invalid),
        (b"\xc3\xa9\r", invalid),
    ]
    terminal = windows_terminal if os.name == "nt" else posix_terminal
    with tempfile.TemporaryDirectory(prefix="mitigate-terminal-fixture-") as directory:
        # A missing private parent stops even a valid code before native storage.
        state = str(Path(directory) / "absent" / "enrollment")
        for payload, expected in scenarios:
            with terminal([sys.executable, str(Path(__file__).resolve()), "--child", cli, state]) as (capture, send, wait):
                capture.expect(b"Paste enrollment code (hidden):")
                writer = threading.Thread(target=send, args=(payload,), daemon=True)
                writer.start()
                writer.join(timeout=15)
                assert not writer.is_alive(), "Fixture input stalled"
                capture.expect(b"TERMINAL_RESTORED")
                assert wait() == 0, "Terminal fixture child failed"
                capture.expect(expected)
                assert code[:60] not in capture.data and b"secret-canary" not in capture.data, "Hidden input was echoed"
    print("Enrollment terminal verified: hidden paste, editing, bounds, cancellation and exact mode restoration.")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 2:
        verify(str(Path(sys.argv[1]).resolve()))
    else:
        raise SystemExit("Pass the built Mitigate executable.")
