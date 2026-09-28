"""Verify shipped amalgamation against the reviewed upstream release."""
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "vendor" / "libsqlite3-sys" / "sqlite3"
expected = {
    "sqlite3.c": "b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189",
    "sqlite3.h": "919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d",
    "sqlite3ext.h": "ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be",
}
for name, digest in expected.items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
        raise SystemExit("Bundled SQLite provenance check failed.")
print("Bundled SQLite 3.53.4 provenance verified.")
