"""Closed signed-release layout. Never extract archive-selected paths or run code."""

import hashlib
import json
import re
import stat
import struct
import zipfile
import zlib

from authenticate import VerificationError
from package import TARGETS
from preflight import expected_source

MAX_MANIFEST = 16 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 384 * 1024 * 1024
BUILD_FIELDS = (
    "schema_version",
    "kind",
    "version",
    "source_commit",
    "target",
    "rustc",
    "cargo_lock_sha256",
    "toolchain_file_sha256",
)
MANIFEST_FIELDS = {*BUILD_FIELDS, "archive", "archive_sha256", "archive_size", "files"}


def require(condition, code="release_contract"):
    if not condition:
        raise VerificationError(code)


def closed_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(data):
    require(0 < len(data) <= MAX_MANIFEST)
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=closed_object,
            parse_constant=lambda _: require(False),
        )
    except (ValueError, RecursionError):
        raise VerificationError("release_contract") from None


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_manifest(data, target, commit, tag):
    return _validate_manifest(data, target, commit, tag, "signed_release")


def validate_candidate(data, target, commit, tag):
    """Build tooling only: structural validation grants no publisher trust."""
    return _validate_manifest(data, target, commit, tag, "unsigned_candidate")


def _validate_manifest(data, target, commit, tag, kind):
    require(expected_source(commit, tag) and len(tag) <= 64)
    manifest = decode(data)
    require(isinstance(manifest, dict) and set(manifest) == MANIFEST_FIELDS)
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1)
    require(manifest["kind"] == kind)
    require(target in TARGETS and manifest["target"] == target)
    require(manifest["version"] == tag[1:] and manifest["source_commit"] == commit)
    require(isinstance(manifest["rustc"], str) and 0 < len(manifest["rustc"]) <= 4096)
    require(
        all(
            digest(manifest[key])
            for key in ("cargo_lock_sha256", "toolchain_file_sha256", "archive_sha256")
        )
    )
    require(
        type(manifest["archive_size"]) is int
        and 0 < manifest["archive_size"] <= 128 * 1024 * 1024
    )
    prefix = f"mitigate-{tag[1:]}-{target}"
    require(manifest["archive"] == prefix + ".zip")
    binary = "mitigate.exe" if target.endswith("windows-msvc") else "mitigate"
    expected = {
        binary,
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.txt",
        "RUST_NOTICES.html",
        "sbom.spdx.json",
        "build-info.json",
        "INSTALL.txt",
    }
    files = manifest["files"]
    require(isinstance(files, dict) and set(files) == expected)
    total = 0
    for name, entry in files.items():
        require(
            isinstance(entry, dict) and set(entry) == {"sha256", "size", "executable"}
        )
        require(
            digest(entry["sha256"])
            and type(entry["size"]) is int
            and 0 < entry["size"] <= MAX_FILE
        )
        require(
            type(entry["executable"]) is bool
            and entry["executable"] == (name == binary)
        )
        if name == "build-info.json":
            require(entry["size"] <= MAX_MANIFEST)
        total += entry["size"]
    require(total <= MAX_TOTAL)
    return manifest, prefix, binary


def checked_files(archive, manifest, prefix):
    """Consume only an authenticated snapshot; independently check every member.

    Total expanded bytes, individual bytes, exact names/types/modes and digests
    are checked before consumers can create installation files. No extractall.
    """
    require(
        archive.size == manifest["archive_size"]
        and archive.sha256 == manifest["archive_sha256"],
        "archive_mismatch",
    )
    files = manifest["files"]
    expected = {f"{prefix}/{name}" for name in files}
    result = {}
    try:
        # Bound the directory before ZipFile allocates entry objects. Eight small
        # members need neither ZIP64 nor split disks, comments or trailing data.
        with archive.path.open("rb") as reader:
            reader.seek(-22, 2)
            end = struct.unpack("<4s4H2LH", reader.read(22))
        require(
            end[:5] == (b"PK\x05\x06", 0, 0, len(expected), len(expected))
            and end[7] == 0
            and 0 < end[5] <= 4096
            and end[6] + end[5] + 22 == archive.size
        )
        with zipfile.ZipFile(archive.path) as source:
            entries = source.infolist()
            require(
                len(entries) == len(expected)
                and {entry.filename for entry in entries} == expected
            )
            require(not source.comment)
            for entry in entries:
                name = entry.filename.removeprefix(prefix + "/")
                record = files[name]
                mode = entry.external_attr >> 16
                require(
                    entry.file_size == record["size"]
                    and stat.S_ISREG(mode)
                    and stat.S_IMODE(mode) == (0o755 if record["executable"] else 0o644)
                    and entry.create_system == 3
                    and not entry.flag_bits & ~0x808
                    and not entry.extra
                    and not entry.comment
                    and entry.compress_type
                    in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                )
                with source.open(entry) as reader:
                    data = reader.read(record["size"] + 1)
                    require(len(data) == record["size"] and not reader.read(1))
                require(
                    hashlib.sha256(data).hexdigest() == record["sha256"],
                    "file_mismatch",
                )
                result[name] = data
    except (
        OSError,
        ValueError,
        RuntimeError,
        NotImplementedError,
        zipfile.BadZipFile,
        struct.error,
        zlib.error,
    ):
        raise VerificationError("archive_invalid") from None
    require(
        decode(result["build-info.json"])
        == {key: manifest[key] for key in BUILD_FIELDS}
    )
    return result
