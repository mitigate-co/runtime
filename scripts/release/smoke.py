"""Verify and exercise a locally built unsigned candidate in fresh synthetic state.

Checksum integrity is not publisher authentication. This is a CI smoke harness,
not an installer; do not run it on an untrusted downloaded archive.
"""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import zipfile

from package import TARGETS
from sbom import sha256

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 384 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate manifest field")
        value[key] = item
    return value


def verify_candidate(directory, target, commit):
    require(target in TARGETS and re.fullmatch(r"[0-9a-f]{40}", commit), "Invalid expected build")
    manifests = list(directory.glob("*.manifest.json"))
    require(len(manifests) == 1, "Expected one manifest")
    path = manifests[0]
    require(not path.is_symlink() and path.stat().st_size <= 16384, "Invalid manifest file")
    manifest = json.loads(path.read_bytes(), object_pairs_hook=closed_object)
    require(set(manifest) == {"schema_version", "kind", "version", "source_commit", "target",
                             "rustc", "cargo_lock_sha256", "toolchain_file_sha256", "archive",
                             "archive_sha256", "archive_size", "files"}, "Unknown manifest fields")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["kind"] == "unsigned_candidate", "Not a supported candidate")
    require(manifest["target"] == target and manifest["source_commit"] == commit, "Wrong candidate build")
    require(isinstance(manifest["version"], str) and re.fullmatch(r"\d+\.\d+\.\d+", manifest["version"]),
            "Invalid candidate version")
    for field in ("cargo_lock_sha256", "toolchain_file_sha256", "archive_sha256"):
        require(isinstance(manifest[field], str) and re.fullmatch(r"[0-9a-f]{64}", manifest[field]),
                "Invalid candidate digest")
    require(isinstance(manifest["rustc"], str) and len(manifest["rustc"]) <= 4096, "Invalid compiler metadata")
    name = f"mitigate-{manifest['version']}-{target}"
    require(manifest["archive"] == name + ".zip" and path.name == name + ".manifest.json",
            "Wrong artifact name")
    binary = "mitigate.exe" if target.endswith("windows-msvc") else "mitigate"
    expected = {binary, "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt", "sbom.spdx.json",
                "RUST_NOTICES.html", "build-info.json", "INSTALL.txt"}
    files = manifest["files"]
    require(isinstance(files, dict) and set(files) == expected, "Unexpected packaged files")
    total = 0
    for name_in_archive, entry in files.items():
        require(isinstance(entry, dict) and set(entry) == {"sha256", "size", "executable"},
                "Unknown file metadata")
        require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
                "Invalid file digest")
        require(type(entry["size"]) is int and 0 < entry["size"] <= MAX_FILE, "Invalid file size")
        require(type(entry["executable"]) is bool and entry["executable"] == (name_in_archive == binary),
                "Invalid executable mode")
        total += entry["size"]
    require(total <= MAX_TOTAL, "Candidate exceeds expanded size limit")
    archive_path = directory / manifest["archive"]
    require(not archive_path.is_symlink() and type(manifest["archive_size"]) is int
            and 0 < manifest["archive_size"] <= MAX_ARCHIVE, "Invalid archive size")
    require(archive_path.stat().st_size == manifest["archive_size"], "Archive size mismatch")
    require(sha256(archive_path.read_bytes()) == manifest["archive_sha256"], "Archive checksum mismatch")
    verified = {}
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        require(len(infos) == len(expected) and {i.filename for i in infos} == {f"{name}/{f}" for f in expected},
                "Unexpected or duplicate archive paths")
        for info in infos:
            key = info.filename.removeprefix(name + "/")
            entry = files[key]
            require(info.file_size == entry["size"] and stat.S_ISREG(info.external_attr >> 16)
                    and not info.flag_bits & 1, "Invalid ZIP entry")
            data = archive.read(info)
            require(len(data) == entry["size"] and sha256(data) == entry["sha256"], "File checksum mismatch")
            verified[key] = data
    info = json.loads(verified["build-info.json"], object_pairs_hook=closed_object)
    require(info == {k: manifest[k] for k in ("schema_version", "kind", "version", "source_commit", "target",
                    "rustc", "cargo_lock_sha256", "toolchain_file_sha256")}, "Conflicting build information")
    return manifest, binary, verified


def smoke(directory, target, commit):
    manifest, binary, files = verify_candidate(directory, target, commit)
    with tempfile.TemporaryDirectory(prefix="mitigate-package-smoke-") as temporary:
        root = Path(temporary)
        executable = root / binary
        executable.write_bytes(files[binary])
        executable.chmod(0o700)
        project = root / "project"
        project.mkdir()
        config = root / "config.json"
        config.write_text('{"schema_version":1}', encoding="utf-8")
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() in ("SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP", "TMPDIR")}
        environment.update({"HOME": str(root), "USERPROFILE": str(root), "XDG_DATA_HOME": str(root)})

        def report(*args):
            result = subprocess.run([str(executable), *args, "--json"], cwd=root, env=environment,
                                    capture_output=True, timeout=30)
            require(result.returncode == 0 and not result.stderr, "Packaged CLI command failed")
            return json.loads(result.stdout)

        require(report("version")["version"] == manifest["version"], "Packaged version mismatch")
        require(report("config", "check", "--config", str(config))["valid"] is True, "Config check failed")
        scan = report("mcp", "scan", "--root", str(project))
        require(scan["servers"] == [], "Fresh scan was not empty")
        privacy = report("privacy", "self-test", "--work-dir", str(root))
        require(all(privacy[key] is True for key in ("passed", "positive_control", "queue_isolation",
                    "persisted_canaries_absent")) and privacy["network_requests"] == 0, "Privacy probe failed")
        egress = report("egress", "inspect")
        require(egress["destination"] is None and egress["queue"] is None
                and egress["observed_event_types"] == [], "Fresh egress state is not empty")
        config.write_text('{"schema_version":1,"credential":"private-smoke-canary"}', encoding="utf-8")
        result = subprocess.run([str(executable), "config", "check", "--config", str(config), "--json"],
                                cwd=root, env=environment, capture_output=True, timeout=30)
        require(result.returncode == 2 and not result.stdout
                and b"private-smoke-canary" not in result.stderr, "Invalid config failed unsafely")
    print("Packaged native CLI passed fresh-state version/config/scan/privacy/egress checks.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    smoke(args.directory, args.target, args.commit)
