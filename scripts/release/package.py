"""Create an unsigned CI candidate from a clean committed native Runtime build.

No credentials, signing, publication or customer state access. Archive reproducibility
means identical input bytes produce identical ZIP bytes, not bit-reproducible Rust.
"""

import argparse
import datetime
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import zipfile

from sbom import build_sbom, json_bytes, sha256

TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
           "aarch64-apple-darwin", "x86_64-apple-darwin")


def run(root, *args):
    return subprocess.run(args, cwd=root, check=True, stdout=subprocess.PIPE,
                          text=True, encoding="utf-8").stdout.strip()


def source_revision(root):
    if run(root, "git", "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Package candidates require a clean committed checkout")
    commit = run(root, "git", "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid source revision")
    return commit


def archive_bytes(path, files):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, (data, executable) in sorted(files.items()):
            if not re.fullmatch(r"[A-Za-z0-9._/-]+", name) or ".." in name.split("/") or name.startswith("/"):
                raise ValueError("Invalid package path")
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = (0o100755 if executable else 0o100644) << 16
            archive.writestr(item, data, compresslevel=9)


def package(root, target, output):
    import json

    if target not in TARGETS:
        raise ValueError("Unsupported release target")
    root, output = root.resolve(), output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be a new directory")
    commit = source_revision(root)
    toolchain = run(root, "rustc", "-vV")
    if f"host: {target}" not in toolchain.splitlines():
        raise ValueError("Candidate must be built and smoke-tested on its native target")
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        if os.environ.get(name):
            raise ValueError("Custom compiler flags/wrappers are not release inputs")
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Expected stable numeric candidate version")
    run(root, "cargo", "build", "--release", "--locked", "--package", "mitigate-cli",
        "--bin", "mitigate", "--target", target)
    metadata = json.loads(run(root, "cargo", "metadata", "--locked", "--format-version", "1",
                              "--filter-platform", target))
    executable = "mitigate.exe" if target.endswith("windows-msvc") else "mitigate"
    binary = Path(metadata["target_directory"]) / target / "release" / executable
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("Missing native release binary")
    built_version = json.loads(run(root, str(binary), "version", "--json"))
    if built_version["version"] != version:
        raise ValueError("Binary version differs from workspace")
    run(root, sys.executable, "scripts/verify-vendored-sqlite.py")
    epoch = int(run(root, "git", "show", "-s", "--format=%ct", commit))
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom, notices = build_sbom(metadata, tomllib.loads((root / "Cargo.lock").read_text()),
                               root, commit, target, created)
    sysroot = Path(run(root, "rustc", "--print", "sysroot"))
    rust_notices = (sysroot / "share/doc/rust/COPYRIGHT-library.html").read_bytes()
    if not 0 < len(rust_notices) <= 4 * 1024 * 1024:
        raise ValueError("Missing or oversized Rust standard library notices")
    compiler = dict(line.split(": ", 1) for line in toolchain.splitlines()[1:] if ": " in line)
    sbom["packages"].append({
        "SPDXID": "SPDXRef-RustStandardLibrary", "name": "Rust standard library",
        "versionInfo": compiler["release"], "filesAnalyzed": False,
        "downloadLocation": "NOASSERTION", "licenseDeclared": "Apache-2.0 OR MIT",
        "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
        "sourceInfo": f"https://github.com/rust-lang/rust/tree/{compiler['commit-hash']}/library; "
                      "including upstream exceptions and dependencies in RUST_NOTICES.html",
    })
    cli_id = next(p["SPDXID"] for p in sbom["packages"] if p["name"] == "mitigate-cli")
    sbom["relationships"].append({"spdxElementId": "SPDXRef-RustStandardLibrary",
                                 "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": cli_id})
    build_info = {
        "schema_version": 1, "kind": "unsigned_candidate", "version": version,
        "source_commit": commit, "target": target, "rustc": toolchain,
        "cargo_lock_sha256": sha256((root / "Cargo.lock").read_bytes()),
        "toolchain_file_sha256": sha256((root / "rust-toolchain.toml").read_bytes()),
    }
    name = f"mitigate-{version}-{target}"
    contents = {
        executable: (binary.read_bytes(), True),
        "LICENSE": ((root / "LICENSE").read_bytes(), False),
        "NOTICE": ((root / "NOTICE").read_bytes(), False),
        "THIRD_PARTY_NOTICES.txt": (notices, False),
        "RUST_NOTICES.html": (rust_notices, False),
        "sbom.spdx.json": (json_bytes(sbom), False),
        "build-info.json": (json_bytes(build_info), False),
        "INSTALL.txt": (b"UNSIGNED TEST CANDIDATE. Not a supported public release.\n"
                        b"Use only in an isolated test environment. No automatic install or update.\n"
                        b"Run mitigate version and mitigate privacy self-test --json.\n"
                        b"Runtime setup: https://github.com/mitigate-co/runtime/blob/main/README.md\n", False),
    }
    if source_revision(root) != commit:
        raise ValueError("Source changed during build")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mitigate-package-", dir=output.parent) as temporary:
        staging = Path(temporary) / "output"
        staging.mkdir()
        archive = staging / (name + ".zip")
        archive_bytes(archive, {f"{name}/{key}": value for key, value in contents.items()})
        manifest = {
            **build_info, "archive": archive.name,
            "archive_sha256": sha256(archive.read_bytes()), "archive_size": archive.stat().st_size,
            "files": {key: {"sha256": sha256(data), "size": len(data), "executable": executable}
                      for key, (data, executable) in sorted(contents.items())},
        }
        (staging / (name + ".manifest.json")).write_bytes(json_bytes(manifest))
        (staging / (name + ".spdx.json")).write_bytes(json_bytes(sbom))
        checksums = "".join(f"{sha256(path.read_bytes())}  {path.name}\n"
                            for path in sorted(staging.iterdir()))
        (staging / "SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
        staging.rename(output)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = package(Path(__file__).resolve().parents[2], args.target, args.output)
    print(f"Unsigned candidate created: {result.name}")
