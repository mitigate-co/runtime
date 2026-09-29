"""Synthetic supply-chain regressions; never execute fixture archive bytes."""

import copy
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import warnings
import zipfile

from package import archive_bytes, source_revision, verify_compiler
from sbom import build_sbom, cli_graph, json_bytes, sha256, source_identity
from smoke import verify_candidate

COMMIT = "a" * 40
TARGET = "x86_64-unknown-linux-gnu"
NAME = "mitigate-0.1.0-" + TARGET


class CandidateTests(unittest.TestCase):
    def test_compiler_target_version_flags_and_profiles_are_bound(self):
        compiler = f"rustc fixture\nhost: {TARGET}\nrelease: 1.98.1\ncommit-hash: {COMMIT}"
        self.assertEqual(verify_compiler(compiler, TARGET, "1.98.1", {})["release"], "1.98.1")
        for target, channel in ((TARGET, "1.99.0"), ("aarch64-apple-darwin", "1.98.1")):
            with self.assertRaises(ValueError):
                verify_compiler(compiler, target, channel, {})
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
                     "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
                     "CARGO_PROFILE_RELEASE_LTO"):
            with self.assertRaises(ValueError):
                verify_compiler(compiler, TARGET, "1.98.1", {name: "override"})

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.info = {"schema_version": 1, "kind": "unsigned_candidate", "version": "0.1.0",
                     "source_commit": COMMIT, "target": TARGET, "rustc": "synthetic compiler",
                     "cargo_lock_sha256": "b" * 64, "toolchain_file_sha256": "c" * 64}
        self.contents = {name: (b"synthetic bytes", name == "mitigate") for name in (
            "mitigate", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt", "sbom.spdx.json", "INSTALL.txt",
            "RUST_NOTICES.html")}
        self.contents["build-info.json"] = (json_bytes(self.info), False)
        self.archive = self.root / (NAME + ".zip")
        archive_bytes(self.archive, {f"{NAME}/{key}": value for key, value in self.contents.items()})
        self.manifest = {**self.info, "archive": self.archive.name,
                         "archive_sha256": sha256(self.archive.read_bytes()),
                         "archive_size": self.archive.stat().st_size,
                         "files": {key: {"sha256": sha256(data), "size": len(data), "executable": mode}
                                   for key, (data, mode) in self.contents.items()}}
        self.path = self.root / (NAME + ".manifest.json")
        self.write()

    def write(self):
        self.path.write_bytes(json_bytes(self.manifest))

    def verify(self):
        return verify_candidate(self.root, TARGET, COMMIT)

    def rehash(self):
        self.manifest["archive_sha256"] = sha256(self.archive.read_bytes())
        self.manifest["archive_size"] = self.archive.stat().st_size
        self.write()

    def test_deterministic_bytes_modes_and_verified_contents(self):
        second = self.root / "second.zip"
        archive_bytes(second, {f"{NAME}/{key}": value for key, value in reversed(list(self.contents.items()))})
        self.assertEqual(second.read_bytes(), self.archive.read_bytes())
        manifest, binary, verified = self.verify()
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(binary, "mitigate")
        self.assertEqual(verified, {name: data for name, (data, _) in self.contents.items()})

    def test_tampering_wrong_target_revision_and_unknown_fields(self):
        original = copy.deepcopy(self.manifest)
        for field, value in (("archive_sha256", "f" * 64), ("source_commit", "f" * 40),
                             ("target", "x86_64-pc-windows-msvc"), ("archive", "../outside.zip"),
                             ("kind", "signed_release"), ("schema_version", True),
                             ("archive_size", 512 * 1024 * 1024), ("unexpected", "private-canary")):
            with self.subTest(field=field):
                self.manifest = {**original, field: value}
                self.write()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_duplicate_json_unknown_file_and_oversized_expansion(self):
        self.path.write_text(self.path.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        with self.assertRaises(ValueError):
            self.verify()
        self.write()
        self.manifest["files"]["mitigate"]["size"] = 512 * 1024 * 1024
        self.write()
        with self.assertRaises(ValueError):
            self.verify()

    def test_archive_traversal_duplicate_symlink_and_checksum_mismatch(self):
        original_bytes = self.archive.read_bytes()
        for mode in ("traversal", "duplicate", "symlink", "modified"):
            with self.subTest(mode=mode):
                with zipfile.ZipFile(self.archive, "w") as archive:
                    for key, (data, executable) in self.contents.items():
                        info = zipfile.ZipInfo(f"{NAME}/{key}")
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | 0o755) << 16
                        if key == "mitigate":
                            if mode == "traversal":
                                info.filename = "../mitigate"
                            elif mode == "symlink":
                                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                            elif mode == "modified":
                                data = b"X" * len(data)
                        archive.writestr(info, data)
                        if mode == "duplicate" and key == "mitigate":
                            with warnings.catch_warnings():
                                warnings.simplefilter("ignore", UserWarning)
                                archive.writestr(info, data)
                self.rehash()
                with self.assertRaises(ValueError):
                    self.verify()
        self.archive.write_bytes(original_bytes)

    def test_file_modes_and_nested_unknown_fields(self):
        for field, value in (("executable", False), ("sha256", "0" * 64), ("url", "https://example.invalid")):
            original = copy.deepcopy(self.manifest)
            self.manifest["files"]["mitigate"][field] = value
            self.write()
            with self.assertRaises(ValueError):
                self.verify()
            self.manifest = original

    def test_conflicting_embedded_build_information(self):
        self.manifest["rustc"] = "different compiler"
        self.write()
        with self.assertRaises(ValueError):
            self.verify()

    def test_clean_source_required_including_untracked_files(self):
        def git(*args):
            return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)
        git("init")
        git("add", ".")
        git("-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "fixture")
        self.assertRegex(source_revision(self.root), r"^[0-9a-f]{40}$")
        self.path.write_text("changed")
        with self.assertRaises(ValueError):
            source_revision(self.root)
        git("restore", "--", self.path.name)
        (self.root / "untracked").write_text("private-canary")
        with self.assertRaises(ValueError):
            source_revision(self.root)


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "LICENSE").write_text("root notice")
        (self.root / "NOTICE").write_text("root copyright")
        packages = []
        for name in ("mitigate-cli", "normal", "builder", "dev-only"):
            directory = self.root / ("crates" if name == "mitigate-cli" else "registry") / name
            directory.mkdir(parents=True)
            (directory / "LICENSE-MIT").write_text("upstream license " + name)
            packages.append({"id": str(directory), "name": name, "version": "0.1.0", "license": "MIT",
                             "manifest_path": str(directory / "Cargo.toml"),
                             "source": None if name == "mitigate-cli" else "registry+https://github.com/rust-lang/crates.io-index"})
        ids = {p["name"]: p["id"] for p in packages}
        self.metadata = {"packages": packages, "workspace_members": [ids["mitigate-cli"]],
                         "resolve": {"nodes": [{"id": ids[name], "deps": [
                             {"pkg": ids[other], "dep_kinds": [{"kind": kind}]}
                             for other, kind in (("normal", None), ("builder", "build"), ("dev-only", "dev"))]
                             if name == "mitigate-cli" else []} for name in ids]}}
        self.lock = {"package": [{"name": p["name"], "version": p["version"],
                                   "source": p["source"], "checksum": "a" * 64} for p in packages]}

    def build(self):
        return build_sbom(self.metadata, self.lock, self.root, COMMIT, TARGET, "2026-09-29T00:00:00Z")

    def test_target_graph_build_dependencies_not_dev_and_no_local_paths(self):
        _, selected, edges = cli_graph(self.metadata)
        self.assertEqual({p["name"] for p in selected}, {"mitigate-cli", "normal", "builder"})
        self.assertEqual({kind for _, _, kind in edges}, {"DEPENDENCY_OF", "BUILD_DEPENDENCY_OF"})
        document, notices = self.build()
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        self.assertNotIn(str(self.root), json.dumps(document))
        self.assertNotIn(str(self.root), notices.decode())
        self.assertIn(b"upstream license normal", notices)
        self.assertNotIn(b"dev-only", notices)
        self.assertEqual(self.build(), (document, notices))

    def test_missing_locked_digest_and_unreviewed_sources_fail(self):
        self.lock["package"][1]["checksum"] = None
        with self.assertRaises(ValueError):
            self.build()
        package = self.metadata["packages"][1]
        package["source"] = "git+https://example.invalid/unreviewed"
        with self.assertRaises(ValueError):
            source_identity(package, self.root, COMMIT)
        package["source"] = None
        with self.assertRaises(ValueError):
            source_identity(package, self.root, COMMIT)

    def test_legacy_cargo_license_alternatives_are_normalized(self):
        self.metadata["packages"][1]["license"] = "MIT/Apache-2.0"
        document, _ = self.build()
        entry = next(p for p in document["packages"] if p["name"] == "normal")
        self.assertEqual(entry["licenseDeclared"], "MIT OR Apache-2.0")

    def test_exact_upstream_notice_supplement_rejects_source_and_byte_drift(self):
        package = self.metadata["packages"][1]
        directory = Path(package["manifest_path"]).parent
        (directory / "LICENSE-MIT").unlink()
        (directory / ".cargo_vcs_info.json").write_bytes(json_bytes({"git": {"sha1": COMMIT}}))
        catalog = self.root / "scripts/release/licenses"
        catalog.mkdir(parents=True)
        notice = catalog / "normal.txt"
        notice.write_bytes(b"upstream copyright and MIT permission")
        (catalog / "supplements.json").write_bytes(json_bytes({"normal@0.1.0": {
            "file": notice.name, "sha256": sha256(notice.read_bytes()), "commit": COMMIT,
            "source_url": "https://example.invalid/synthetic/LICENSE"}}))
        self.assertIn(b"upstream copyright and MIT permission", self.build()[1])
        (directory / ".cargo_vcs_info.json").write_bytes(json_bytes({"git": {"sha1": "f" * 40}}))
        with self.assertRaises(ValueError):
            self.build()
        (directory / ".cargo_vcs_info.json").write_bytes(json_bytes({"git": {"sha1": COMMIT}}))
        notice.write_bytes(b"altered")
        with self.assertRaises(ValueError):
            self.build()
    def test_nested_notices_included_and_absent_notices_refused(self):
        directory = Path(self.metadata["packages"][1]["manifest_path"]).parent
        nested = directory / "third_party"
        nested.mkdir()
        (nested / "LICENSE").write_text("nested copyright")
        self.assertIn(b"nested copyright", self.build()[1])
        (nested / "LICENSE").unlink()
        (directory / "LICENSE-MIT").unlink()
        with self.assertRaises(ValueError):
            self.build()


if __name__ == "__main__":
    unittest.main()
