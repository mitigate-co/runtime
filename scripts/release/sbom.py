"""Build-input SPDX inventory from Cargo's resolved, target-filtered CLI graph.

No source paths, environment values or Cargo IDs are emitted. This describes
resolved inputs, including build dependencies, not a binary reachability claim.
"""

import hashlib
import json
import os
import re
from pathlib import Path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def cli_graph(metadata):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = [p["id"] for p in packages.values() if p["name"] == "mitigate-cli"
             and p["id"] in metadata["workspace_members"]]
    if len(roots) != 1:
        raise ValueError("Expected exactly one workspace CLI")
    selected, edges, pending = set(), set(), [roots[0]]
    while pending:
        current = pending.pop()
        if current in selected:
            continue
        selected.add(current)
        for dependency in nodes[current]["deps"]:
            for kind in dependency["dep_kinds"]:
                if kind["kind"] not in (None, "build"):
                    continue
                other = dependency["pkg"]
                edges.add((other, current, "BUILD_DEPENDENCY_OF"
                           if kind["kind"] == "build" else "DEPENDENCY_OF"))
                pending.append(other)
    return roots[0], [packages[key] for key in selected], edges


def source_identity(package, root, commit):
    source = package["source"]
    if source == "registry+https://github.com/rust-lang/crates.io-index":
        return f"crates.io/{package['name']}/{package['version']}"
    if source is not None:
        raise ValueError("Unreviewed package source")
    path = Path(package["manifest_path"]).resolve().parent.relative_to(root.resolve())
    if path.parts[0] not in ("crates", "vendor"):
        raise ValueError("Unexpected local dependency")
    return f"mitigate-co/runtime/{commit}/{path.as_posix()}"


def license_notices(package, root):
    directory = Path(package["manifest_path"]).resolve().parent
    paths = set()
    # Nested upstream notices matter (for example ring's third_party licenses).
    # Limit traversal to the downloaded crate, never follow symlinks.
    for current, directories, files in os.walk(directory, followlinks=False):
        if any((Path(current) / child).is_symlink() for child in directories):
            raise ValueError("Symlink directory in dependency source")
        for filename in files:
            if re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE)([._-]|$)", filename.upper()):
                path = Path(current) / filename
                if path.is_symlink():
                    raise ValueError("Symlink license notice")
                paths.add(path)
    if package.get("license_file"):
        path = (directory / package["license_file"]).resolve()
        path.relative_to(directory)
        paths.add(path)
    if directory.is_relative_to(root / "crates"):
        paths.update((root / "LICENSE", root / "NOTICE"))
    supplement = None
    if not paths:
        catalog = root / "scripts/release/licenses/supplements.json"
        reviewed = json.loads(catalog.read_bytes()) if catalog.exists() else {}
        supplement = reviewed.get(f"{package['name']}@{package['version']}")
        if supplement is None or package["license"] != "MIT":
            raise ValueError(f"No license notices for {package['name']}")
        vcs = json.loads((directory / ".cargo_vcs_info.json").read_bytes())
        if vcs["git"]["sha1"] != supplement["commit"]:
            raise ValueError("License supplement source mismatch")
        path = catalog.parent / supplement["file"]
        path.resolve().relative_to(catalog.parent.resolve())
        if path.is_symlink() or sha256(path.read_bytes()) != supplement["sha256"]:
            raise ValueError("License supplement digest mismatch")
        paths.add(path)
    chunks = [f"\n=== {package['name']} {package['version']} ===\n",
              f"Declared license: {package['license']}\n"]
    for path in sorted(paths):
        data = path.read_bytes()
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("Oversized license notice")
        text = data.decode("utf-8")
        label = ("upstream supplement: " + supplement["source_url"] if supplement else
                 path.name if path.parent == root else path.relative_to(directory).as_posix())
        chunks.extend((f"\n--- {label} ---\n", text, "\n"))
    return "".join(chunks)


def build_sbom(metadata, lockfile, root, commit, target, created):
    root_id, selected, edges = cli_graph(metadata)
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum")
                 for p in lockfile["package"]}
    ids, packages, notices = {}, [], []
    for package in sorted(selected, key=lambda p: (p["name"], p["version"])):
        identity = source_identity(package, root, commit)
        identifier = "SPDXRef-" + sha256(identity.encode())[:32]
        ids[package["id"]] = identifier
        name, version, license = package["name"], package["version"], package["license"]
        # Cargo's historical slash syntax denotes alternatives, not conjunction.
        if license and re.fullmatch(r"[A-Za-z0-9.+-]+(/[A-Za-z0-9.+-]+)+", license):
            license = license.replace("/", " OR ")
        if not license or "/" in license:
            raise ValueError("Expected reviewed SPDX license expression")
        entry = {
            "SPDXID": identifier, "name": name, "versionInfo": version,
            "filesAnalyzed": False, "licenseDeclared": license,
            "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
        }
        if package["source"]:
            digest = checksums[(name, version, package["source"])]
            if not digest or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Registry dependency lacks locked SHA-256")
            entry.update({
                "downloadLocation": f"https://crates.io/api/v1/crates/{name}/{version}/download",
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                  "referenceType": "purl",
                                  "referenceLocator": f"pkg:cargo/{name}@{version}"}],
            })
        else:
            entry["sourceInfo"] = identity
        packages.append(entry)
        notices.append(license_notices(package, root))
    # The vendored Rust binding's version is not the bundled C library version.
    sqlite = next((p for p in selected if p["name"] == "libsqlite3-sys"), None)
    if sqlite:
        packages.append({
            "SPDXID": "SPDXRef-SQLite", "name": "SQLite", "versionInfo": "3.53.4",
            "downloadLocation": "https://sqlite.org/2026/sqlite-amalgamation-3530400.zip",
            "checksums": [{"algorithm": "SHA256", "checksumValue":
                "1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d"}],
            "filesAnalyzed": False, "licenseDeclared": "LicenseRef-SQLite-Public-Domain",
            "licenseConcluded": "NOASSERTION", "copyrightText": "NONE",
        })
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                      "relatedSpdxElement": ids[root_id]}]
    relationships += [{"spdxElementId": ids[a], "relationshipType": kind,
                       "relatedSpdxElement": ids[b]} for a, b, kind in edges]
    if sqlite:
        relationships.append({"spdxElementId": "SPDXRef-SQLite", "relationshipType": "DEPENDENCY_OF",
                              "relatedSpdxElement": ids[sqlite["id"]]})
    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"mitigate-{target}-build-inputs",
        "documentNamespace": f"https://github.com/mitigate-co/runtime/sbom/{commit}/{target}",
        "creationInfo": {"created": created, "creators": ["Tool: mitigate-release-sbom-1"]},
        "documentComment": "Resolved normal and build dependencies for the native CLI target. "
            "Includes conservative build inputs; excludes dev-only crates. Not a reachability analysis. "
            "The packager adds the Rust standard library and its upstream notices separately. "
            "System libraries and compiler executables are build prerequisites, not bundled packages.",
        "packages": sorted(packages, key=lambda p: p["SPDXID"]),
        "relationships": sorted(relationships, key=lambda r: tuple(r.values())),
    }
    if sqlite:
        statement = "SQLite is in the public domain. See https://sqlite.org/copyright.html."
        document["hasExtractedLicensingInfos"] = [{
            "licenseId": "LicenseRef-SQLite-Public-Domain", "extractedText": statement,
            "seeAlsos": ["https://sqlite.org/copyright.html"],
        }]
        notices.append("\n=== SQLite 3.53.4 ===\n" + statement + "\n")
    return document, "".join(notices).encode()
