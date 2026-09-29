# Supplemental upstream notices

These exact-version crates declare MIT but omit a standalone license notice from
their published archive. `supplements.json` pins each package version, the
archive's `.cargo_vcs_info.json` commit, the upstream license URL and the copied
file's SHA-256. The package checksum remains independently pinned in Cargo.lock.
The packager refuses changed source metadata or notice bytes and does not fetch
licenses at build time. An unlisted missing notice fails packaging.

- `jsonschema-value` / `jsonschema-regex` 0.58.2: root MIT license at the exact
  published source revision, preserving Dmitry Dygalo's copyright.
- Verus builtins/macros/vstd: root MIT license at each exact published revision,
  preserving the Verus Contributors' copyright. The graph conservatively includes
  these build inputs; it does not assert runtime reachability.
- `vsimd` / `uuid-simd` 0.8.0: root MIT license at the exact published source
  revision, preserving Nugine's copyright.
- `convert_case` 0.4.0: the published manifest already declares MIT and names
  David Purdum. Its source revision contains no license file. The copy is the
  upstream author's first explicit MIT license file, commit
  `f72ca63c9d579fbab22e361c76e39d31d1e86a2e`, preserving the 2020 copyright.
  The catalog's package commit deliberately remains
  `300d9eef9e8c970e15f324afbc3df8b6a4ebbf71`; the license source URL identifies
  the separate license-file revision. This is not a claim that the file was
  shipped inside the 0.4.0 crate.

Full upstream URLs and byte digests are recorded beside every mapping. These
notices add no executable dependency or new license-policy exception. Recheck
them when updating a package version, and remove a mapping when the published
crate includes its own complete notices.
