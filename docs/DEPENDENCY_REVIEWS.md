# Dependency maintenance reviews

## yoke-derive 0.8.4 — 2026-09-30

The registry withdrew `yoke-derive 0.8.3`, causing the existing audit gate to
reject the locked graph. Update only this transitive package to
[0.8.4](https://crates.io/crates/yoke-derive/0.8.4). Do not ignore the warning or
relax the dependency gate.

The published archive identifies upstream commit
`a59ab860d4bda548e94dfbf992d87fe1f761bc55` in `unicode-org/icu4x`, at
`utils/yoke/derive`. Review of the two published archives found one implementation
change: lifetime-name underscore construction now uses `str::repeat` instead of
a byte vector and UTF-8 conversion. The macro's generated authority and borrowing
code is otherwise unchanged. No new package enters the Runtime lockfile.

This is a build-time procedural macro used through the existing ICU dependencies.
It adds no networking, telemetry, build script or Runtime data collection. Its
Unicode-3.0 license and license text are unchanged; retain that notice through the
existing release license bundle. The upstream declared Rust minimum remains
compatible with the pinned toolchain. Full workspace verification and the normal
dependency, license and native package gates still apply.

Upstream identifies the patch as a
[minimum Rust version fix](https://github.com/unicode-org/icu4x/pull/8528).
