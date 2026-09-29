#!/usr/bin/env bash
# CI-only synthetic keyring; do not point XDG_DATA_HOME at a user's real keyring.
set -euo pipefail
: "${RUNNER_TEMP:?Run only on an ephemeral CI runner}"
test "$XDG_DATA_HOME" = "$RUNNER_TEMP/mitigate-keyring-fixture"
printf '%s' 'mitigate-ci-fixture' | gnome-keyring-daemon --unlock --components=secrets >/dev/null
target/debug/mitigate-test-mcp secret-contract target/debug/mitigate
python3 scripts/verify-policy.py target/debug/mitigate --native
cargo run -p mitigate-enrollment --features https --example native_lifecycle --locked -- --allow-native-fixture --cli target/debug/mitigate
node scripts/verify-enrollment-cli.mjs target/debug/mitigate
