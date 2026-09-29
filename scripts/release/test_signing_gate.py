"""Closed release policy and provider protection evidence; no secret or mutation calls."""

import copy
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from authenticate import VerificationError
import signing_gate as gate
from test_preflight import evidence, COMMIT, TAG
from test_stage_release import context


def protections():
    return {
        "id": 123,
        "name": "release-signing",
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [{"type": "User", "reviewer": {"id": 456}}],
            }
        ],
    }, {"total_count": 1, "branch_policies": [{"type": "tag", "name": "v*"}]}


class SigningGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mitigate-signing-gate-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        self.policy = self.root / "docs" / "RELEASE_BLOCKERS.json"
        self.policy.write_text(
            '{"schema_version":1,"unresolved_issues":[]}', encoding="utf-8"
        )
        self.evidence = evidence()
        self.evidence["contents/docs/RELEASE_BLOCKERS.json?ref=main"] = (
            self.main_policy([])
        )
        settings, policies = protections()
        self.evidence["environments/release-signing"] = settings
        self.evidence[
            "environments/release-signing/deployment-branch-policies?per_page=100"
        ] = policies
        self.context = context()
        self.context["GITHUB_JOB"] = "preflight"
        self.source = patch.object(gate, "source_revision", return_value=COMMIT)
        self.source.start()
        self.addCleanup(self.source.stop)

    def check(self):
        return gate.signing_gate(
            self.root, COMMIT, TAG, self.evidence.get, self.context
        )

    def main_policy(self, issues):
        data = json.dumps({"schema_version": 1, "unresolved_issues": issues}).encode()
        return {
            "type": "file",
            "path": "docs/RELEASE_BLOCKERS.json",
            "encoding": "base64",
            "size": len(data),
            "content": base64.b64encode(data).decode() + "\n",
        }

    def test_only_complete_source_policy_and_environment_evidence_qualifies(self):
        report = self.check()
        self.assertTrue(report["signing_prerequisites_met"])
        self.assertEqual(len(report["gates"]), 7)
        self.assertEqual(report["unresolved_issues"], [])
        settings = self.evidence["environments/release-signing"]
        settings["protection_rules"][0]["prevent_self_review"] = True
        self.assertTrue(self.check()["signing_prerequisites_met"])

    def test_closed_issue_cannot_silently_clear_checked_in_failure(self):
        self.policy.write_text('{"schema_version":1,"unresolved_issues":[36,46,50,57]}')
        seen = []

        def read(path):
            seen.append(path)
            return self.evidence.get(path)

        report = gate.signing_gate(self.root, COMMIT, TAG, read, self.context)
        self.assertFalse(report["signing_prerequisites_met"])
        self.assertEqual(report["unresolved_issues"], [36, 46, 50, 57])
        self.assertFalse(any(path.startswith("issues/") for path in seen))

    def test_missing_invalid_oversized_or_unknown_policy_fails_closed(self):
        for data in (
            b"not json",
            b"[]",
            b'{"schema_version":true,"unresolved_issues":[]}',
            b'{"schema_version":1,"unresolved_issues":[],"override":true}',
            b'{"schema_version":1,"unresolved_issues":[],"unresolved_issues":[36]}',
            b'{"schema_version":1,"unresolved_issues":[true]}',
            b'{"schema_version":1,"unresolved_issues":[-1]}',
            b'{"schema_version":1,"unresolved_issues":[36,36]}',
            b'{"schema_version":1,"unresolved_issues":[50,36]}',
            b"x" * 4097,
            b"\xff",
        ):
            with self.subTest(data=data[:80]):
                self.policy.write_bytes(data)
                self.assertFalse(self.check()["signing_prerequisites_met"])
        self.policy.unlink()
        self.assertFalse(self.check()["signing_prerequisites_met"])

    def test_new_failures_on_main_block_an_older_otherwise_eligible_source(self):
        self.evidence["contents/docs/RELEASE_BLOCKERS.json?ref=main"] = (
            self.main_policy([57])
        )
        report = self.check()
        self.assertFalse(report["signing_prerequisites_met"])
        self.assertEqual(report["unresolved_issues"], [57])
        self.policy.write_text('{"schema_version":1,"unresolved_issues":[36]}')
        self.assertEqual(self.check()["unresolved_issues"], [36, 57])

    def test_absent_or_malformed_main_policy_is_not_an_empty_policy(self):
        key = "contents/docs/RELEASE_BLOCKERS.json?ref=main"
        for field, value in (
            ("type", "symlink"),
            ("path", "another.json"),
            ("encoding", "none"),
            ("size", 5000),
            ("size", True),
            ("content", "invalid base64"),
        ):
            invalid = self.main_policy([])
            invalid[field] = value
            self.evidence[key] = invalid
            self.assertFalse(self.check()["signing_prerequisites_met"])
        del self.evidence[key]
        self.assertFalse(self.check()["signing_prerequisites_met"])

    def test_invalid_source_does_not_request_provider_evidence(self):
        with self.assertRaises(VerificationError):
            gate.signing_gate(
                self.root, "wrong", TAG, lambda _: self.fail("provider called")
            )

    def test_workflow_context_and_checkout_are_not_optional(self):
        for key in self.context:
            changed = dict(self.context, **{key: "wrong"})
            report = gate.signing_gate(
                self.root, COMMIT, TAG, self.evidence.get, changed
            )
            self.assertFalse(report["signing_prerequisites_met"])
        for result in ("b" * 40, ValueError("private-path-canary")):
            with patch.object(
                gate,
                "source_revision",
                side_effect=result if isinstance(result, Exception) else None,
                return_value=result,
            ):
                report = self.check()
                self.assertFalse(report["signing_prerequisites_met"])
                self.assertNotIn("private-path-canary", json.dumps(report))

    def test_missing_source_or_ci_evidence_blocks_even_with_approvals_configured(self):
        for key in list(evidence()):
            original = self.evidence.pop(key)
            self.assertFalse(self.check()["signing_prerequisites_met"], key)
            self.evidence[key] = original

    def test_missing_environment_extra_tag_or_branch_policy_blocks(self):
        settings, policies = protections()
        for field, value in (
            ("name", "unprotected"),
            ("id", True),
            ("deployment_branch_policy", None),
            ("protection_rules", []),
        ):
            invalid = copy.deepcopy(settings)
            invalid[field] = value
            self.assertFalse(gate.protected_environment(invalid, policies))
        for invalid in (
            None,
            {},
            {"total_count": 2, "branch_policies": policies["branch_policies"]},
            {"total_count": 1, "branch_policies": [{"type": "branch", "name": "v*"}]},
            {"total_count": 1, "branch_policies": [{"type": "tag", "name": "*"}]},
        ):
            self.assertFalse(gate.protected_environment(settings, invalid))

    def test_malformed_duplicate_or_missing_reviewers_never_count_as_approval_policy(
        self,
    ):
        settings, policies = protections()
        for reviewers in (
            [],
            None,
            [None],
            [{"type": "Bot", "reviewer": {"id": 1}}],
            [{"type": "User", "reviewer": {"id": True}}],
            [{"type": "User", "reviewer": {"id": 1}}] * 2,
        ):
            invalid = copy.deepcopy(settings)
            invalid["protection_rules"][0]["reviewers"] = reviewers
            self.assertFalse(gate.protected_environment(invalid, policies))
        settings["protection_rules"] *= 2
        self.assertFalse(gate.protected_environment(settings, policies))

    def test_provider_descriptions_and_tokens_cannot_enter_report(self):
        self.evidence["environments/release-signing"][
            "private_field"
        ] = "private-token-canary"
        report = self.check()
        self.assertTrue(report["signing_prerequisites_met"])
        self.assertNotIn("private-token-canary", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
