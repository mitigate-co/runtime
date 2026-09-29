"""Release evidence failures never acquire signing or publication authority."""

import copy
import subprocess
import unittest
from unittest.mock import patch

from preflight import (
    REPOSITORY,
    WORKFLOWS,
    expected_source,
    github,
    latest_run,
    preflight,
)

COMMIT = "a" * 40
TAG = "v0.1.0"
TAG_SHA = "b" * 40


def evidence():
    values = {
        "": {
            "full_name": REPOSITORY,
            "private": False,
            "archived": False,
            "default_branch": "main",
        },
        "git/ref/tags/"
        + TAG: {"ref": "refs/tags/" + TAG, "object": {"type": "tag", "sha": TAG_SHA}},
        "git/tags/"
        + TAG_SHA: {
            "sha": TAG_SHA,
            "tag": TAG,
            "object": {
                "type": "commit",
                "sha": COMMIT,
                "url": f"https://api.github.com/repos/{REPOSITORY}/git/commits/{COMMIT}",
            },
            "verification": {"verified": True, "reason": "valid"},
        },
        f"compare/{COMMIT}...main": {
            "status": "ahead",
            "base_commit": {"sha": COMMIT},
            "merge_base_commit": {"sha": COMMIT},
        },
    }
    for number, (workflow, names) in enumerate(WORKFLOWS.items(), 1):
        run = {
            "id": number,
            "run_attempt": 1,
            "head_sha": COMMIT,
            "head_branch": "main",
            "event": "push",
            "path": ".github/workflows/" + workflow,
            "head_repository": {"full_name": REPOSITORY},
            "status": "completed",
            "conclusion": "success",
        }
        values[
            f"actions/workflows/{workflow}/runs?event=push&head_sha={COMMIT}&per_page=100"
        ] = {"total_count": 1, "workflow_runs": [run]}
        values[f"actions/runs/{number}/attempts/1/jobs?per_page=100"] = {
            "total_count": len(names),
            "jobs": [
                {
                    "name": name,
                    "head_sha": COMMIT,
                    "run_id": number,
                    "run_attempt": 1,
                    "status": "completed",
                    "conclusion": "success",
                }
                for name in names
            ],
        }
    return values


class SourceGates(unittest.TestCase):
    def test_all_exact_source_gates_pass_without_any_mutation(self):
        values = evidence()
        paths = []

        def read(path):
            paths.append(path)
            return values.get(path)

        report = preflight(COMMIT, TAG, read)
        self.assertTrue(report["source_eligible"])
        self.assertEqual(len(report["gates"]), 5)
        self.assertEqual(len(paths), 8)

    def test_missing_unavailable_or_private_evidence_blocks(self):
        for path in evidence():
            with self.subTest(path=path):
                values = evidence()
                del values[path]
                self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])
        values = evidence()
        values[""]["private"] = True
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_unsigned_lightweight_changed_tag_or_non_main_source_blocks(self):
        for field, value in (
            ("verified", False),
            ("verified", 1),
            ("reason", "unknown_key"),
        ):
            values = evidence()
            values["git/tags/" + TAG_SHA]["verification"][field] = value
            self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])
        for field, value in (("type", "commit"), ("sha", "f" * 40)):
            values = evidence()
            values["git/ref/tags/" + TAG]["object"][field] = value
            self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])
        values = evidence()
        values[f"compare/{COMMIT}...main"]["merge_base_commit"]["sha"] = "f" * 40
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_newer_failed_run_is_not_replaced_by_an_old_success(self):
        values = evidence()
        key = f"actions/workflows/verify.yml/runs?event=push&head_sha={COMMIT}&per_page=100"
        run = copy.deepcopy(values[key]["workflow_runs"][0])
        run.update({"id": 3, "conclusion": "failure"})
        values[key]["workflow_runs"].append(run)
        values[key]["total_count"] = 2
        self.assertEqual(latest_run(values[key], "verify.yml", COMMIT)["id"], 3)
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_successful_retry_cannot_erase_first_attempt_evidence(self):
        values = evidence()
        key = f"actions/workflows/verify.yml/runs?event=push&head_sha={COMMIT}&per_page=100"
        values[key]["workflow_runs"][0]["run_attempt"] = 2
        jobs = values.pop("actions/runs/1/attempts/1/jobs?per_page=100")
        for job in jobs["jobs"]:
            job["run_attempt"] = 2
        values["actions/runs/1/attempts/2/jobs?per_page=100"] = jobs
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_new_successful_run_cannot_hide_an_older_failure_at_the_same_commit(self):
        values = evidence()
        key = f"actions/workflows/verify.yml/runs?event=push&head_sha={COMMIT}&per_page=100"
        older = values[key]["workflow_runs"][0]
        newer = copy.deepcopy(older)
        newer["id"] = 3
        older["conclusion"] = "failure"
        values[key]["workflow_runs"].append(newer)
        values[key]["total_count"] = 2
        jobs = copy.deepcopy(values["actions/runs/1/attempts/1/jobs?per_page=100"])
        for job in jobs["jobs"]:
            job["run_id"] = 3
        values["actions/runs/3/attempts/1/jobs?per_page=100"] = jobs
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_skipped_missing_extra_stale_attempt_and_wrong_commit_jobs_block(self):
        key = "actions/runs/1/attempts/1/jobs?per_page=100"
        for field, value in (
            ("head_sha", "f" * 40),
            ("run_attempt", 2),
            ("status", "queued"),
            ("conclusion", "skipped"),
            ("conclusion", "failure"),
            ("run_id", 2),
        ):
            values = evidence()
            values[key]["jobs"][0][field] = value
            self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])
        values = evidence()
        values[key]["total_count"] += 1
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])
        values = evidence()
        values[key]["jobs"].append(values[key]["jobs"][0])
        values[key]["total_count"] += 1
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_pull_request_fork_branch_other_workflow_and_incomplete_run_list_block(
        self,
    ):
        key = f"actions/workflows/verify.yml/runs?event=push&head_sha={COMMIT}&per_page=100"
        for field, value in (
            ("event", "pull_request"),
            ("head_branch", "feature"),
            ("head_repository", {"full_name": "untrusted/fork"}),
            ("head_repository", None),
            ("path", ".github/workflows/other.yml"),
        ):
            values = evidence()
            values[key]["workflow_runs"][0][field] = value
            self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])
        values = evidence()
        values[key]["total_count"] += 1
        self.assertFalse(preflight(COMMIT, TAG, values.get)["source_eligible"])

    def test_bad_input_does_not_contact_github(self):
        for commit, tag in (
            ("short", TAG),
            (COMMIT, "v0.1.0;echo x"),
            (COMMIT, "v00.1.0"),
            (COMMIT, "v0.1.0-beta"),
            (None, TAG),
            (COMMIT, None),
        ):
            self.assertFalse(expected_source(commit, tag))
            with self.assertRaises(ValueError):
                preflight(commit, tag, lambda _: self.fail("unexpected GitHub request"))

    def test_cli_failures_remain_closed_and_provider_diagnostics_are_discarded(self):
        for failure in (FileNotFoundError(), subprocess.TimeoutExpired("gh", 20)):
            with patch("preflight.subprocess.run", side_effect=failure):
                self.assertIsNone(github(""))
        for response in (
            subprocess.CompletedProcess([], 1, b"", b"private-token-canary"),
            subprocess.CompletedProcess([], 0, b"not JSON", b""),
        ):
            with patch("preflight.subprocess.run", return_value=response) as run:
                self.assertIsNone(github(""))
                args = run.call_args.args[0]
                self.assertEqual(args[:4], ["gh", "api", "--hostname", "github.com"])
                self.assertEqual(args[4], "repos/" + REPOSITORY)
                self.assertNotIn("--method", args)


if __name__ == "__main__":
    unittest.main()
