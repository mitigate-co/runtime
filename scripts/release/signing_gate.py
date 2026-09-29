"""Read-only prerequisites for the protected release-signing job.

This observes source, checked-in unresolved failures and environment protections.
It creates no environment, approves no deployment and acquires no signing keys.
"""

import base64
import binascii
import json
import os
from pathlib import Path
import subprocess

from authenticate import VerificationError, regular
from install_contract import decode, require
from package import source_revision
from preflight import REPOSITORY, expected_source, github, preflight
from stage_release import Parser, workflow_context

ENVIRONMENT = "release-signing"


def unresolved_issues(data):
    require(0 < len(data) <= 4096, "release_blocker_policy")
    try:
        policy = decode(data)
    except VerificationError:
        raise VerificationError("release_blocker_policy") from None
    require(
        isinstance(policy, dict)
        and set(policy) == {"schema_version", "unresolved_issues"}
        and type(policy["schema_version"]) is int
        and policy["schema_version"] == 1,
        "release_blocker_policy",
    )
    issues = policy["unresolved_issues"]
    require(
        isinstance(issues, list)
        and len(issues) <= 100
        and all(type(issue) is int and 0 < issue <= 1_000_000_000 for issue in issues)
        and issues == sorted(set(issues)),
        "release_blocker_policy",
    )
    return issues


def current_main_issues(response):
    require(
        isinstance(response, dict)
        and response.get("type") == "file"
        and response.get("path") == "docs/RELEASE_BLOCKERS.json"
        and response.get("encoding") == "base64"
        and type(response.get("size")) is int
        and 0 < response["size"] <= 4096
        and isinstance(response.get("content"), str)
        and 0 < len(response["content"]) <= 8192,
        "release_blocker_policy",
    )
    try:
        data = base64.b64decode(response["content"].replace("\n", ""), validate=True)
    except (ValueError, binascii.Error):
        raise VerificationError("release_blocker_policy") from None
    require(len(data) == response["size"], "release_blocker_policy")
    return unresolved_issues(data)


def protected_environment(environment, policies):
    """Check documented public API fields; actual approval remains GitHub's gate."""
    if not isinstance(environment, dict) or not isinstance(policies, dict):
        return False
    branches = environment.get("deployment_branch_policy")
    if (
        environment.get("name") != ENVIRONMENT
        or type(environment.get("id")) is not int
        or environment["id"] <= 0
        or not isinstance(branches, dict)
        or set(branches) != {"protected_branches", "custom_branch_policies"}
        or branches["protected_branches"] is not False
        or branches["custom_branch_policies"] is not True
    ):
        return False
    rules = environment.get("protection_rules")
    if not isinstance(rules, list) or len(rules) > 10:
        return False
    if any(not isinstance(rule, dict) for rule in rules):
        return False
    approvals = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    if len(approvals) != 1:
        return False
    rule = approvals[0]
    if type(rule.get("prevent_self_review")) is not bool:
        return False
    reviewers = rule.get("reviewers")
    if not isinstance(reviewers, list) or not 1 <= len(reviewers) <= 6:
        return False
    identities = set()
    for reviewer in reviewers:
        if not isinstance(reviewer, dict) or reviewer.get("type") not in (
            "User",
            "Team",
        ):
            return False
        identity = reviewer.get("reviewer")
        if (
            not isinstance(identity, dict)
            or type(identity.get("id")) is not int
            or identity["id"] <= 0
        ):
            return False
        identities.add((reviewer["type"], identity["id"]))
    if len(identities) != len(reviewers):
        return False
    branches = policies.get("branch_policies")
    if (
        type(policies.get("total_count")) is not int
        or policies["total_count"] != 1
        or not isinstance(branches, list)
        or len(branches) != 1
        or not isinstance(branches[0], dict)
    ):
        return False
    return branches[0].get("type") == "tag" and branches[0].get("name") == "v*"


def signing_gate(root, commit, tag, read=github, environment=None, *, job="preflight"):
    require(expected_source(commit, tag) and len(tag) <= 64, "invalid_source")
    environment = os.environ if environment is None else environment
    try:
        require(job in {"preflight", "sign"}, "release_workflow_context")
        workflow_context(commit, tag, environment, job=job)
        context_valid = True
    except VerificationError:
        context_valid = False
    try:
        checkout_valid = source_revision(root) == commit
    except (OSError, ValueError, subprocess.CalledProcessError):
        checkout_valid = False
    issues, policy_valid = [], False
    try:
        path = root / "docs" / "RELEASE_BLOCKERS.json"
        require(regular(path.lstat()), "release_blocker_policy")
        with path.open("rb") as source:
            issues = unresolved_issues(source.read(4097))
        policy_valid = True
    except (OSError, VerificationError):
        pass
    main_policy_valid = False
    try:
        # An older otherwise eligible tag cannot hide a failure recorded on main
        # after that tag's source was reviewed. Both policies must be clear.
        current = current_main_issues(
            read("contents/docs/RELEASE_BLOCKERS.json?ref=main")
        )
        issues = sorted(set(issues) | set(current))
        main_policy_valid = True
    except VerificationError:
        pass
    source = preflight(commit, tag, read)
    protections = protected_environment(
        read(f"environments/{ENVIRONMENT}"),
        read(f"environments/{ENVIRONMENT}/deployment-branch-policies?per_page=100"),
    )
    gates = [
        {"id": "direct_release_workflow", "passed": context_valid},
        {"id": "clean_selected_checkout", "passed": checkout_valid},
        {"id": "source_and_ci", "passed": source["source_eligible"]},
        {"id": "blocker_policy_valid", "passed": policy_valid},
        {"id": "current_main_policy_valid", "passed": main_policy_valid},
        {
            "id": "unresolved_failures_cleared",
            "passed": policy_valid and main_policy_valid and not issues,
        },
        {"id": "signing_environment_protected", "passed": protections},
    ]
    return {
        "schema_version": 1,
        "repository": REPOSITORY,
        "source_commit": commit,
        "tag": tag,
        "signing_prerequisites_met": all(gate["passed"] for gate in gates),
        "unresolved_issues": issues,
        "gates": gates,
    }


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    try:
        args = parser.parse_args()
        report = signing_gate(
            Path(__file__).resolve().parents[2], args.commit, args.tag
        )
    except VerificationError as error:
        report = {
            "schema_version": 1,
            "signing_prerequisites_met": False,
            "error": str(error),
        }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["signing_prerequisites_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
