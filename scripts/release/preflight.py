"""Read-only source checks before release signing. This never creates a release.

GitHub evidence is necessary, not sufficient: Apple signing/notarization, artifact
authentication, known security blockers and fresh-machine acceptance remain gates.
"""

import argparse
import json
import re
import subprocess

REPOSITORY = "mitigate-co/runtime"
WORKFLOWS = {
    "verify.yml": frozenset(
        {
            "rust (ubuntu-latest)",
            "rust (macos-latest)",
            "rust (windows-latest)",
            "dependencies",
            "secrets",
        }
    ),
    "package.yml": frozenset(
        {
            "package (ubuntu-22.04, x86_64-unknown-linux-gnu)",
            "package (windows-2022, x86_64-pc-windows-msvc)",
            "package (macos-14, aarch64-apple-darwin)",
            "package (macos-15-intel, x86_64-apple-darwin)",
        }
    ),
}


def expected_source(commit, tag):
    return bool(
        isinstance(commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", commit)
        and isinstance(tag, str)
        and re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    )


def signed_tag(reference, tag_object, tag, commit):
    try:
        return (
            reference["ref"] == "refs/tags/" + tag
            and reference["object"]["type"] == "tag"
            and reference["object"]["sha"] == tag_object["sha"]
            and tag_object["tag"] == tag
            and tag_object["object"]
            == {
                "type": "commit",
                "sha": commit,
                "url": f"https://api.github.com/repos/{REPOSITORY}/git/commits/{commit}",
            }
            and tag_object["verification"]["verified"] is True
            and tag_object["verification"]["reason"] == "valid"
        )
    except (KeyError, TypeError):
        return False


def on_main(comparison, commit):
    try:
        return (
            comparison["status"] in ("identical", "ahead")
            and comparison["base_commit"]["sha"] == commit
            and comparison["merge_base_commit"]["sha"] == commit
        )
    except (KeyError, TypeError):
        return False


def latest_run(response, workflow, commit):
    if not isinstance(response, dict) or not isinstance(
        response.get("workflow_runs"), list
    ):
        return None
    # Refuse incomplete evidence instead of selecting an older convenient success.
    runs = response["workflow_runs"]
    if (
        type(response.get("total_count")) is not int
        or response["total_count"] != len(runs)
        or len(runs) > 100
    ):
        return None
    matches = []
    for run in runs:
        if not isinstance(run, dict):
            return None
        if (
            run.get("head_sha") == commit
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("path") == ".github/workflows/" + workflow
            and isinstance(run.get("head_repository"), dict)
            and run["head_repository"].get("full_name") == REPOSITORY
        ):
            if (
                type(run.get("id")) is not int
                or run["id"] <= 0
                or type(run.get("run_attempt")) is not int
                or run["run_attempt"] <= 0
            ):
                return None
            matches.append(run)
    latest = max(matches, key=lambda run: (run["id"], run["run_attempt"]), default=None)
    if any(
        run is not latest
        and (
            run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run["run_attempt"] != 1
        )
        for run in matches
    ):
        return None
    return latest


def passed_jobs(run, response, workflow, commit):
    if (
        not run
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("run_attempt") != 1
    ):
        return False
    if not isinstance(response, dict) or not isinstance(response.get("jobs"), list):
        return False
    jobs = response["jobs"]
    if (
        type(response.get("total_count")) is not int
        or response["total_count"] != len(jobs)
        or len(jobs) != len(WORKFLOWS[workflow])
    ):
        return False
    if any(
        not isinstance(job, dict) or not isinstance(job.get("name"), str)
        for job in jobs
    ):
        return False
    return {job.get("name") for job in jobs} == WORKFLOWS[workflow] and all(
        job.get("head_sha") == commit
        and type(job.get("run_id")) is int
        and type(job.get("run_attempt")) is int
        and job["run_id"] == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        for job in jobs
    )


def github(path):
    """No mutation methods, shell interpolation, token lookup or provider output."""
    try:
        endpoint = "repos/" + REPOSITORY + ("/" + path if path else "")
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", endpoint],
            capture_output=True,
            timeout=20,
        )
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            return None
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def preflight(commit, tag, read=github):
    if not expected_source(commit, tag):
        raise ValueError(
            "Use a full lowercase commit SHA and a stable vMAJOR.MINOR.PATCH tag"
        )
    repository = read("")
    public = (
        isinstance(repository, dict)
        and repository.get("full_name") == REPOSITORY
        and repository.get("private") is False
        and repository.get("archived") is False
        and repository.get("default_branch") == "main"
    )
    gates = [{"id": "public_runtime_repository", "passed": public}]
    reference = read("git/ref/tags/" + tag)
    tag_object = None
    if isinstance(reference, dict):
        target = reference.get("object", {})
        digest = target.get("sha") if isinstance(target, dict) else None
        if (
            isinstance(target, dict)
            and target.get("type") == "tag"
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{40}", digest)
        ):
            tag_object = read("git/tags/" + digest)
    gates.append(
        {
            "id": "verified_annotated_tag",
            "passed": signed_tag(reference, tag_object, tag, commit),
        }
    )
    gates.append(
        {
            "id": "source_on_main",
            "passed": on_main(read(f"compare/{commit}...main"), commit),
        }
    )
    for workflow in WORKFLOWS:
        response = read(
            f"actions/workflows/{workflow}/runs?event=push&head_sha={commit}&per_page=100"
        )
        run = latest_run(response, workflow, commit)
        jobs = (
            read(
                f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100"
            )
            if run
            else None
        )
        gates.append(
            {
                "id": "native_tests" if workflow == "verify.yml" else "native_packages",
                "passed": passed_jobs(run, jobs, workflow, commit),
            }
        )
    return {
        "schema_version": 1,
        "repository": REPOSITORY,
        "source_commit": commit,
        "tag": tag,
        "source_eligible": all(gate["passed"] for gate in gates),
        "gates": gates,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        report = preflight(args.commit, args.tag)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["source_eligible"] else 2)
