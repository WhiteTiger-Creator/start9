"""Shared machinery for the effective-permission verifier.

Paths, fixture loading, the unprivileged runner and the plausible wrong
expansions live here so test_outputs.py carries assertions and nothing else.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

WORKFLOW_PATH = Path("/app/workflow/resolve_access.py")
ORIGINAL_WORKFLOW_PATH = Path("/app/workflow/.resolve_access.original")
DEFAULT_INPUT = Path("/app/data/expanded_bindings.json")
# The shipped shallow file is overwritten in place by the expansion, so the
# verifier keeps its own copy to prove the evaluator depends on that step.
SHIPPED_EXPANDED_REFERENCE_PATH = Path("/tests/fixtures/shipped_expanded.json")
BINDINGS_PATH = Path("/app/data/role_bindings.json")
DIRECTORY_PATH = Path("/app/data/directory_export.json")
RESOURCE_TREE_PATH = Path("/app/data/resource_tree.json")
ROLE_CATALOG_PATH = Path("/app/data/role_catalog.json")
POLICY_PATH = Path("/app/data/access_policies.json")
EXCLUSIONS_PATH = Path("/app/data/scope_exclusions.json")
CONFLICTS_PATH = Path("/app/data/duty_conflicts.json")
SPEC_PATH = Path("/app/docs/report_spec.json")
LOG_PATH = Path("/app/incident/access_governance_log.md")
EXPECTED_FIXTURE = Path("/tests/fixtures/expected_report.json")
ALT_INPUT = Path("/tests/fixtures/alt_expanded_bindings.json")

TIER_ORDER = ["critical", "elevated", "routine"]
TIER_RANK = {name: len(TIER_ORDER) - idx for idx, name in enumerate(TIER_ORDER)}
BASIS_ORDER = ["direct_grant", "duty_conflict", "propagated_deny", "role_inheritance",
               "scoped_wildcard"]

FIXTURE = json.loads(EXPECTED_FIXTURE.read_text())
SPEC = json.loads(SPEC_PATH.read_text())

POLICY_FIELDS = (
    "permission_weight", "admission_min", "critical_risk_min", "critical_escalation_min",
    "critical_suppressed_min", "elevated_risk_min", "elevated_depth_min",
)
# Mirrors the governed baseline in the access log; the verifier resolves policy
# the same way the evaluator does, so these must not drift apart.
BASELINE = {
    "permission_weight": 4, "admission_min": 9, "critical_risk_min": 200,
    "critical_escalation_min": 260, "critical_suppressed_min": 40,
    "elevated_risk_min": 14, "elevated_depth_min": 8,
}
REVIEWED_PERMISSIONS = {"deploy", "delete", "rotate", "export"}
BINDING_FIELDS = ("binding_id", "principal", "role", "scope")

DECISION_KEYS = set(SPEC["principal_decisions_json"]["required_fields"])
QUEUE_KEYS = set(SPEC["exception_queue"]["required_fields"])
SUMMARY_KEYS = set(SPEC["summary_json"]["required_fields"])

# Documented wall-clock budget for one full run on the graded bindings.
# instruction.md and report_spec.json state the same number. The reference
# carries one running tally down the resource tree; rebuilding each node's set
# from every grant is the node count times the grant count and cannot finish.
RUNTIME_BUDGET_SEC = 90.0
# Wall-clock of each graded run, keyed by the input it was given, so the budget
# is enforced at its stated value rather than only by the looser harness timeout.
ELAPSED: dict[str, float] = {}

# Crafted bindings that put the governed precedence rules against the readings
# the board reversed. Used by the probe fixture in test_outputs.py.
PROBE_BINDINGS = [
    {"binding_id": "z-001", "principal": "probe-one", "role": "role-operator", "scope": "/prod/*"},
    {"binding_id": "z-002", "principal": "probe-one", "role": "role-breakglass",
     "scope": "/prod/payments"},
    {"binding_id": "z-003", "principal": "probe-two", "role": "role-analyst", "scope": "/prod/*"},
    {"binding_id": "z-004", "principal": "probe-two", "role": "role-custodian",
     "scope": "/prod/payments"},
    {"binding_id": "z-005", "principal": "probe-three", "role": "role-operator", "scope": "/prod"},
    {"binding_id": "z-006", "principal": "probe-three", "role": "role-breakglass",
     "scope": "/prod/payments/*"},
]

# Plausible mis-walks of the directory, each of which must produce a different
# binding set from the governed expansion: the shipped shallow file, a walk that
# takes only direct members, one that drops handles entirely, and one that reuses
# a single visited set across every binding so later bindings under-expand.
WRONG_EXPANSIONS = ("shipped_shallow", "direct_members_only", "handles_dropped", "shared_visited")


def digest(value: object) -> str:
    """Content digest of a whole artifact; the graded binding set and decision
    map are far too large to embed in a fixture, so equality is asserted over
    their digests."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: Path):
    return [json.loads(line)
            for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: object) -> None:
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def wrong_expansion(label: str) -> list[dict]:
    """Build one of the WRONG_EXPANSIONS variants from the operational sources."""
    if label == "shipped_shallow":
        return load_json(SHIPPED_EXPANDED_REFERENCE_PATH)
    bindings = load_json(BINDINGS_PATH)
    groups = {g["handle"]: g for g in load_json(DIRECTORY_PATH)["groups"]}
    shared_seen: set[str] = set()
    out: list[dict] = []
    for row in bindings:
        principal = row["principal"]
        if not principal.startswith("@"):
            out.append(dict(row))
            continue
        if label == "handles_dropped":
            continue
        group = groups.get(principal)
        if not group:
            continue
        if label == "direct_members_only":
            # nested groups are never followed
            for member in group["members"]:
                out.append(dict(row, principal=member))
            continue
        # shared_visited: transitive, but one visited set is reused across every
        # binding, so a handle already walked once contributes nothing again
        stack = [principal]
        while stack:
            handle = stack.pop()
            if handle in shared_seen or handle not in groups:
                continue
            shared_seen.add(handle)
            current = groups[handle]
            for member in current["members"]:
                out.append(dict(row, principal=member))
            stack.extend(current.get("nested", []))
    return out


def resolve_policy(permission: str, data: dict) -> dict:
    """Resolve the policy for one permission the way the governance log settles it."""
    base = dict(BASELINE)
    base.update({k: int(v) for k, v in data.get("default", {}).items() if k in BASELINE})
    override = data.get("permission_overrides", {}).get(permission)
    if isinstance(override, dict):
        base.update({k: int(v) for k, v in override.items() if k in BASELINE})
    return base


def same_scalar_type(got: object, want: object) -> bool:
    """Exact type match. bool subclasses int in Python, so they are separated
    explicitly, and an integer count written as a float is not the same type."""
    if isinstance(got, bool) != isinstance(want, bool):
        return False
    return type(got) is type(want)


# --- verifier execution isolation -------------------------------------------
# The submitted /app/workflow/resolve_access.py is untrusted once the separate
# verifier runs it. We execute it under an unprivileged UID (65534 / nobody) via
# setpriv, so it cannot write the reward path, read the held-out fixtures under
# /tests, or interfere with the verifier. Inputs are staged into a
# candidate-writable work area; the tree, catalog and policy keep their fixed paths.
CWORK = Path("/candidate-work")
_run_ctr = itertools.count()
SETPRIV = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs"]
# A minimal explicit environment rather than the verifier's own.
CANDIDATE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/candidate-work",
                 "LANG": "C.UTF-8"}
CANDIDATE_TIMEOUT = 300


def candidate_dir() -> Path:
    d = CWORK / f"run-{next(_run_ctr)}"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o777)
    return d


def run_agent(argv, cwd: Path):
    """Run the submitted program unprivileged, with a scrubbed environment."""
    return subprocess.run(
        SETPRIV + argv, check=True, capture_output=True, text=True, cwd=str(cwd),
        env=dict(CANDIDATE_ENV), timeout=CANDIDATE_TIMEOUT,
    )


def run_pipeline(tmp_path: Path, script_path: Path = WORKFLOW_PATH,
                 input_path: Path = DEFAULT_INPUT):
    """Run the submitted evaluator on one binding set and return its artifacts."""
    work = candidate_dir()
    out_dir = work / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o777)
    staged_input = work / "input.json"
    shutil.copy(str(input_path), str(staged_input))
    os.chmod(staged_input, 0o644)
    started = time.monotonic()
    result = run_agent(
        [sys.executable, str(script_path),
         "--input", str(staged_input), "--output-dir", str(out_dir)],
        cwd=work,
    )
    ELAPSED[str(input_path)] = time.monotonic() - started
    assert result.returncode == 0
    return (out_dir,
            load_json(out_dir / "summary.json"),
            load_json(out_dir / "principal_decisions.json"),
            load_jsonl(out_dir / "exception_queue.jsonl"))


def run_on_bindings(tmp_path: Path, label: str, bindings: list[dict]):
    """Run the submitted evaluator on a crafted binding set."""
    staged = tmp_path / f"{label}.json"
    staged.parent.mkdir(parents=True, exist_ok=True)
    write_json(staged, bindings)
    return run_pipeline(tmp_path / label, input_path=staged)
