"""Verifier tests for the control-plane effective-permission evaluator task."""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

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
SPEC_PATH = Path("/app/docs/report_spec.json")
LOG_PATH = Path("/app/incident/access_governance_log.md")
EXPECTED_FIXTURE = Path("/tests/fixtures/expected_report.json")
ALT_INPUT = Path("/tests/fixtures/alt_expanded_bindings.json")

TIER_ORDER = ["critical", "elevated", "routine"]
TIER_RANK = {name: len(TIER_ORDER) - idx for idx, name in enumerate(TIER_ORDER)}
BASIS_ORDER = ["direct_grant", "propagated_deny", "role_inheritance", "scoped_wildcard"]

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
WRONG_EXPANSIONS = ("shipped_shallow", "unbounded_closure", "cycle_naive", "depth_first")


WRONG_EXPANSIONS = ("shipped_shallow", "direct_members_only", "handles_dropped")


def _wrong_expansion(label: str) -> list[dict]:
    """Plausible mis-walks of the directory: the shipped shallow file, an
    expansion that takes only direct members, and one that drops handles
    entirely. Each must produce a different binding set from the governed walk."""
    bindings = _load_json(BINDINGS_PATH)
    groups = {g["handle"]: g for g in _load_json(DIRECTORY_PATH)["groups"]}
    if label == "shipped_shallow":
        return _load_json(SHIPPED_EXPANDED_REFERENCE_PATH)
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
        for member in group["members"]:            # direct members only: nested
            out.append(dict(row, principal=member))  # groups are never followed
    return out


def _digest(value: object) -> str:
    """Content digest of a whole artifact; the graded binding set and decision
    map are far too large to embed in a fixture, so equality is asserted over
    their digests."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# Documented wall-clock budget for one full run on the graded bindings.
# instruction.md and report_spec.json state the same number. The reference
# carries one running tally down the resource tree; rebuilding each node's set
# from every grant is the node count times the grant count and cannot finish.
RUNTIME_BUDGET_SEC = 90.0


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


# --- verifier execution isolation -------------------------------------------------
# The submitted /app/workflow/resolve_access.py is untrusted once the separate verifier runs it.
# We execute it under an unprivileged UID (65534 / nobody) via setpriv, so it cannot write the
# reward path, read the held-out fixtures under /tests, or interfere with the verifier. Inputs are
# staged into a candidate-writable work area; the tree, catalog and policy keep their fixed paths.
_CWORK = Path("/candidate-work")
_run_ctr = itertools.count()
_SETPRIV = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs"]

# The submitted program gets a minimal explicit environment rather than inheriting the verifier's
# (PATH/PYTHONPATH/CI variables and any other grader context).
_CANDIDATE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/candidate-work", "LANG": "C.UTF-8"}
_CANDIDATE_TIMEOUT = 300


def _candidate_dir() -> Path:
    d = _CWORK / f"run-{next(_run_ctr)}"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o777)
    return d


def _run_agent(argv, cwd: Path):
    """Run the submitted program under the unprivileged candidate UID with a scrubbed environment."""
    return subprocess.run(
        _SETPRIV + argv, check=True, capture_output=True, text=True, cwd=str(cwd),
        env=dict(_CANDIDATE_ENV), timeout=_CANDIDATE_TIMEOUT,
    )


def _run_pipeline(tmp_path: Path, script_path: Path = WORKFLOW_PATH, input_path: Path = DEFAULT_INPUT):
    work = _candidate_dir()
    out_dir = work / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o777)
    staged_input = work / "input.json"
    shutil.copy(str(input_path), str(staged_input))
    os.chmod(staged_input, 0o644)
    result = _run_agent(
        [sys.executable, str(script_path), "--input", str(staged_input), "--output-dir", str(out_dir)],
        cwd=work,
    )
    assert result.returncode == 0
    summary = _load_json(out_dir / "summary.json")
    decisions = _load_json(out_dir / "principal_decisions.json")
    queue = _load_jsonl(out_dir / "exception_queue.jsonl")
    return out_dir, summary, decisions, queue


def _run_on_bindings(tmp_path: Path, label: str, bindings: list[dict]):
    staged = tmp_path / f"{label}.json"
    staged.parent.mkdir(parents=True, exist_ok=True)
    _write_json(staged, bindings)
    return _run_pipeline(tmp_path / label, input_path=staged)


@pytest.fixture(scope="session")
def primary_outputs(tmp_path_factory):
    return _run_pipeline(tmp_path_factory.mktemp("primary"))


# --------------------------------------------------------------------------
# Step 1: the alias-addressed bindings must be expanded before anything resolves
# --------------------------------------------------------------------------
def test_expansion_sources_are_intact():
    """Verifies that expansion sources are intact."""
    assert _digest(_load_json(BINDINGS_PATH)) == FIXTURE["role_bindings_digest"]
    assert _digest(_load_json(DIRECTORY_PATH)) == FIXTURE["directory_export_digest"]


def test_bindings_expanded():
    """/app/data/expanded_bindings.json shipped shallow; it must hold the governed expansion."""
    expanded = _load_json(DEFAULT_INPUT)
    assert isinstance(expanded, list)
    assert len(expanded) == FIXTURE["expanded_count"]
    assert _digest(expanded) == FIXTURE["expanded_digest"]


def test_expanded_records_carry_only_binding_fields():
    """Verifies that expanded records carry only binding fields."""
    for record in _load_json(DEFAULT_INPUT):
        assert set(record) == set(BINDING_FIELDS)


def test_no_alias_handles_remain_in_the_expanded_bindings():
    """Verifies that no alias handles remain in the expanded bindings."""
    handles = {g["handle"] for g in _load_json(DIRECTORY_PATH)["groups"]}
    for record in _load_json(DEFAULT_INPUT):
        assert not record["principal"].startswith("@"), record
        assert record["principal"] not in handles


def test_shipped_and_wrong_expansions_differ_from_the_governed_one():
    """The expansion is real work: the shipped file and each plausible wrong walk all differ."""
    expected = FIXTURE["expanded_digest"]
    shipped = _load_json(SHIPPED_EXPANDED_REFERENCE_PATH)
    assert shipped != expected
    # the shipped file is a shallow expansion: it resolved handles to their direct
    # members but never followed the nesting, so it is short of the governed set
    assert not any(row["principal"].startswith("@") for row in shipped)
    assert len(shipped) < FIXTURE["expanded_count"]
    for label in WRONG_EXPANSIONS:
        assert _digest(_wrong_expansion(label)) != expected, label


def test_evaluator_output_depends_on_the_expansion(tmp_path: Path):
    """Even a correctly repaired evaluator emits wrong artifacts on a wrongly expanded set."""
    for label in WRONG_EXPANSIONS:
        _, summary, decisions, queue = _run_on_bindings(
            tmp_path, label, _wrong_expansion(label)
        )
        assert summary != FIXTURE["primary"]["summary"], label
        assert (_digest(decisions), _digest(queue)) != (
            FIXTURE["primary"]["decisions_digest"],
            FIXTURE["primary"]["queue_digest"],
        ), label


def test_nested_alias_principal_and_decision_flip(tmp_path: Path, primary_outputs):
    """A principal reachable only through a twice-nested handle disappears under the shallow
    expansion, and a named principal's effective decision flips with it."""
    _, _, decisions, _ = primary_outputs
    _, _, shallow_decisions, _ = _run_on_bindings(
        tmp_path, "shallow_probe", _load_json(SHIPPED_EXPANDED_REFERENCE_PATH)
    )
    nested_only = FIXTURE["nested_only_principal"]
    assert decisions.get(nested_only), nested_only
    assert nested_only not in shallow_decisions

    flip = FIXTURE["decision_flip"]

    def effect_at(blob: dict) -> str | None:
        for row in blob.get(flip["principal"], []):
            if row["node"] == flip["node"] and row["permission"] == flip["permission"]:
                return row["effect"]
        return None

    assert effect_at(decisions) == flip["correct_effect"]
    assert effect_at(shallow_decisions) == flip["shallow_effect"]
    assert flip["correct_effect"] != flip["shallow_effect"]


# --------------------------------------------------------------------------
# Step 2: the evaluator output contract
# --------------------------------------------------------------------------
def test_cli_exists():
    """Verifies that cli exists."""
    assert WORKFLOW_PATH.exists()


def test_output_dir_contains_exactly_three_files(primary_outputs):
    """Verifies that output dir contains exactly three files."""
    out_dir, _, _, _ = primary_outputs
    names = sorted(p.name for p in out_dir.iterdir() if p.is_file())
    assert names == ["exception_queue.jsonl", "principal_decisions.json", "summary.json"]


def test_primary_summary_matches_fixture(primary_outputs):
    """Verifies that primary summary matches fixture."""
    _, summary, _, _ = primary_outputs
    assert summary == FIXTURE["primary"]["summary"]


def test_primary_decisions_match_fixture(primary_outputs):
    """Verifies that primary decisions match fixture."""
    _, _, decisions, _ = primary_outputs
    assert _digest(decisions) == FIXTURE["primary"]["decisions_digest"]


def test_primary_queue_matches_fixture(primary_outputs):
    """Verifies that primary queue matches fixture."""
    _, _, _, queue = primary_outputs
    assert _digest(queue) == FIXTURE["primary"]["queue_digest"]


def _same_scalar_type(got: object, want: object) -> bool:
    """Exact type match. bool subclasses int in Python, so they are separated
    explicitly, and an integer count written as a float is not the same type."""
    if isinstance(got, bool) != isinstance(want, bool):
        return False
    return type(got) is type(want)


def test_summary_field_types_are_exact(primary_outputs):
    """Every summary field carries the contracted scalar type; equality alone
    would accept a count emitted as a float."""
    summary = primary_outputs[1]
    for key, want in FIXTURE["primary"]["summary"].items():
        got = summary[key]
        assert _same_scalar_type(got, want), (
            f"{key}: contract says {type(want).__name__}, got {type(got).__name__} ({got!r})"
        )


def test_summary_serialises_identically_to_the_contract(primary_outputs):
    """The summary's canonical JSON text matches the sealed one, catching a value
    written in a different numeric form."""
    assert _digest(primary_outputs[1]) == _digest(FIXTURE["primary"]["summary"])


def test_inherited_reach_is_reported_and_varies(primary_outputs):
    """Every decision carries an inherited-reach count, the counts vary across the
    tree, and the summary's maximum is the largest of them."""
    _, summary, decisions, _ = primary_outputs
    rows = [r for v in decisions.values() for r in v]
    counts = [r["node_effective_principals"] for r in rows]
    assert counts and all(isinstance(c, int) and not isinstance(c, bool) for c in counts)
    assert len(set(counts)) > 20, f"only {len(set(counts))} distinct reach values"
    assert max(counts) == summary["max_effective_principals"]


def test_inherited_reach_counts_ancestors_not_just_the_node(primary_outputs):
    """A node's reach is at least its parent's: inherited allows must be carried
    down, so a child can never see fewer principals than its ancestor grants."""
    _, _, decisions, _ = primary_outputs
    reach = {}
    for rows in decisions.values():
        for row in rows:
            reach[row["node"]] = row["node_effective_principals"]
    checked = 0
    for node, count in reach.items():
        parent = node.rsplit("/", 1)[0] or "/"
        if parent != node and parent in reach:
            assert count >= reach[parent], f"{node} sees fewer principals than {parent}"
            checked += 1
    assert checked > 100, "the tree must contain parent/child pairs to compare"


def test_summary_schema(primary_outputs):
    """Verifies that summary schema."""
    _, summary, _, _ = primary_outputs
    assert set(summary) == SUMMARY_KEYS
    assert summary["schema_version"] == "acl-resolve-v1"
    assert list(summary["tier_counts"]) == TIER_ORDER
    assert list(summary["basis_counts"]) == BASIS_ORDER


def test_decisions_schema_and_sorting(primary_outputs):
    """Verifies that decisions schema and sorting."""
    _, _, decisions, _ = primary_outputs
    assert list(decisions) == sorted(decisions)
    nodes = {row["node"] for row in _load_json(RESOURCE_TREE_PATH)}
    permissions = {
        rule["permission"]
        for role in _load_json(ROLE_CATALOG_PATH)
        for rule in role["rules"]
    }
    for principal_rows in decisions.values():
        keys = [(row["node"], row["permission"]) for row in principal_rows]
        assert keys == sorted(keys)
        assert len(keys) == len(set(keys))
        for row in principal_rows:
            assert set(row) == DECISION_KEYS
            assert row["node"] in nodes
            assert row["permission"] in permissions
            assert row["effect"] in {"allow", "deny"}
            assert row["decision_basis"] in BASIS_ORDER
            assert row["contested_effects"] == sorted(row["contested_effects"])
            assert set(row["contested_effects"]) <= {"allow", "deny"}
            assert row["node_depth"] == (0 if row["node"] == "/" else row["node"].count("/"))
            assert row["inherit_distance"] >= 0
            assert row["contest_count"] >= 0
            assert row["suppressed_descendants"] >= 0


def test_queue_required_fields(primary_outputs):
    """Verifies that queue required fields."""
    _, _, _, queue = primary_outputs
    for row in queue:
        assert set(row) == QUEUE_KEYS
        assert row["tier"] in TIER_RANK
        assert row["permission"] in REVIEWED_PERMISSIONS
        assert row["decision_id"] == f"{row['principal']}:{row['node']}:{row['permission']}"


def test_queue_rows_agree_with_the_decision_blob(primary_outputs):
    """Verifies that queue rows agree with the decision blob."""
    _, _, decisions, queue = primary_outputs
    for row in queue:
        matches = [
            d for d in decisions[row["principal"]]
            if d["node"] == row["node"] and d["permission"] == row["permission"]
        ]
        assert len(matches) == 1
        for field in SPEC["principal_decisions_json"]["required_fields"]:
            assert row[field] == matches[0][field]


def test_queue_sorted(primary_outputs):
    """Verifies that queue sorted."""
    _, _, _, queue = primary_outputs
    assert queue == sorted(
        queue,
        key=lambda row: (
            -TIER_RANK[row["tier"]],
            -row["risk_score"],
            -row["escalation_index"],
            -row["suppressed_descendants"],
            -row["contest_count"],
            -row["scope_specificity"],
            row["principal"],
            row["node"],
            row["permission"],
        ),
    )


def test_exception_queue_jsonl_compact(primary_outputs):
    """Verifies that exception queue jsonl compact."""
    out_dir, _, _, _ = primary_outputs
    for line in (out_dir / "exception_queue.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        assert ": " not in line
        assert json.dumps(json.loads(line), separators=(",", ":")) == line


def test_summary_math_consistency(primary_outputs):
    """Verifies that summary math consistency."""
    _, summary, decisions, queue = primary_outputs
    rows = [row for principal_rows in decisions.values() for row in principal_rows]
    assert summary["resolved_decision_count"] == len(rows)
    assert summary["allow_decision_count"] == sum(1 for r in rows if r["effect"] == "allow")
    assert summary["deny_decision_count"] == sum(1 for r in rows if r["effect"] == "deny")
    assert summary["allow_decision_count"] + summary["deny_decision_count"] == len(rows)
    assert summary["contested_decision_count"] == sum(1 for r in rows if r["contest_count"] > 0)
    assert summary["total_risk_score"] == sum(r["risk_score"] for r in rows)
    assert summary["total_escalation_index"] == sum(r["escalation_index"] for r in rows)
    assert summary["total_suppressed_descendants"] == sum(r["suppressed_descendants"] for r in rows)
    assert summary["queued_decision_count"] == len(queue)
    assert summary["max_suppressed_descendants"] == max(
        (r["suppressed_descendants"] for r in rows), default=0
    )
    for field in ("risk_score", "escalation_index", "contest_count"):
        assert summary["max_" + field] == max((r[field] for r in queue), default=0)


def test_summary_counts_track_the_expanded_bindings(primary_outputs):
    """Verifies that summary counts track the expanded bindings."""
    _, summary, decisions, _ = primary_outputs
    assert summary["expanded_binding_count"] == len(_load_json(DEFAULT_INPUT))
    assert summary["principal_count"] == len(decisions)
    assert summary["resource_node_count"] == len({r["node"] for r in _load_json(RESOURCE_TREE_PATH)})
    assert summary["role_count"] == len({r["role"] for r in _load_json(ROLE_CATALOG_PATH)})


def test_tier_and_basis_counts_enumerate_every_label(primary_outputs):
    """Verifies that tier and basis counts enumerate every label."""
    _, summary, decisions, queue = primary_outputs
    tiers = {tier: 0 for tier in TIER_ORDER}
    for row in queue:
        tiers[row["tier"]] += 1
    assert summary["tier_counts"] == tiers
    bases = {basis: 0 for basis in BASIS_ORDER}
    for principal_rows in decisions.values():
        for row in principal_rows:
            bases[row["decision_basis"]] += 1
    assert summary["basis_counts"] == bases
    assert all(count > 0 for count in bases.values())


# --------------------------------------------------------------------------
# Original / broken snapshot
# --------------------------------------------------------------------------
def test_original_snapshot_preserved():
    """Verifies that original snapshot preserved."""
    assert ORIGINAL_WORKFLOW_PATH.exists()
    digest = hashlib.sha256(ORIGINAL_WORKFLOW_PATH.read_bytes()).hexdigest()
    assert digest == FIXTURE["broken_evaluator_sha256"]


def test_broken_snapshot_is_wrong(tmp_path: Path):
    """Verifies that broken snapshot is wrong."""
    _, summary, decisions, queue = _run_pipeline(tmp_path, script_path=ORIGINAL_WORKFLOW_PATH)
    assert summary != FIXTURE["primary"]["summary"]
    assert _digest(decisions) != FIXTURE["primary"]["decisions_digest"]
    assert _digest(queue) != FIXTURE["primary"]["queue_digest"]


# --------------------------------------------------------------------------
# Generalization / idempotency / CLI
# --------------------------------------------------------------------------
def test_pipeline_rerun_idempotent(tmp_path: Path):
    """Verifies that pipeline rerun idempotent."""
    _, sa, da, qa = _run_pipeline(tmp_path / "a")
    _, sb, db, qb = _run_pipeline(tmp_path / "b")
    assert (sa, da, qa) == (sb, db, qb)


def test_pipeline_supports_alternate_binding_set(tmp_path: Path):
    """Verifies that pipeline supports alternate binding set."""
    _, summary, decisions, queue = _run_pipeline(tmp_path, input_path=ALT_INPUT)
    assert summary == FIXTURE["alternate"]["summary"]
    assert _digest(decisions) == FIXTURE["alternate"]["decisions_digest"]
    assert _digest(queue) == FIXTURE["alternate"]["queue_digest"]


def test_cli_defaults_work_and_match_explicit_run(tmp_path: Path):
    """Verifies that cli defaults work and match explicit run."""
    _, explicit_summary, _, _ = _run_pipeline(tmp_path)
    # The no-argument run writes to the default /app/output; clear any root-owned artifacts from
    # solve.sh and make the dir candidate-writable so the unprivileged program can populate it.
    default_out = Path("/app/output")
    shutil.rmtree(default_out, ignore_errors=True)
    default_out.mkdir(parents=True, exist_ok=True)
    os.chmod(default_out, 0o777)
    _run_agent([sys.executable, str(WORKFLOW_PATH)], cwd=_candidate_dir())
    assert _load_json(default_out / "summary.json") == explicit_summary


def test_submitted_program_runs_unprivileged_and_cannot_write_reward(tmp_path: Path):
    """The isolation itself works: code run the way the verifier runs the agent is unprivileged
    (uid 65534) and cannot write the reward path."""
    # Ensure the reward path exists and is root-owned (as it is under test.sh) before probing.
    os.makedirs("/logs/verifier", exist_ok=True)
    reward = Path("/logs/verifier/reward.txt")
    if not reward.exists():
        reward.write_text("0")
    os.chmod("/logs/verifier", 0o755)
    os.chmod(reward, 0o644)
    probe = _candidate_dir() / "probe.py"
    probe.write_text(
        "import os\n"
        "print(os.getuid())\n"
        "open('/logs/verifier/reward.txt', 'w').write('1')\n",
        encoding="utf-8",
    )
    os.chmod(probe, 0o644)
    res = subprocess.run(
        _SETPRIV + [sys.executable, str(probe)],
        capture_output=True, text=True, cwd=str(_CWORK), check=False,
    )
    assert res.stdout.strip().splitlines()[0] == "65534", "submitted program must run as uid 65534"
    assert res.returncode != 0 and "Permission denied" in res.stderr, (
        "unprivileged submitted program must not be able to write the reward path"
    )


# --------------------------------------------------------------------------
# Source-path influence
# --------------------------------------------------------------------------
def test_resource_tree_source_path_affects_output(tmp_path: Path):
    """Verifies that resource tree source path affects output."""
    original = RESOURCE_TREE_PATH.read_text(encoding="utf-8")
    try:
        _, summary_a, decisions_a, queue_a = _run_pipeline(tmp_path / "a")
        trimmed = [r for r in json.loads(original) if not r["node"].startswith("/prod/payments/")]
        _write_json(RESOURCE_TREE_PATH, trimmed)
        _, summary_b, decisions_b, queue_b = _run_pipeline(tmp_path / "b")
        assert summary_a["resource_node_count"] > summary_b["resource_node_count"]
        assert summary_a != summary_b
        assert decisions_a != decisions_b
        assert queue_a != queue_b
    finally:
        RESOURCE_TREE_PATH.write_text(original, encoding="utf-8")


def test_role_catalog_source_path_affects_output(tmp_path: Path):
    """Verifies that role catalog source path affects output."""
    original = ROLE_CATALOG_PATH.read_text(encoding="utf-8")
    try:
        _, summary_a, decisions_a, _ = _run_pipeline(tmp_path / "a")
        flattened = [dict(role, inherits=[]) for role in json.loads(original)]
        _write_json(ROLE_CATALOG_PATH, flattened)
        _, summary_b, decisions_b, _ = _run_pipeline(tmp_path / "b")
        assert summary_a["basis_counts"]["role_inheritance"] > 0
        assert summary_b["basis_counts"]["role_inheritance"] == 0
        assert summary_a != summary_b
        assert decisions_a != decisions_b
    finally:
        ROLE_CATALOG_PATH.write_text(original, encoding="utf-8")


def test_policy_source_path_affects_output(tmp_path: Path):
    """Verifies that policy source path affects output."""
    original = POLICY_PATH.read_text(encoding="utf-8")
    try:
        data = json.loads(original)
        data["default"]["admission_min"] = 999
        _write_json(POLICY_PATH, data)
        _, summary, _, queue = _run_pipeline(tmp_path / "shifted")
        assert summary != FIXTURE["primary"]["summary"]
        assert len(queue) < FIXTURE["primary"]["queue_count"]
    finally:
        POLICY_PATH.write_text(original, encoding="utf-8")


# --------------------------------------------------------------------------
# Policy resolution
# --------------------------------------------------------------------------
def _resolve(permission: str, data: dict) -> dict:
    base = dict(BASELINE)
    base.update({k: int(v) for k, v in data.get("default", {}).items() if k in BASELINE})
    override = data.get("permission_overrides", {}).get(permission)
    if isinstance(override, dict):
        base.update({k: int(v) for k, v in override.items() if k in BASELINE})
    return base


def test_sparse_override_inherits_remaining_fields():
    """Verifies that sparse override inherits remaining fields."""
    data = json.loads(POLICY_PATH.read_text())
    overrides = data.get("permission_overrides", {})
    sparse = [p for p, o in overrides.items() if len(o) == 1]
    assert sparse, "the shipped policy must exercise a single-field override"
    default_resolved = _resolve("__absent__", data)
    for permission in sparse:
        resolved = _resolve(permission, data)
        named = next(iter(overrides[permission]))
        assert resolved[named] == int(overrides[permission][named])
        for field in POLICY_FIELDS:
            if field != named:
                assert resolved[field] == default_resolved[field]


def test_policy_default_may_omit_fields_and_falls_back_to_baseline():
    """Verifies that policy default may omit fields and falls back to baseline."""
    data = json.loads(POLICY_PATH.read_text())
    omitted = [f for f in POLICY_FIELDS if f not in data.get("default", {})]
    assert omitted, "the shipped policy must omit at least one field to exercise fallback"
    resolved = _resolve("__absent__", data)
    for field in omitted:
        assert resolved[field] == BASELINE[field]


def test_tier_rules_follow_resolved_policy(primary_outputs):
    """Verifies that tier rules follow resolved policy."""
    _, _, _, queue = primary_outputs
    data = json.loads(POLICY_PATH.read_text())
    for row in queue:
        p = _resolve(row["permission"], data)
        assert row["risk_score"] >= p["admission_min"]
        if (
            row["risk_score"] >= p["critical_risk_min"]
            or row["escalation_index"] >= p["critical_escalation_min"]
            or row["suppressed_descendants"] >= p["critical_suppressed_min"]
        ):
            assert row["tier"] == "critical"
        elif (
            row["risk_score"] >= p["elevated_risk_min"]
            or row["contest_count"] >= 2
            or row["node_depth"] >= p["elevated_depth_min"]
        ):
            assert row["tier"] == "elevated"
        else:
            assert row["tier"] == "routine"


# --------------------------------------------------------------------------
# Capacity cap
# --------------------------------------------------------------------------
def test_principal_capacity_cap_applied_after_ordering(primary_outputs):
    """Verifies that principal capacity cap applied after ordering."""
    _, _, decisions, queue = primary_outputs
    per_principal: dict[str, int] = {}
    for row in queue:
        per_principal[row["principal"]] = per_principal.get(row["principal"], 0) + 1
    assert per_principal
    assert max(per_principal.values()) <= 3, f"principal exceeded cap: {per_principal}"
    admissible = sum(
        1
        for principal_rows in decisions.values()
        for row in principal_rows
        if row["permission"] in REVIEWED_PERMISSIONS
    )
    assert admissible > len(queue), "fixture must contain more admissible decisions than the cap allows"
    seen_order = [row["principal"] for row in queue]
    for principal in per_principal:
        idxs = [i for i, name in enumerate(seen_order) if name == principal]
        assert idxs == sorted(idxs)


# --------------------------------------------------------------------------
# Precedence dialect: specificity, propagation and inheritance
# --------------------------------------------------------------------------
@pytest.fixture(scope="session")
def probe_outputs(tmp_path_factory):
    bindings = [
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
    _, _, decisions, _ = _run_on_bindings(tmp_path_factory.mktemp("probe"), "probe", bindings)
    index = {
        (principal, row["node"], row["permission"]): row
        for principal, rows in decisions.items()
        for row in rows
    }
    return index


def test_specific_allow_beats_broader_deny_and_child_overrides_inherited_deny(probe_outputs):
    # /prod/* denies delete (role-operator, distance 0, specificity 2); the exact /prod/payments
    # break-glass binding both grants delete at distance 0 and inherits the operator deny at
    # distance 1, both at specificity 5. Specificity is compared first, then distance, then effect.
    """Verifies that specific allow beats broader deny and child overrides inherited deny."""
    row = probe_outputs[("probe-one", "/prod/payments", "delete")]
    assert row["effect"] == "allow"
    assert row["scope_specificity"] == 5
    assert row["inherit_distance"] == 0
    assert row["decision_basis"] == "direct_grant"
    assert "deny" in row["contested_effects"]


def test_exact_deny_propagates_downward_but_an_exact_allow_does_not(probe_outputs):
    """Verifies that exact deny propagates downward but an exact allow does not."""
    row = probe_outputs[("probe-one", "/prod/payments/ledger", "delete")]
    assert row["effect"] == "deny"
    assert row["decision_basis"] == "propagated_deny"
    assert row["scope_specificity"] == 5
    assert row["inherit_distance"] == 1


def test_node_level_deny_suppresses_the_subtree(probe_outputs):
    # An exact deny at /prod/payments beats the /prod/* allow there and at both children.
    """Verifies that node level deny suppresses the subtree."""
    row = probe_outputs[("probe-two", "/prod/payments", "export")]
    assert row["effect"] == "deny"
    assert row["decision_basis"] == "direct_grant"
    assert row["contest_count"] == 1
    assert row["contested_effects"] == ["allow"]
    assert row["suppressed_descendants"] == 2
    for child in ("/prod/payments/ledger", "/prod/payments/settlement"):
        child_row = probe_outputs[("probe-two", child, "export")]
        assert child_row["effect"] == "deny"
        assert child_row["decision_basis"] == "propagated_deny"
    assert probe_outputs[("probe-two", "/prod", "export")]["effect"] == "allow"
    assert probe_outputs[("probe-two", "/prod", "export")]["scope_specificity"] == 2


def test_deeper_wildcard_outranks_a_shallower_exact_scope(probe_outputs):
    # /prod exact scores 3; /prod/payments/* scores 4 and therefore wins at /prod/payments,
    # which the "an exact scope always beats a wildcard" reading gets backwards.
    """Verifies that deeper wildcard outranks a shallower exact scope."""
    row = probe_outputs[("probe-three", "/prod/payments", "delete")]
    assert row["scope_specificity"] == 4
    assert row["effect"] == "allow"
    assert row["decision_basis"] == "scoped_wildcard"
    root_row = probe_outputs[("probe-three", "/prod", "delete")]
    assert root_row["scope_specificity"] == 3
    assert root_row["effect"] == "deny"
    assert root_row["scope_specificity"] < row["scope_specificity"]


def test_role_inheritance_distance_is_the_shortest_path(probe_outputs):
    # role-breakglass reaches role-viewer through role-custodian in two hops and through
    # role-operator/role-analyst in three; the shorter one governs.
    """Verifies that role inheritance distance is the shorpath."""
    row = probe_outputs[("probe-one", "/prod/payments", "read")]
    assert row["inherit_distance"] == 2
    assert row["decision_basis"] == "role_inheritance"


# --------------------------------------------------------------------------
# Anti-delegation: static AST ban
# --------------------------------------------------------------------------
def test_evaluator_does_not_import_engines():
    """Verifies that evaluator does not import engines."""
    tree = ast.parse(WORKFLOW_PATH.read_text(encoding="utf-8"))
    banned = set(SPEC["workflow_repair"]["prohibited_imports"])
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    offending = banned & found
    assert not offending, f"evaluator must not delegate to a database or graph engine: {offending}"


def test_ast_check_catches_a_delegating_engine(tmp_path: Path):
    """The AST ban is real: a networkx-importing engine is detected."""
    shim = tmp_path / "delegating_engine.py"
    shim.write_text("import networkx\n\n\ndef run(a, b):\n    return networkx.DiGraph()\n")
    tree = ast.parse(shim.read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "networkx" in imported


# --------------------------------------------------------------------------
# Sources stay operational
# --------------------------------------------------------------------------
def test_governance_log_present():
    """Verifies that governance log present."""
    assert LOG_PATH.exists() and LOG_PATH.stat().st_size > 0


def test_evaluator_does_not_reference_test_artifacts():
    """Verifies that evaluator does not reference artifacts."""
    code = WORKFLOW_PATH.read_text(encoding="utf-8")
    for token in ("/tests", "expected_report.json", "alt_expanded_bindings.json"):
        assert token not in code
