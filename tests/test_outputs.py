"""Verifier tests for the control-plane effective-permission evaluator task.

Each test below corresponds to something instruction.md states is graded: the
expansion step, the sealed reference on the shipped and alternate binding sets,
the output contract, each dated decision in the governance log on its own
crafted instance, determinism, the frozen snapshot, the import ban and the
runtime budget. Shared machinery lives in harness.py.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from harness import (
    ALT_INPUT, BASELINE, BASIS_ORDER, BINDING_FIELDS, CONFLICTS_PATH, CWORK,
    DECISION_KEYS, EXCLUSIONS_PATH,
    DEFAULT_INPUT, DIRECTORY_PATH, ELAPSED, FIXTURE, LOG_PATH,
    ORIGINAL_WORKFLOW_PATH, POLICY_FIELDS, POLICY_PATH, PROBE_BINDINGS,
    QUEUE_KEYS, RESOURCE_TREE_PATH, REVIEWED_PERMISSIONS, ROLE_CATALOG_PATH,
    RUNTIME_BUDGET_SEC, SETPRIV, SHIPPED_EXPANDED_REFERENCE_PATH, SPEC,
    SUMMARY_KEYS, TIER_ORDER, TIER_RANK, WORKFLOW_PATH, WRONG_EXPANSIONS,
    BINDINGS_PATH, candidate_dir, digest, load_json, resolve_policy,
    run_agent, run_on_bindings, run_pipeline, same_scalar_type, wrong_expansion,
    write_json,
)


@pytest.fixture(scope="session")
def primary_outputs(tmp_path_factory):
    return run_pipeline(tmp_path_factory.mktemp("primary"))


@pytest.fixture(scope="session")
def probe_outputs(tmp_path_factory):
    """Decisions for the crafted probe bindings, indexed for direct lookup."""
    _, _, decisions, _ = run_on_bindings(
        tmp_path_factory.mktemp("probe"), "probe", PROBE_BINDINGS)
    return {(principal, row["node"], row["permission"]): row
            for principal, rows in decisions.items() for row in rows}


# --------------------------------------------------------------------------
# Step 1: the alias-addressed bindings must be expanded before anything resolves
# --------------------------------------------------------------------------
def test_expansion_sources_are_intact():
    """The bindings and the directory export are read, not rewritten."""
    assert digest(load_json(BINDINGS_PATH)) == FIXTURE["role_bindings_digest"]
    assert digest(load_json(DIRECTORY_PATH)) == FIXTURE["directory_export_digest"]


def test_expanded_bindings_match_the_governed_walk():
    """/app/data/expanded_bindings.json shipped shallow; it must now hold the
    governed expansion, carrying only binding fields and no surviving handle."""
    expanded = load_json(DEFAULT_INPUT)
    assert isinstance(expanded, list)
    assert len(expanded) == FIXTURE["expanded_count"]
    assert digest(expanded) == FIXTURE["expanded_digest"]
    handles = {g["handle"] for g in load_json(DIRECTORY_PATH)["groups"]}
    for record in expanded:
        assert set(record) == set(BINDING_FIELDS)
        assert not record["principal"].startswith("@"), record
        assert record["principal"] not in handles


def test_shipped_and_wrong_expansions_differ_from_the_governed_one():
    """The expansion is real work: the shipped file and every plausible wrong walk differ."""
    expected = FIXTURE["expanded_digest"]
    shipped = load_json(SHIPPED_EXPANDED_REFERENCE_PATH)
    assert digest(shipped) != expected
    # the shipped file resolved handles to their direct members but never
    # followed the nesting, so it is short of the governed set
    assert not any(row["principal"].startswith("@") for row in shipped)
    assert len(shipped) < FIXTURE["expanded_count"]
    for label in WRONG_EXPANSIONS:
        wrong = wrong_expansion(label)
        assert wrong, label
        assert digest(wrong) != expected, label


def test_evaluator_output_depends_on_the_expansion(tmp_path: Path):
    """Even a correctly repaired evaluator emits wrong artifacts on a wrongly expanded set."""
    for label in WRONG_EXPANSIONS:
        _, summary, decisions, queue = run_on_bindings(tmp_path, label, wrong_expansion(label))
        assert summary != FIXTURE["primary"]["summary"], label
        assert (digest(decisions), digest(queue)) != (
            FIXTURE["primary"]["decisions_digest"], FIXTURE["primary"]["queue_digest"]), label


def test_nested_alias_principal_and_decision_flip(tmp_path: Path, primary_outputs):
    """A principal reachable only through a twice-nested handle disappears under the
    shallow expansion, and a named principal's effective decision flips with it."""
    _, _, decisions, _ = primary_outputs
    _, _, shallow_decisions, _ = run_on_bindings(
        tmp_path, "shallow_probe", load_json(SHIPPED_EXPANDED_REFERENCE_PATH))
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
# Step 2: the graded run against the sealed reference and the output contract
# --------------------------------------------------------------------------
def test_primary_run_matches_the_sealed_reference(primary_outputs):
    """Summary, decision blob and queue all match the sealed reference run, and the
    summary's canonical JSON matches too, catching a value in a different numeric form."""
    _, summary, decisions, queue = primary_outputs
    assert summary == FIXTURE["primary"]["summary"]
    assert digest(summary) == digest(FIXTURE["primary"]["summary"])
    assert digest(decisions) == FIXTURE["primary"]["decisions_digest"]
    assert digest(queue) == FIXTURE["primary"]["queue_digest"]


def test_pipeline_supports_alternate_binding_set(tmp_path: Path):
    """A held-out binding set the agent never sees produces the sealed result."""
    _, summary, decisions, queue = run_pipeline(tmp_path, input_path=ALT_INPUT)
    assert summary == FIXTURE["alternate"]["summary"]
    assert digest(decisions) == FIXTURE["alternate"]["decisions_digest"]
    assert digest(queue) == FIXTURE["alternate"]["queue_digest"]


def test_output_dir_contains_exactly_three_files(primary_outputs):
    """A run writes the three contracted artifacts and nothing else."""
    out_dir, _, _, _ = primary_outputs
    names = sorted(p.name for p in out_dir.iterdir() if p.is_file())
    assert names == ["exception_queue.jsonl", "principal_decisions.json", "summary.json"]


def test_summary_schema_and_field_types(primary_outputs):
    """The summary carries exactly the contracted fields, in the contracted label
    order, at the contracted scalar types; equality alone would accept a float count."""
    _, summary, _, _ = primary_outputs
    assert set(summary) == SUMMARY_KEYS
    assert summary["schema_version"] == "acl-resolve-v1"
    assert list(summary["tier_counts"]) == TIER_ORDER
    assert list(summary["basis_counts"]) == BASIS_ORDER
    for key, want in FIXTURE["primary"]["summary"].items():
        got = summary[key]
        assert same_scalar_type(got, want), (
            f"{key}: contract says {type(want).__name__}, got {type(got).__name__} ({got!r})")


def test_decisions_schema_and_sorting(primary_outputs):
    """Every decision row carries the contracted fields and values, and both the
    principal map and each principal's rows are in the contracted order."""
    _, _, decisions, _ = primary_outputs
    assert list(decisions) == sorted(decisions)
    nodes = {row["node"] for row in load_json(RESOURCE_TREE_PATH)}
    permissions = {rule["permission"] for role in load_json(ROLE_CATALOG_PATH)
                   for rule in role["rules"]}
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


def test_queue_matches_the_contract(primary_outputs):
    """Queue rows carry the contracted fields, agree field-for-field with the
    decision blob, sit in the contracted order and are serialised compactly."""
    out_dir, _, decisions, queue = primary_outputs
    for row in queue:
        assert set(row) == QUEUE_KEYS
        assert row["tier"] in TIER_RANK
        assert row["permission"] in REVIEWED_PERMISSIONS
        assert row["decision_id"] == f"{row['principal']}:{row['node']}:{row['permission']}"
        matches = [d for d in decisions[row["principal"]]
                   if d["node"] == row["node"] and d["permission"] == row["permission"]]
        assert len(matches) == 1
        for field in SPEC["principal_decisions_json"]["required_fields"]:
            assert row[field] == matches[0][field]
    assert queue == sorted(queue, key=lambda row: (
        -TIER_RANK[row["tier"]], -row["risk_score"], -row["escalation_index"],
        -row["suppressed_descendants"], -row["contest_count"], -row["scope_specificity"],
        row["principal"], row["node"], row["permission"]))
    for line in (out_dir / "exception_queue.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            assert ": " not in line
            assert json.dumps(json.loads(line), separators=(",", ":")) == line


def test_summary_math_consistency(primary_outputs):
    """Every summary total is the total of the artifacts emitted beside it."""
    _, summary, decisions, queue = primary_outputs
    rows = [row for principal_rows in decisions.values() for row in principal_rows]
    assert summary["resolved_decision_count"] == len(rows)
    assert summary["allow_decision_count"] == sum(1 for r in rows if r["effect"] == "allow")
    assert summary["deny_decision_count"] == sum(1 for r in rows if r["effect"] == "deny")
    assert summary["allow_decision_count"] + summary["deny_decision_count"] == len(rows)
    assert summary["contested_decision_count"] == sum(1 for r in rows if r["contest_count"] > 0)
    assert summary["total_risk_score"] == sum(r["risk_score"] for r in rows)
    assert summary["total_escalation_index"] == sum(r["escalation_index"] for r in rows)
    assert summary["total_suppressed_descendants"] == sum(
        r["suppressed_descendants"] for r in rows)
    assert summary["queued_decision_count"] == len(queue)
    assert summary["max_suppressed_descendants"] == max(
        (r["suppressed_descendants"] for r in rows), default=0)
    for field in ("risk_score", "escalation_index", "contest_count"):
        assert summary["max_" + field] == max((r[field] for r in queue), default=0)


def test_summary_counts_track_the_expanded_bindings(primary_outputs):
    """The summary's population counts come from the operational inputs."""
    _, summary, decisions, _ = primary_outputs
    assert summary["expanded_binding_count"] == len(load_json(DEFAULT_INPUT))
    assert summary["principal_count"] == len(decisions)
    assert summary["resource_node_count"] == len(
        {r["node"] for r in load_json(RESOURCE_TREE_PATH)})
    assert summary["role_count"] == len({r["role"] for r in load_json(ROLE_CATALOG_PATH)})


def test_tier_and_basis_counts_enumerate_every_label(primary_outputs):
    """Both label breakdowns enumerate every documented label, and each basis occurs."""
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


# --------------------------------------------------------------------------
# Each governed decision, pinned on a crafted instance where the drafts disagree
# --------------------------------------------------------------------------
def test_specific_allow_beats_broader_deny_and_child_overrides_inherited_deny(probe_outputs):
    """/prod/* denies delete (role-operator, distance 0, specificity 2); the exact
    /prod/payments break-glass binding both grants delete at distance 0 and inherits
    the operator deny at distance 1, both at specificity 5. Specificity is compared
    first, then distance, then effect."""
    row = probe_outputs[("probe-one", "/prod/payments", "delete")]
    assert row["effect"] == "allow"
    assert row["scope_specificity"] == 5
    assert row["inherit_distance"] == 0
    assert row["decision_basis"] == "direct_grant"
    assert "deny" in row["contested_effects"]


def test_exact_deny_propagates_downward_but_an_exact_allow_does_not(probe_outputs):
    """The allow that governs at /prod/payments does not carry to its child, but the
    deny it beat there does, so the child resolves deny on propagation."""
    row = probe_outputs[("probe-one", "/prod/payments/ledger", "delete")]
    assert row["effect"] == "deny"
    assert row["decision_basis"] == "propagated_deny"
    assert row["scope_specificity"] == 5
    assert row["inherit_distance"] == 1


def test_node_level_deny_suppresses_the_subtree(probe_outputs):
    """An exact deny at /prod/payments beats the /prod/* allow there and at both
    children, and is counted as suppressing exactly those two descendants."""
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
    """/prod exact scores 3; /prod/payments/* scores 4 and therefore wins at
    /prod/payments, which the "an exact scope always beats a wildcard" reading gets
    backwards."""
    row = probe_outputs[("probe-three", "/prod/payments", "delete")]
    assert row["scope_specificity"] == 4
    assert row["effect"] == "allow"
    assert row["decision_basis"] == "scoped_wildcard"
    root_row = probe_outputs[("probe-three", "/prod", "delete")]
    assert root_row["scope_specificity"] == 3
    assert root_row["effect"] == "deny"
    assert root_row["scope_specificity"] < row["scope_specificity"]


def test_role_inheritance_distance_is_the_shortest_path(probe_outputs):
    """role-breakglass reaches role-viewer through role-custodian in two hops and
    through role-operator then role-analyst in three; the shortest path governs."""
    row = probe_outputs[("probe-one", "/prod/payments", "read")]
    assert row["inherit_distance"] == 2
    assert row["decision_basis"] == "role_inheritance"


def test_sparse_override_inherits_remaining_fields():
    """A permission override naming one field changes that field alone."""
    data = json.loads(POLICY_PATH.read_text())
    overrides = data.get("permission_overrides", {})
    sparse = [p for p, o in overrides.items() if len(o) == 1]
    assert sparse, "the shipped policy must exercise a single-field override"
    default_resolved = resolve_policy("__absent__", data)
    for permission in sparse:
        resolved = resolve_policy(permission, data)
        named = next(iter(overrides[permission]))
        assert resolved[named] == int(overrides[permission][named])
        for field in POLICY_FIELDS:
            if field != named:
                assert resolved[field] == default_resolved[field]


def test_policy_default_may_omit_fields_and_falls_back_to_baseline():
    """A field the policy file omits keeps the baseline the governance log states."""
    data = json.loads(POLICY_PATH.read_text())
    omitted = [f for f in POLICY_FIELDS if f not in data.get("default", {})]
    assert omitted, "the shipped policy must omit at least one field to exercise fallback"
    resolved = resolve_policy("__absent__", data)
    for field in omitted:
        assert resolved[field] == BASELINE[field]


def test_tier_rules_follow_resolved_policy(primary_outputs):
    """Every queued row is admitted and tiered by its own resolved policy."""
    _, _, _, queue = primary_outputs
    data = json.loads(POLICY_PATH.read_text())
    for row in queue:
        p = resolve_policy(row["permission"], data)
        assert row["risk_score"] >= p["admission_min"]
        if (row["risk_score"] >= p["critical_risk_min"]
                or row["escalation_index"] >= p["critical_escalation_min"]
                or row["suppressed_descendants"] >= p["critical_suppressed_min"]):
            assert row["tier"] == "critical"
        elif (row["risk_score"] >= p["elevated_risk_min"]
                or row["contest_count"] >= 2
                or row["node_depth"] >= p["elevated_depth_min"]):
            assert row["tier"] == "elevated"
        else:
            assert row["tier"] == "routine"


def test_principal_capacity_cap_applied_after_ordering(primary_outputs):
    """The per-principal cap is applied after the queue is ordered, so each
    principal keeps its highest-ranked rows in rank order rather than its first three."""
    _, _, decisions, queue = primary_outputs
    per_principal: dict[str, int] = {}
    for row in queue:
        per_principal[row["principal"]] = per_principal.get(row["principal"], 0) + 1
    assert per_principal
    assert max(per_principal.values()) <= 3, f"principal exceeded cap: {per_principal}"
    admissible = sum(1 for principal_rows in decisions.values() for row in principal_rows
                     if row["permission"] in REVIEWED_PERMISSIONS)
    assert admissible > len(queue), "more admissible decisions than the cap allows"
    seen_order = [row["principal"] for row in queue]
    for principal in per_principal:
        idxs = [i for i, name in enumerate(seen_order) if name == principal]
        assert idxs == sorted(idxs)


# --------------------------------------------------------------------------
# The fixed source paths, determinism, the CLI and the runtime budget
# --------------------------------------------------------------------------
def test_resource_tree_source_path_affects_output(tmp_path: Path):
    """The resource tree is resolved from its fixed path, not inlined."""
    original = RESOURCE_TREE_PATH.read_text(encoding="utf-8")
    try:
        _, summary_a, decisions_a, queue_a = run_pipeline(tmp_path / "a")
        trimmed = [r for r in json.loads(original)
                   if not r["node"].startswith("/prod/payments/")]
        write_json(RESOURCE_TREE_PATH, trimmed)
        _, summary_b, decisions_b, queue_b = run_pipeline(tmp_path / "b")
        assert summary_a["resource_node_count"] > summary_b["resource_node_count"]
        assert summary_a != summary_b
        assert decisions_a != decisions_b
        assert queue_a != queue_b
    finally:
        RESOURCE_TREE_PATH.write_text(original, encoding="utf-8")


def test_role_catalog_source_path_affects_output(tmp_path: Path):
    """The role catalog is resolved from its fixed path, inheritance included."""
    original = ROLE_CATALOG_PATH.read_text(encoding="utf-8")
    try:
        _, summary_a, decisions_a, _ = run_pipeline(tmp_path / "a")
        flattened = [dict(role, inherits=[]) for role in json.loads(original)]
        write_json(ROLE_CATALOG_PATH, flattened)
        _, summary_b, decisions_b, _ = run_pipeline(tmp_path / "b")
        assert summary_a["basis_counts"]["role_inheritance"] > 0
        assert summary_b["basis_counts"]["role_inheritance"] == 0
        assert summary_a != summary_b
        assert decisions_a != decisions_b
    finally:
        ROLE_CATALOG_PATH.write_text(original, encoding="utf-8")


def test_policy_source_path_affects_output(tmp_path: Path):
    """The access policy is resolved from its fixed path and gates admission."""
    original = POLICY_PATH.read_text(encoding="utf-8")
    try:
        data = json.loads(original)
        data["default"]["admission_min"] = 999
        write_json(POLICY_PATH, data)
        _, summary, _, queue = run_pipeline(tmp_path / "shifted")
        assert summary != FIXTURE["primary"]["summary"]
        assert len(queue) < FIXTURE["primary"]["queue_count"]
    finally:
        POLICY_PATH.write_text(original, encoding="utf-8")


def test_pipeline_rerun_idempotent(tmp_path: Path):
    """Two runs over the same binding set produce identical artifacts."""
    _, sa, da, qa = run_pipeline(tmp_path / "a")
    _, sb, db, qb = run_pipeline(tmp_path / "b")
    assert (sa, da, qa) == (sb, db, qb)


def test_cli_defaults_work_and_match_explicit_run(tmp_path: Path):
    """Omitting both options uses the documented defaults."""
    _, explicit_summary, _, _ = run_pipeline(tmp_path)
    # The no-argument run writes to the default /app/output; clear any root-owned
    # artifacts from solve.sh and make the dir candidate-writable first.
    default_out = Path("/app/output")
    shutil.rmtree(default_out, ignore_errors=True)
    default_out.mkdir(parents=True, exist_ok=True)
    os.chmod(default_out, 0o777)
    run_agent([sys.executable, str(WORKFLOW_PATH)], cwd=candidate_dir())
    assert load_json(default_out / "summary.json") == explicit_summary


def test_graded_run_meets_documented_runtime_budget(primary_outputs):
    """The graded run finishes inside the budget instruction.md and the output
    contract both state, not merely inside the harness safety timeout."""
    elapsed = ELAPSED[str(DEFAULT_INPUT)]
    assert elapsed <= RUNTIME_BUDGET_SEC, (
        f"graded run took {elapsed:.1f}s, over the {RUNTIME_BUDGET_SEC}s budget")


def test_runtime_budget_is_stated_in_the_contract():
    """The budget enforced above is the one the output contract publishes."""
    assert int(SPEC["runtime_budget_seconds"]) == int(RUNTIME_BUDGET_SEC)


# --------------------------------------------------------------------------
# The frozen snapshot, the import ban and verifier isolation
# --------------------------------------------------------------------------
def test_original_snapshot_preserved():
    """The rollout's evaluator must still be on disk, unmodified."""
    assert ORIGINAL_WORKFLOW_PATH.exists()
    got = hashlib.sha256(ORIGINAL_WORKFLOW_PATH.read_bytes()).hexdigest()
    assert got == FIXTURE["broken_evaluator_sha256"]


def test_broken_snapshot_is_wrong(tmp_path: Path):
    """The shipped evaluator does not already produce the governed result."""
    _, summary, decisions, queue = run_pipeline(tmp_path, script_path=ORIGINAL_WORKFLOW_PATH)
    assert summary != FIXTURE["primary"]["summary"]
    assert digest(decisions) != FIXTURE["primary"]["decisions_digest"]
    assert digest(queue) != FIXTURE["primary"]["queue_digest"]


def test_evaluator_does_not_import_engines():
    """The evaluator resolves the dialect itself rather than delegating to an engine."""
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
    """The import ban is real: a networkx-importing engine is detected."""
    shim = tmp_path / "delegating_engine.py"
    shim.write_text("import networkx\n\n\ndef run(a, b):\n    return networkx.DiGraph()\n")
    imported = {alias.name.split(".")[0]
                for node in ast.walk(ast.parse(shim.read_text()))
                if isinstance(node, ast.Import) for alias in node.names}
    assert "networkx" in imported


def test_evaluator_does_not_reference_test_artifacts():
    """The evaluator derives its answer rather than reading anything verifier-side."""
    code = WORKFLOW_PATH.read_text(encoding="utf-8")
    for token in ("/tests", "expected_report.json", "alt_expanded_bindings.json"):
        assert token not in code


def test_governance_log_present():
    """The minute book the rules are reconstructed from is in the environment."""
    assert LOG_PATH.exists() and LOG_PATH.stat().st_size > 0


def test_submitted_program_runs_unprivileged_and_cannot_write_reward(tmp_path: Path):
    """Code run the way the verifier runs the agent is unprivileged (uid 65534)
    and cannot write the reward path."""
    os.makedirs("/logs/verifier", exist_ok=True)
    reward = Path("/logs/verifier/reward.txt")
    if not reward.exists():
        reward.write_text("0")
    os.chmod("/logs/verifier", 0o755)
    os.chmod(reward, 0o644)
    probe = candidate_dir() / "probe.py"
    probe.write_text(
        "import os\n"
        "print(os.getuid())\n"
        "open('/logs/verifier/reward.txt', 'w').write('1')\n",
        encoding="utf-8")
    os.chmod(probe, 0o644)
    res = subprocess.run(SETPRIV + [sys.executable, str(probe)],
                         capture_output=True, text=True, cwd=str(CWORK), check=False)
    assert res.stdout.strip().splitlines()[0] == "65534", "must run as uid 65534"
    assert res.returncode != 0 and "Permission denied" in res.stderr, (
        "unprivileged submitted program must not be able to write the reward path")


# --------------------------------------------------------------------------
# Scope exclusions and separation of duties
# --------------------------------------------------------------------------
def _with_registers(tmp_path: Path, label: str, bindings, *, excepts=None, conflicts=None):
    """Run the submitted evaluator over crafted bindings with crafted registers."""
    saved = {p: p.read_text(encoding="utf-8") for p in (EXCLUSIONS_PATH, CONFLICTS_PATH)}
    try:
        write_json(EXCLUSIONS_PATH, excepts if excepts is not None else [])
        write_json(CONFLICTS_PATH, conflicts if conflicts is not None else [])
        _, summary, decisions, queue = run_on_bindings(tmp_path, label, bindings)
        return summary, {(pr, r["node"], r["permission"]): r
                         for pr, rows in decisions.items() for r in rows}
    finally:
        for path, text in saved.items():
            path.write_text(text, encoding="utf-8")


def test_an_exclusion_carves_its_subtree_out_of_the_binding(tmp_path: Path):
    """A carved-out node takes nothing from the binding it is carved from.

    The draft that treated the exclusion list as reviewer guidance would leave the
    /prod/* grant reaching /prod/payments and both its children.
    """
    binding = [{"binding_id": "x-001", "principal": "excl-one",
                "role": "role-operator", "scope": "/prod/*"}]
    plain, _ = _with_registers(tmp_path, "excl_none", binding)
    carved, rows = _with_registers(
        tmp_path, "excl_some", binding,
        excepts=[{"binding_id": "x-001", "except": ["/prod/payments/*"]}])
    assert carved["resolved_decision_count"] < plain["resolved_decision_count"]
    for node in ("/prod/payments", "/prod/payments/ledger", "/prod/payments/settlement"):
        assert not [k for k in rows if k[0] == "excl-one" and k[1] == node], node
    assert [k for k in rows if k[0] == "excl-one" and k[1] == "/prod"]


def test_an_exclusion_blocks_an_exact_denys_propagation(tmp_path: Path):
    """The carve stops a propagated deny at the carved node while its sibling keeps it."""
    binding = [{"binding_id": "x-002", "principal": "excl-two",
                "role": "role-custodian", "scope": "/prod/payments"}]
    _, rows = _with_registers(
        tmp_path, "excl_prop", binding,
        excepts=[{"binding_id": "x-002", "except": ["/prod/payments/ledger"]}])
    reached = {k[1] for k in rows if k[0] == "excl-two"}
    assert "/prod/payments" in reached
    assert "/prod/payments/ledger" not in reached
    assert "/prod/payments/settlement" in reached


def test_an_exclusion_naming_an_unknown_node_carves_nothing(tmp_path: Path):
    """A carve the tree does not carry leaves the binding exactly as it was."""
    binding = [{"binding_id": "x-003", "principal": "excl-three",
                "role": "role-operator", "scope": "/prod/*"}]
    plain, _ = _with_registers(tmp_path, "excl_plain", binding)
    dangling, _ = _with_registers(
        tmp_path, "excl_dangling", binding,
        excepts=[{"binding_id": "x-003", "except": ["/no/such/node/*"]}])
    assert dangling == plain


def test_an_exclusion_does_not_change_scope_specificity(tmp_path: Path):
    """Specificity is measured on the scope as written, not on what survives the carve."""
    binding = [{"binding_id": "x-004", "principal": "excl-four",
                "role": "role-operator", "scope": "/prod/*"}]
    _, plain = _with_registers(tmp_path, "spec_plain", binding)
    _, carved = _with_registers(
        tmp_path, "spec_carved", binding,
        excepts=[{"binding_id": "x-004", "except": ["/prod/payments/*"]}])
    shared = set(plain) & set(carved)
    assert shared
    for key in shared:
        assert plain[key]["scope_specificity"] == carved[key]["scope_specificity"], key


def test_a_duty_conflict_revokes_the_lower_weighted_allow(tmp_path: Path):
    """delete outweighs deploy, so the deploy allow is the one that becomes a deny."""
    bindings = [{"binding_id": "d-001", "principal": "sod-one",
                 "role": "role-breakglass", "scope": "/prod/payments"}]
    _, before = _with_registers(tmp_path, "sod_off", bindings)
    _, after = _with_registers(
        tmp_path, "sod_on", bindings,
        conflicts=[{"conflict_id": "SOD-01", "permissions": ["delete", "deploy"]}])
    node = "/prod/payments"
    if ("sod-one", node, "deploy") in before and ("sod-one", node, "delete") in before:
        if (before[("sod-one", node, "deploy")]["effect"] == "allow"
                and before[("sod-one", node, "delete")]["effect"] == "allow"):
            assert after[("sod-one", node, "deploy")]["effect"] == "deny"
            assert after[("sod-one", node, "deploy")]["decision_basis"] == "duty_conflict"
            assert after[("sod-one", node, "delete")]["effect"] == "allow"
            return
    pytest.skip("the crafted binding does not hold both allows at the probe node")


def test_the_graded_run_exercises_both_new_registers(primary_outputs):
    """Both registers are load-bearing on the graded run, not merely present."""
    _, summary, decisions, _ = primary_outputs
    assert summary["revoked_conflict_count"] > 0
    revoked = [r for rows in decisions.values() for r in rows
               if r["decision_basis"] == "duty_conflict"]
    assert len(revoked) == summary["revoked_conflict_count"]
    assert all(r["effect"] == "deny" for r in revoked)
    assert summary["basis_counts"]["duty_conflict"] == summary["revoked_conflict_count"]
    carved = load_json(EXCLUSIONS_PATH)
    assert carved and any(x.endswith("/*") for r in carved for x in r["except"])


def test_exclusion_register_actually_influences_the_output(tmp_path: Path):
    """The exclusion register is resolved from its fixed path, not inlined."""
    saved = EXCLUSIONS_PATH.read_text(encoding="utf-8")
    try:
        write_json(EXCLUSIONS_PATH, [])
        _, summary, _, _ = run_pipeline(tmp_path)
        assert summary["resolved_decision_count"] > \
            FIXTURE["primary"]["summary"]["resolved_decision_count"]
    finally:
        EXCLUSIONS_PATH.write_text(saved, encoding="utf-8")


def test_duty_conflict_register_actually_influences_the_output(tmp_path: Path):
    """The duty-conflict register is resolved from its fixed path, not inlined."""
    saved = CONFLICTS_PATH.read_text(encoding="utf-8")
    try:
        write_json(CONFLICTS_PATH, [])
        _, summary, _, _ = run_pipeline(tmp_path)
        assert summary["revoked_conflict_count"] == 0
        assert summary["basis_counts"]["duty_conflict"] == 0
        assert summary["allow_decision_count"] > \
            FIXTURE["primary"]["summary"]["allow_decision_count"]
    finally:
        CONFLICTS_PATH.write_text(saved, encoding="utf-8")
