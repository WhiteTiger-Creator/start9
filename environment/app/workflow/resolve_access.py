#!/usr/bin/env python3
"""Control-plane effective-permission evaluator (INCIDENT SNAPSHOT - DO NOT SHIP).

This is the evaluator as it stood when the access review stalled. It still
resolves several stages against the February draft proposals and the March
interim decisions that the access governance board later reversed, so the
decisions and the exception queue it produces are wrong. Restore it to the
board's final decisions recorded in /app/incident/access_governance_log.md.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_INPUT = "/app/data/expanded_bindings.json"
DEFAULT_OUTPUT_DIR = "/app/output"
RESOURCE_TREE_PATH = "/app/data/resource_tree.json"
ROLE_CATALOG_PATH = "/app/data/role_catalog.json"
ACCESS_POLICY_PATH = "/app/data/access_policies.json"

SCHEMA_VERSION = "acl-resolve-v1"
TIER_ORDER = ["critical", "elevated", "routine"]
BASIS_ORDER = ["direct_grant", "propagated_deny", "role_inheritance", "scoped_wildcard"]

# Draft/interim constants (pre-reversal).
EXACT_SPECIFICITY_FLOOR = 1000   # #ACL-4010 draft: exact always beats wildcard
DRAFT_CRITICAL_RISK = 18         # #ACL-4044 draft tier threshold
DRAFT_ELEVATED_RISK = 9          # #ACL-4044 draft tier threshold
DRAFT_ADMISSION_MIN = 5          # #ACL-4040 draft admission floor
PRINCIPAL_CAP = 3

# Baseline access policy (#ACL-4150). Any field the policy file omits keeps
# these values; the policy file may override per default and per permission.
POLICY_BASELINE = {
    "permission_weight": 4,
    "admission_min": 9,
    "critical_risk_min": 22,
    "critical_escalation_min": 30,
    "critical_suppressed_min": 3,
    "elevated_risk_min": 14,
    "elevated_depth_min": 3,
}


def canon(value: object) -> str:
    return str(value).strip().lower()


def coerce_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return 0


def canon_path(value: object) -> str:
    """#ACL-4101 path normalization: collapse repeated separators, drop a
    trailing separator, an empty path is the root."""
    segments = [seg for seg in canon(value).split("/") if seg]
    return "/" + "/".join(segments) if segments else "/"


def canon_effect(value: object) -> str:
    """#ACL-4101: 'deny' is the only deny spelling; anything else is allow."""
    return "deny" if canon(value) == "deny" else "allow"


def path_depth(path: str) -> int:
    return 0 if path == "/" else path.count("/")


# --------------------------------------------------------------------------
# Resource tree (#ACL-4101, #ACL-4104)
# --------------------------------------------------------------------------
def build_tree(rows: list[dict]) -> tuple[list[str], dict[str, list[str]]]:
    nodes: list[str] = []
    seen: set[str] = set()
    parent: dict[str, str | None] = {}
    for row in rows:
        node = canon_path(row.get("node", ""))
        if node in seen:
            continue
        seen.add(node)
        nodes.append(node)
        raw_parent = row.get("parent")
        parent[node] = None if raw_parent is None else canon_path(raw_parent)
    descendants: dict[str, list[str]] = {node: [] for node in nodes}
    for node in nodes:
        cursor = parent.get(node)
        guard = 0
        while cursor is not None and cursor in descendants and guard <= len(nodes):
            descendants[cursor].append(node)
            cursor = parent.get(cursor)
            guard += 1
    return sorted(nodes), {node: sorted(kids) for node, kids in descendants.items()}


# --------------------------------------------------------------------------
# Role catalog: breadth-first inheritance, minimum distance (#ACL-4102)
# --------------------------------------------------------------------------
def build_catalog(rows: list[dict]) -> dict[str, dict]:
    catalog: dict[str, dict] = {}
    for row in rows:
        name = canon(row.get("role", ""))
        if not name:
            continue
        catalog[name] = {
            "inherits": [canon(p) for p in row.get("inherits", []) if canon(p)],
            "rules": [
                (canon(rule.get("permission", "")), canon_effect(rule.get("effect", "allow")))
                for rule in row.get("rules", [])
                if canon(rule.get("permission", ""))
            ],
        }
    return catalog


def role_rules(role: str, catalog: dict[str, dict]) -> list[tuple[str, str, str, int]]:
    """#ACL-4109 draft: depth-first walk, distance is the first-found depth."""
    collected: list[tuple[str, str, str, int]] = []
    expanded: set[str] = set()

    def walk(current: str, distance: int) -> None:
        if current in expanded:
            return
        expanded.add(current)
        entry = catalog.get(current)
        if entry is None:
            return
        for permission, effect in entry["rules"]:
            collected.append((permission, effect, current, distance))
        for parent in entry["inherits"]:
            walk(parent, distance + 1)

    walk(role, 0)
    return collected


# --------------------------------------------------------------------------
# Scope semantics and specificity (#ACL-4108)
# --------------------------------------------------------------------------
def parse_scope(scope: str) -> tuple[str, bool]:
    text = canon(scope)
    if text.endswith("/*"):
        return canon_path(text[:-2]), True
    if text == "*":
        return "/", True
    return canon_path(text), False


def scope_specificity(base: str, wildcard: bool) -> int:
    # #ACL-4010 draft: any exact scope outranks any wildcard scope.
    return path_depth(base) + (0 if wildcard else EXACT_SPECIFICITY_FLOOR)


# --------------------------------------------------------------------------
# Applicable-rule expansion (#ACL-4104, #ACL-4108)
# --------------------------------------------------------------------------
def applicable_rules(
    bindings: list[dict],
    catalog: dict[str, dict],
    tree_nodes: list[str],
    descendants: dict[str, list[str]],
) -> dict[tuple[str, str, str], list[dict]]:
    node_set = set(tree_nodes)
    table: dict[tuple[str, str, str], list[dict]] = {}
    for binding in bindings:
        principal = canon(binding.get("principal", ""))
        role = canon(binding.get("role", ""))
        binding_id = canon(binding.get("binding_id", ""))
        base, wildcard = parse_scope(binding.get("scope", ""))
        if not principal or base not in node_set or role not in catalog:
            continue
        specificity = scope_specificity(base, wildcard)
        for permission, effect, declaring_role, distance in role_rules(role, catalog):
            # #ACL-4020 draft: an exact scope never reaches a descendant node.
            if wildcard:
                targets = [(base, False)] + [(kid, False) for kid in descendants[base]]
            else:
                targets = [(base, False)]
            for node, propagated in targets:
                table.setdefault((principal, node, permission), []).append(
                    {
                        "binding_id": binding_id,
                        "role": role,
                        "declaring_role": declaring_role,
                        "permission": permission,
                        "effect": effect,
                        "scope": canon(binding.get("scope", "")),
                        "scope_base": base,
                        "wildcard": wildcard,
                        "scope_specificity": specificity,
                        "inherit_distance": distance,
                        "propagated": propagated,
                    }
                )
    return table


def precedence_key(rule: dict) -> tuple:
    # #ACL-4006 draft: a deny outranks an allow whatever the scope specificity,
    # and #ACL-4008 draft: an inherited deny cannot be overridden by a child.
    return (
        0 if rule["effect"] == "deny" else 1,
        -rule["scope_specificity"],
        rule["inherit_distance"],
        rule["binding_id"],
        rule["role"],
    )


def decision_basis(rule: dict, node: str) -> str:
    # #ACL-4124 interim: an exact winning scope is a direct grant even when the
    # rule arrived through an inherited role.
    if not rule["wildcard"] and rule["scope_base"] == node:
        return "direct_grant"
    if rule["propagated"]:
        return "propagated_deny"
    if rule["inherit_distance"] > 0:
        return "role_inheritance"
    return "scoped_wildcard"


def rule_identity(rule: dict) -> tuple:
    return (rule["binding_id"], rule["role"], rule["permission"], rule["scope"])


# --------------------------------------------------------------------------
# Policy resolution (#ACL-4150, #ACL-4152)
# --------------------------------------------------------------------------
def resolve_policy(permission: str, policy_data: dict) -> dict:
    resolved = dict(POLICY_BASELINE)
    for field, value in policy_data.get("default", {}).items():
        if field in resolved:
            resolved[field] = coerce_int(value)
    override = policy_data.get("permission_overrides", {}).get(permission)
    if isinstance(override, dict):
        for field, value in override.items():
            if field in resolved:
                resolved[field] = coerce_int(value)
    return resolved


def assign_tier(decision: dict, policy: dict) -> str:
    # #ACL-4044 draft thresholds.
    if decision["risk_score"] >= DRAFT_CRITICAL_RISK:
        return "critical"
    if decision["risk_score"] >= DRAFT_ELEVATED_RISK:
        return "elevated"
    return "routine"


DECISION_FIELDS = (
    "node",
    "node_depth",
    "permission",
    "effect",
    "decision_basis",
    "source_binding_id",
    "source_role",
    "source_scope",
    "inherit_distance",
    "scope_specificity",
    "contest_count",
    "contested_effects",
    "suppressed_descendants",
    "risk_score",
    "escalation_index",
)
QUEUE_FIELDS = ("decision_id", "principal", *DECISION_FIELDS, "tier")


def run(input_path: str, output_dir: str) -> None:
    bindings = json.loads(Path(input_path).read_text(encoding="utf-8"))
    tree_rows = json.loads(Path(RESOURCE_TREE_PATH).read_text(encoding="utf-8"))
    catalog_rows = json.loads(Path(ROLE_CATALOG_PATH).read_text(encoding="utf-8"))
    policy_data = json.loads(Path(ACCESS_POLICY_PATH).read_text(encoding="utf-8"))

    tree_nodes, descendants = build_tree(tree_rows)
    catalog = build_catalog(catalog_rows)
    table = applicable_rules(bindings, catalog, tree_nodes, descendants)

    # --- winner selection and provenance ---
    winners: dict[tuple[str, str, str], dict] = {}
    for key in sorted(table):
        rules = sorted(table[key], key=precedence_key)
        winner = rules[0]
        losers = rules[1:]
        principal, node, permission = key
        winners[key] = {
            "principal": principal,
            "node": node,
            "node_depth": path_depth(node),
            "permission": permission,
            "effect": winner["effect"],
            "decision_basis": decision_basis(winner, node),
            "source_binding_id": winner["binding_id"],
            "source_role": winner["role"],
            "source_scope": winner["scope"],
            "inherit_distance": winner["inherit_distance"],
            "scope_specificity": winner["scope_specificity"],
            "contest_count": len(losers),
            "contested_effects": sorted({r["effect"] for r in losers}),
            "identity": rule_identity(winner),
        }

    # --- cascade measure ---
    for key, decision in winners.items():
        principal, node, permission = key
        count = 0
        for child in descendants.get(node, []):
            other = winners.get((principal, child, permission))
            if (
                other is not None
                and other["identity"] == decision["identity"]
                and other["decision_basis"] == "propagated_deny"
            ):
                count += 1
        decision["suppressed_descendants"] = count

    # --- scoring: #ACL-4012 and #ACL-4018 drafts ---
    for decision in winners.values():
        policy = resolve_policy(decision["permission"], policy_data)
        decision["risk_score"] = policy["permission_weight"] + decision["contest_count"]
        decision["escalation_index"] = (
            decision["risk_score"] + decision["scope_specificity"]
        )

    decisions = [winners[key] for key in sorted(winners)]

    # --- admission: #ACL-4040 draft, every permission is reviewable ---
    queue_rows: list[dict] = []
    for decision in decisions:
        policy = resolve_policy(decision["permission"], policy_data)
        if decision["risk_score"] < DRAFT_ADMISSION_MIN:
            continue
        row = dict(decision)
        row["tier"] = assign_tier(decision, policy)
        row["decision_id"] = (
            f"{decision['principal']}:{decision['node']}:{decision['permission']}"
        )
        queue_rows.append(row)

    tier_rank = {name: len(TIER_ORDER) - index for index, name in enumerate(TIER_ORDER)}
    queue_rows.sort(
        key=lambda r: (
            -tier_rank[r["tier"]],
            -r["risk_score"],
            -r["escalation_index"],
            -r["suppressed_descendants"],
            -r["contest_count"],
            -r["scope_specificity"],
            r["principal"],
            r["node"],
            r["permission"],
        )
    )
    seen: dict[str, int] = {}
    capped: list[dict] = []
    for row in queue_rows:
        used = seen.get(row["principal"], 0)
        if used < PRINCIPAL_CAP:
            capped.append(row)
            seen[row["principal"]] = used + 1
    queue_rows = capped

    # --- summary aggregates: #ACL-4048 interim ---
    basis_counts = {basis: 0 for basis in BASIS_ORDER}
    for decision in decisions:
        basis_counts[decision["decision_basis"]] += 1
    tier_counts = {tier: 0 for tier in TIER_ORDER}
    for row in queue_rows:
        tier_counts[row["tier"]] += 1

    def qmax(field: str) -> int:
        return max((d[field] for d in decisions), default=0)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "expanded_binding_count": len(bindings),
        "principal_count": len({d["principal"] for d in decisions}),
        "resource_node_count": len(tree_nodes),
        "role_count": len(catalog),
        "resolved_decision_count": len(decisions),
        "allow_decision_count": sum(1 for d in decisions if d["effect"] == "allow"),
        "deny_decision_count": sum(1 for d in decisions if d["effect"] == "deny"),
        "contested_decision_count": sum(1 for d in decisions if d["contest_count"] > 0),
        "basis_counts": basis_counts,
        "tier_counts": tier_counts,
        "total_risk_score": sum(d["risk_score"] for d in decisions),
        "total_escalation_index": sum(d["escalation_index"] for d in decisions),
        "total_suppressed_descendants": sum(d["suppressed_descendants"] for d in decisions),
        "queued_decision_count": len(queue_rows),
        "max_risk_score": qmax("risk_score"),
        "max_escalation_index": qmax("escalation_index"),
        "max_contest_count": qmax("contest_count"),
        "max_suppressed_descendants": max(
            (d["suppressed_descendants"] for d in decisions), default=0
        ),
    }

    by_principal: dict[str, list[dict]] = {}
    for decision in decisions:
        by_principal.setdefault(decision["principal"], []).append(decision)
    out_decisions: dict[str, list[dict]] = {}
    for principal in sorted(by_principal):
        rows = sorted(by_principal[principal], key=lambda d: (d["node"], d["permission"]))
        out_decisions[principal] = [
            {field: row[field] for field in DECISION_FIELDS} for row in rows
        ]

    out_queue = [{field: row[field] for field in QUEUE_FIELDS} for row in queue_rows]

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (out / "principal_decisions.json").write_text(
        json.dumps(out_decisions, indent=2) + "\n", encoding="utf-8"
    )
    with (out / "exception_queue.jsonl").open("w", encoding="utf-8") as handle:
        for row in out_queue:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Control-plane effective-permission evaluator"
    )
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    run(args.input, args.output_dir)


if __name__ == "__main__":
    main()
