#!/usr/bin/env python3
"""Control-plane effective-permission evaluator (governance dialect).

Resolves every principal's effective allow/deny decision over the resource
hierarchy from the expanded role bindings, the role catalog, the resource tree
and the access policies, and records the provenance of the winning rule.

Every precedence rule here is the access governance board's own dialect --
scope specificity, role-inheritance distance, downward deny propagation, the
tie-break chain and the provenance vocabulary are reconstructed from
/app/incident/access_governance_log.md together with the operational data;
/app/docs/report_spec.json is the output contract only.

Standard library only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Fixed absolute operational-input paths. --input selects the expanded binding
# set only; the catalog, tree and policy files never become relative to it.
DEFAULT_INPUT = "/app/data/expanded_bindings.json"
DEFAULT_OUTPUT_DIR = "/app/output"
RESOURCE_TREE_PATH = "/app/data/resource_tree.json"
ROLE_CATALOG_PATH = "/app/data/role_catalog.json"
ACCESS_POLICY_PATH = "/app/data/access_policies.json"

SCHEMA_VERSION = "acl-resolve-v1"
TIER_ORDER = ["critical", "elevated", "routine"]
BASIS_ORDER = ["direct_grant", "propagated_deny", "role_inheritance", "scoped_wildcard"]

# --- Governance constants (final decisions; see log entries in comments) ---
EXACT_SPECIFICITY_BONUS = 1   # #ACL-4108: exact = 2*depth+1, wildcard = 2*depth
RISK_SPEC_DIV = 3             # #ACL-4148: scope_specificity // 3, CEIL
RISK_SUPPRESSED_MULT = 2      # #ACL-4148: 2 * suppressed_descendants
ESCALATION_CONTEST_DIV = 2    # #ACL-4118: contest_count // 2, CEIL
PRINCIPAL_CAP = 3             # #ACL-4146: at most 3 queue rows per principal

# Baseline access policy (#ACL-4150). Any field the policy file omits keeps
# these values; the policy file may override per default and per permission.
POLICY_BASELINE = {
    "permission_weight": 4,
    "admission_min": 9,
    "critical_risk_min": 200,
    "critical_escalation_min": 260,
    "critical_suppressed_min": 40,
    "elevated_risk_min": 14,
    "elevated_depth_min": 8,
}
REVIEWED_PERMISSIONS = ("deploy", "delete", "rotate", "export")  # #ACL-4140


def _ceil_div(numer: int, denom: int) -> int:
    """Integer ceil for non-negative numer; ceil(x/n) == -(-x // n)."""
    return -(-numer // denom)


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
def build_tree(rows: list[dict]) -> tuple[list[str], dict[str, list[str]], dict[str, list[str]]]:
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
    children: dict[str, list[str]] = {node: [] for node in nodes}
    for node in nodes:
        par = parent.get(node)
        if par is not None and par in children:
            children[par].append(node)
    return (sorted(nodes),
            {node: sorted(kids) for node, kids in descendants.items()},
            {node: sorted(kids) for node, kids in children.items()})


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
    """(permission, effect, declaring_role, inherit_distance) for one bound role.

    #ACL-4102: breadth-first over `inherits`, distance is the minimum hop count,
    a role already expanded is never expanded again, an undefined role
    contributes nothing. A role's own rules and its inherited rules are all
    retained; nothing is collapsed.
    """
    collected: list[tuple[str, str, str, int]] = []
    expanded: set[str] = set()
    frontier = [role]
    distance = 0
    while frontier:
        next_frontier: list[str] = []
        for current in frontier:
            if current in expanded:
                continue
            expanded.add(current)
            entry = catalog.get(current)
            if entry is None:
                continue
            for permission, effect in entry["rules"]:
                collected.append((permission, effect, current, distance))
            for parent in entry["inherits"]:
                if parent not in expanded:
                    next_frontier.append(parent)
        frontier = next_frontier
        distance += 1
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
    return 2 * path_depth(base) + (0 if wildcard else EXACT_SPECIFICITY_BONUS)


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
            if wildcard:
                targets = [(base, False)] + [(kid, False) for kid in descendants[base]]
            elif effect == "deny":
                # #ACL-4104: an exact deny also applies at every strict
                # descendant, keeping the specificity computed at its own node.
                targets = [(base, False)] + [(kid, True) for kid in descendants[base]]
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


def effective_principal_counts(
    grants: dict[str, set[str]],
    children: dict[str, list[str]],
    roots: list[str],
) -> dict[str, int]:
    """#ACL-4172: distinct principals holding an allow at each node once grants
    inherited from ancestors are counted.

    The walk carries one running tally down the tree, adding a node's own
    principals on the way in and removing them on the way out, so the whole tree
    costs one pass. Recomputing a node's set from every grant is the node count
    times the grant count and cannot meet the runtime budget.
    """
    counts: dict[str, int] = {}
    live: dict[str, int] = {}
    stack: list[tuple[str, bool]] = [(root, False) for root in reversed(roots)]
    while stack:
        node, leaving = stack.pop()
        own = grants.get(node, ())
        if leaving:
            for principal in own:
                if live[principal] == 1:
                    del live[principal]
                else:
                    live[principal] -= 1
            continue
        for principal in own:
            live[principal] = live.get(principal, 0) + 1
        counts[node] = len(live)
        stack.append((node, True))
        for kid in reversed(children.get(node, ())):
            stack.append((kid, False))
    return counts


def precedence_key(rule: dict) -> tuple:
    # #ACL-4110, strictly in sequence: greater specificity, then smaller
    # inherit distance, then deny before allow, then binding_id, then role.
    return (
        -rule["scope_specificity"],
        rule["inherit_distance"],
        0 if rule["effect"] == "deny" else 1,
        rule["binding_id"],
        rule["role"],
    )


def decision_basis(rule: dict, node: str) -> str:
    # #ACL-4112 ordered cascade, first match wins.
    if rule["propagated"]:
        return "propagated_deny"
    if rule["inherit_distance"] > 0:
        return "role_inheritance"
    if not rule["wildcard"] and rule["scope_base"] == node:
        return "direct_grant"
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
    # #ACL-4144
    if (
        decision["risk_score"] >= policy["critical_risk_min"]
        or decision["escalation_index"] >= policy["critical_escalation_min"]
        or decision["suppressed_descendants"] >= policy["critical_suppressed_min"]
    ):
        return "critical"
    if (
        decision["risk_score"] >= policy["elevated_risk_min"]
        or decision["contest_count"] >= 2
        or decision["node_depth"] >= policy["elevated_depth_min"]
    ):
        return "elevated"
    return "routine"


DECISION_FIELDS = (
    "node",
    "node_effective_principals",
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

    tree_nodes, descendants, children = build_tree(tree_rows)
    catalog = build_catalog(catalog_rows)
    table = applicable_rules(bindings, catalog, tree_nodes, descendants)

    # --- winner selection (#ACL-4110) and provenance (#ACL-4112) ---
    roots = [node for node in tree_nodes if node == "/"] or tree_nodes[:1]
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

    # --- cascade measure (#ACL-4116) ---
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

    # --- scoring (#ACL-4148, #ACL-4118) ---
    for decision in winners.values():
        policy = resolve_policy(decision["permission"], policy_data)
        decision["risk_score"] = (
            policy["permission_weight"]
            + decision["contest_count"]
            + _ceil_div(decision["scope_specificity"], RISK_SPEC_DIV)
            + RISK_SUPPRESSED_MULT * decision["suppressed_descendants"]
        )
        decision["escalation_index"] = (
            decision["risk_score"]
            + decision["node_depth"]
            + _ceil_div(decision["contest_count"], ESCALATION_CONTEST_DIV)
        )

    # --- inherited reach per node (#ACL-4172) ---
    allow_grants: dict[str, set[str]] = {}
    for (principal, node, _permission), decision in winners.items():
        if decision["effect"] == "allow":
            allow_grants.setdefault(node, set()).add(principal)
    reach = effective_principal_counts(allow_grants, children, roots)
    for decision in winners.values():
        decision["node_effective_principals"] = reach.get(decision["node"], 0)

    decisions = [winners[key] for key in sorted(winners)]

    # --- admission and tiering (#ACL-4140, #ACL-4144) ---
    queue_rows: list[dict] = []
    for decision in decisions:
        policy = resolve_policy(decision["permission"], policy_data)
        if decision["permission"] not in REVIEWED_PERMISSIONS:
            continue
        if decision["risk_score"] < policy["admission_min"]:
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
    # #ACL-4146: per-principal cap applied as a final pass over the full order.
    seen: dict[str, int] = {}
    capped: list[dict] = []
    for row in queue_rows:
        used = seen.get(row["principal"], 0)
        if used < PRINCIPAL_CAP:
            capped.append(row)
            seen[row["principal"]] = used + 1
    queue_rows = capped

    # --- summary aggregates (#ACL-4154) ---
    basis_counts = {basis: 0 for basis in BASIS_ORDER}
    for decision in decisions:
        basis_counts[decision["decision_basis"]] += 1
    tier_counts = {tier: 0 for tier in TIER_ORDER}
    for row in queue_rows:
        tier_counts[row["tier"]] += 1

    def qmax(field: str) -> int:
        return max((r[field] for r in queue_rows), default=0)

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
        "max_effective_principals": max((d["node_effective_principals"] for d in winners.values()), default=0),
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
