#!/usr/bin/env python3
"""Expand the group-alias role bindings into concrete principal bindings.

Implements the access governance board's final expansion decision (#ACL-4170 in
/app/incident/access_governance_log.md), which supersedes the #ACL-4004 draft and
revises the #ACL-4106 interim: a handle is expanded breadth first by nesting
level and stops after level 3, a group already expanded on the binding is never
expanded again (which terminates a nesting cycle), the collected principals are
deduplicated, an undefined or empty handle yields no binding at all, and the
result is written to /app/data/expanded_bindings.json in source-binding order
with each source binding's principals in ascending order.
"""

from __future__ import annotations

import json
from pathlib import Path

BINDINGS_PATH = Path("/app/data/role_bindings.json")
DIRECTORY_PATH = Path("/app/data/directory_export.json")
EXPANDED_PATH = Path("/app/data/expanded_bindings.json")

ALIAS_PREFIX = "@"
MAX_NESTING_LEVEL = 3
BINDING_FIELDS = ("binding_id", "principal", "role", "scope")


def canon(value: object) -> str:
    return str(value).strip().lower()


def load_groups(directory: dict) -> dict[str, dict]:
    groups: dict[str, dict] = {}
    for group in directory.get("groups", []):
        handle = canon(group.get("handle", ""))
        if handle:
            groups[handle] = group
    return groups


def expand_handle(handle: str, groups: dict[str, dict]) -> list[str]:
    """Breadth-first nesting walk bounded at MAX_NESTING_LEVEL (#ACL-4170)."""
    collected: set[str] = set()
    expanded: set[str] = set()
    frontier = [handle]
    level = 0
    while frontier and level <= MAX_NESTING_LEVEL:
        next_frontier: list[str] = []
        for current in frontier:
            if current in expanded:
                continue
            expanded.add(current)
            group = groups.get(current)
            if group is None:
                continue
            for member in group.get("members", []):
                name = canon(member)
                if name:
                    collected.add(name)
            for nested in group.get("nested_groups", []):
                nested_handle = canon(nested)
                if nested_handle and nested_handle not in expanded:
                    next_frontier.append(nested_handle)
        frontier = next_frontier
        level += 1
    return sorted(collected)


def expand(bindings: list[dict], groups: dict[str, dict]) -> list[dict]:
    expanded: list[dict] = []
    for binding in bindings:
        principal = canon(binding.get("principal", ""))
        base = {
            "binding_id": canon(binding.get("binding_id", "")),
            "role": canon(binding.get("role", "")),
            "scope": canon(binding.get("scope", "")),
        }
        if not principal.startswith(ALIAS_PREFIX):
            expanded.append({**base, "principal": principal})
            continue
        for name in expand_handle(principal, groups):
            expanded.append({**base, "principal": name})
    return [{field: row[field] for field in BINDING_FIELDS} for row in expanded]


def main() -> None:
    bindings = json.loads(BINDINGS_PATH.read_text(encoding="utf-8"))
    directory = json.loads(DIRECTORY_PATH.read_text(encoding="utf-8"))
    rows = expand(bindings, load_groups(directory))
    EXPANDED_PATH.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
