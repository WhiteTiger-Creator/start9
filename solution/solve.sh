#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Step 1: expand the group-alias role bindings (#ACL-4170) ---------------
# /app/data/role_bindings.json addresses most bindings to group handles and
# /app/data/expanded_bindings.json still holds the previous cycle's shallow
# expansion. Rebuild it from the bindings and the directory export; nothing the
# evaluator resolves is correct until this is done.

python3 "${SCRIPT_DIR}/expand_aliases.py"

# --- Step 2: restore the evaluator and resolve effective permissions --------

cp "${SCRIPT_DIR}/resolve_access_fixed.py" /app/workflow/resolve_access.py
python3 /app/workflow/resolve_access.py --output-dir /app/output
