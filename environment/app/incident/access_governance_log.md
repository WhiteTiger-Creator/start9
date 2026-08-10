# Control-Plane Access Governance — Review Log
Access governance archive for the stalled effective-permission review (2026-Q1 through 2026-Q2).

## Executive Summary
How the effective-permission evaluator is *meant* to behave — the expansion of group-alias role bindings into concrete principals, canonicalization, role-inheritance distance, scope matching and specificity, the downward propagation of node-level denies, the precedence chain that resolves an allow against a deny, the provenance vocabulary recorded for the winning rule, the contest and cascade bookkeeping, scoring, queue admission, tiering, ordering and the reviewer capacity cap — was settled incrementally by the access governance board, and those decisions live in the review entries below rather than in any single summary. Several stages deliberately depart from the deny-overrides behaviour most access-control engines default to: specificity and inheritance distance are both compared before effect, and an exact deny cascades down the resource tree while an exact allow does not. The February draft proposals were revisited during the 2026-05 governance review and several were reversed, and the binding expansion itself was settled only in the 2026-06 review; where a draft or an interim conflicts with a later decision, the later dated decision governs. `/app/docs/report_spec.json` is the output contract only.

## Governance Review Archive
Routine entries are context only. #ACL-ticketed proposal and decision quotes are the authoritative record for evaluator behaviour.

### Review entry 2100 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2100. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2101 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2101. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2102 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2102. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
> **Draft proposal (2026-02-06 - #ACL-4004)** Anders: group-alias expansion: a binding addressed to a group handle takes that group's DIRECT members only, a nested group handle simply stays on the binding as a principal of its own, and a handle the directory leaves without members is retained as an inert binding still carrying the handle *(Superseded — reversed in the 2026-06 governance review.)*
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2103 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2103. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2104 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2104. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2105 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2105. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2106 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2106. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
> **Draft proposal (2026-02-07 - #ACL-4006)** Anders: conflict resolution is deny-overrides: wherever an allow and a deny both apply to a principal at a node, the deny wins regardless of how the two are scoped *(Superseded — reversed in the 2026-05 governance review.)*
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2107 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2107. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2108 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2108. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2109 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2109. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
> **Draft proposal (2026-02-08 - #ACL-4008)** Rosa: a deny a role inherits from a parent role is immutable — a child role cannot grant a permission one of its ancestors denies *(Superseded — reversed in the 2026-05 governance review.)*
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2110 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2110. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2111 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2111. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2112 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2112. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2113 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2113. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2114 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2114. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
> **Draft proposal (2026-02-09 - #ACL-4010)** Rosa: scope specificity: any exact-node scope is more specific than any wildcard scope, whatever depths the two sit at *(Superseded — reversed in the 2026-05 governance review.)*
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2115 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2115. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2116 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2116. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2117 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2117. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2118 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2118. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
> **Draft proposal (2026-02-10 - #ACL-4012)** Anders: risk_score = permission_weight + contest_count, with no specificity term and no cascade term *(Superseded — reversed in the 2026-05 governance review.)*
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2119 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2119. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2120 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2120. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2121 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2121. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
> **Draft proposal (2026-02-11 - #ACL-4018)** Anders: escalation_index = risk_score + scope_specificity *(Superseded — reversed in the 2026-05 governance review.)*
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2122 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2122. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2123 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2123. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2124 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2124. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2125 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2125. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
> **Draft proposal (2026-02-12 - #ACL-4020)** Rosa: propagation: a rule reaches exactly the nodes its scope names — an exact scope never reaches a descendant node, whatever its effect *(Superseded — reversed in the 2026-05 governance review.)*
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2126 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2126. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2127 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2127. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2128 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2128. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
> **Draft proposal (2026-02-13 - #ACL-4040)** Rosa: admit any decision whose risk_score is at least 5, whatever the permission *(Superseded — reversed in the 2026-05 governance review.)*
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2129 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2129. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2130 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2130. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2131 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2131. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2132 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2132. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
> **Draft proposal (2026-02-14 - #ACL-4044)** Anders: tiers: critical when risk_score>=18; elevated when risk_score>=9; else routine *(Superseded — reversed in the 2026-05 governance review.)*
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2133 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2133. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2134 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2134. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2135 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2135. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
> **Governance decision (2026-03-05 - #ACL-4106)** Priya: group-alias expansion interim: expand a handle by full transitive closure over nested_groups with no depth bound at all, and bind a principal once per nesting path that reaches them rather than once per binding *(Revised — see the 2026-06 governance review.)*
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2136 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2136. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2137 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2137. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2138 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2138. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2139 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2139. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2140 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2140. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
> **Governance decision (2026-03-06 - #ACL-4109)** Priya: role-inheritance distance is the depth at which a depth-first walk over `inherits` first reaches the declaring role *(Revised — see the 2026-05 governance review.)*
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2141 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2141. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2142 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2142. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2143 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2143. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
> **Governance decision (2026-03-06 - #ACL-4115)** Priya: scoring interim: risk_score = permission_weight + contest_count + (scope_specificity // 3) + suppressed_descendants and escalation_index = risk_score + node_depth + (contest_count // 2), every division FLOOR *(Revised — see the 2026-05 governance review.)*
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2144 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2144. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2145 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2145. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2146 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2146. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2147 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2147. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
> **Governance decision (2026-03-07 - #ACL-4124)** Priya: decision_basis: a winning rule whose scope names the decision node exactly is a direct_grant even when that rule arrived through an inherited role *(Revised — see the 2026-05 governance review.)*
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2148 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2148. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2149 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2149. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2150 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2150. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
> **Governance decision (2026-03-08 - #ACL-4048)** Yusuf: the max_* summary fields are maxima over EVERY resolved decision, queued or not *(Revised — see the 2026-05 governance review.)*
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2151 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2151. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2152 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2152. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2153 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2153. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2154 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2154. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2155 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2155. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
> **Governance decision (2026-05-02 - #ACL-4101)** Yusuf: canonicalization: binding_id, principal, role and permission are canonicalized with str(...).strip().lower(); a resource path is lowercased, its empty segments dropped and it is rendered as '/' + '/'.join(segments), the empty result rendering as '/'; an effect is `deny` when str(effect).strip().lower() equals `deny` and `allow` in every other case; a binding whose scope base is not a node of the resource tree, or whose role the catalog does not define, contributes nothing at all
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2156 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2156. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2157 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2157. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2158 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2158. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
> **Governance decision (2026-05-03 - #ACL-4102)** Yusuf: role rule resolution, final: from the bound role walk `inherits` BREADTH FIRST, so a role's inherit_distance is the MINIMUM number of hops that reaches it, and a role already expanded on this walk is never expanded again. A role the catalog does not define contributes nothing. Every (permission, effect) pair a reached role declares becomes an applicable rule carrying that distance; a role's own rules and the rules it inherits are all retained and nothing is collapsed. This supersedes #ACL-4109, whose depth-first walk fixes a role at the first depth it happens to reach and therefore reports a larger distance for any role reachable by two inheritance paths
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2159 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2159. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2160 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2160. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2161 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2161. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2162 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2162. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
> **Governance decision (2026-05-03 - #ACL-4108)** Lena: scope semantics and specificity, final: a scope written `X/*` matches node X and every descendant of X; a scope written without the wildcard suffix matches only the node it names. scope_specificity is 2*depth+1 for an exact scope and 2*depth for a wildcard scope, where depth('/') is 0 and each further path segment adds one. This supersedes #ACL-4010: a wildcard rooted deeper than an exact scope now outranks it, so a wildcard at depth 2 scores 4 and beats an exact scope at depth 1 scoring 3
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2163 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2163. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2164 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2164. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2165 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2165. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2166 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2166. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
> **Governance decision (2026-05-04 - #ACL-4104)** Lena: downward propagation, final: a rule whose effect is deny and whose scope names a node EXACTLY also applies at every strict descendant of that node, carrying the scope_specificity computed at its own node and its inherit_distance unchanged. An exact allow never reaches a descendant. This supersedes #ACL-4020 and it is what lets a node-level deny block the allows a wildcard rooted above it would otherwise grant across the whole subtree; because the effect cascades, a mistake near the root of the tree changes every leaf under it
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2167 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2167. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2168 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2168. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2169 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2169. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2170 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2170. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
> **Governance decision (2026-05-05 - #ACL-4110)** Marek: precedence, final, strictly in sequence: (1) the greater scope_specificity wins; (2) then the smaller inherit_distance wins; (3) then deny beats allow; (4) then the lexicographically smaller binding_id; (5) then the lexicographically smaller role. Because specificity is compared BEFORE effect this supersedes the deny-overrides draft #ACL-4006 — a more specific allow does beat a broader deny — and because inherit_distance is also compared before effect it supersedes #ACL-4008 — a rule a role declares itself outranks one it inherits whichever way each of them points, so a child role does override a deny it inherits
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2171 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2171. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2172 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2172. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2173 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2173. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2174 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2174. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
> **Governance decision (2026-05-05 - #ACL-4112)** Lena: decision_basis, final: an ordered cascade over the WINNING rule, first match wins — propagated_deny when the winner is a deny whose exact scope names a strict ancestor of the decision node; otherwise role_inheritance when the winner's inherit_distance is greater than zero; otherwise direct_grant when the winner's scope names the decision node exactly; otherwise scoped_wildcard. This supersedes #ACL-4124, under which an exact scope reported direct_grant even for an inherited rule
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2175 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2175. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2176 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2176. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2177 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2177. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2178 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2178. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
> **Governance decision (2026-05-06 - #ACL-4114)** Marek: decision domain: a decision is emitted for every (principal, resource node, permission) triple at which at least one rule applies once scopes have been matched and #ACL-4104 propagation has been carried out. A triple with no applicable rule is not emitted and no decision is invented for a principal that holds no binding
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2179 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2179. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2180 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2180. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2181 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2181. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2182 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2182. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
> **Governance decision (2026-05-06 - #ACL-4116)** Yusuf: contest bookkeeping, final: contest_count is the number of applicable rules at the triple other than the winner; contested_effects is the ascending list of the distinct effects those losing rules carry. suppressed_descendants counts the strict descendants of the decision node at which the SAME winning rule — the same binding_id, role, permission and scope — also wins for that principal and permission with basis propagated_deny
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2183 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2183. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2184 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2184. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2185 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2185. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2186 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2186. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
> **Governance decision (2026-05-08 - #ACL-4118)** Priya: escalation_index, final: escalation_index = risk_score + node_depth + ceil(contest_count / 2). This supersedes the #ACL-4018 draft and the floor in the #ACL-4115 interim. ROUNDING: contest_count // 2 = CEIL
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2187 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2187. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2188 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2188. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2189 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2189. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2190 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2190. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
> **Governance decision (2026-05-09 - #ACL-4140)** Marek: exception-queue admission, final: the reviewed permissions are exactly {deploy, delete, rotate, export} and `read` is never admitted whatever the access policy file happens to say about it. A decision is admitted iff its permission is reviewed AND its risk_score is at least the resolved admission_min for that permission (inclusive: equal to the floor admits). This supersedes #ACL-4040
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2191 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2191. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2192 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2192. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2193 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2193. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2194 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2194. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
> **Governance decision (2026-05-10 - #ACL-4145)** Yusuf: final queue ordering, strictly in sequence: tier rank critical > elevated > routine; then risk_score desc; then escalation_index desc; then suppressed_descendants desc; then contest_count desc; then scope_specificity desc; then principal asc; then node asc; then permission asc
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2195 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2195. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2196 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2196. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2197 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2197. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2198 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2198. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
> **Governance decision (2026-05-10 - #ACL-4154)** Yusuf: summary aggregation domains, final, revising #ACL-4048: max_risk_score, max_escalation_index and max_contest_count are maxima over the FINAL admitted exception_queue rows only, using 0 when the queue is empty. Only max_suppressed_descendants is taken over EVERY resolved decision, using 0 when there are none. The total_* fields sum over every resolved decision; basis_counts counts every resolved decision while tier_counts counts only the surviving queue rows. expanded_binding_count is the number of records read from the binding set the run was pointed at; principal_count counts the distinct principals holding at least one resolved decision; resource_node_count and role_count count the distinct nodes of the resource tree and the distinct roles of the catalog
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2199 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2199. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2200 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2200. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2201 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2201. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2202 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2202. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
> **Governance decision (2026-05-16 - #ACL-4144)** Marek: tier assignment (the thresholds are resolved policy values): a decision is critical iff risk_score >= critical_risk_min OR escalation_index >= critical_escalation_min OR suppressed_descendants >= critical_suppressed_min. Otherwise, evaluated only when critical does not hold, elevated iff risk_score >= elevated_risk_min OR contest_count >= 2 OR node_depth >= elevated_depth_min. Otherwise routine. This supersedes #ACL-4044
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2203 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2203. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2204 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2204. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2205 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2205. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2206 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2206. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
> **Governance decision (2026-05-18 - #ACL-4150)** Priya: access policy baseline (read from /app/data/access_policies.json at that fixed absolute path; --input never relocates it). Any field the policy file omits keeps its baseline: permission_weight = 4; admission_min = 9; critical_risk_min = 22; critical_escalation_min = 30; critical_suppressed_min = 3; elevated_risk_min = 14; elevated_depth_min = 3
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2207 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2207. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2208 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2208. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2209 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2209. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2210 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2210. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
> **Governance decision (2026-05-18 - #ACL-4152)** Priya: policy resolution, per permission, in three layers: start from the #ACL-4150 baseline; overlay every field the policy file's `default` object supplies (it need not be complete — an omitted field keeps its baseline); then overlay every field that permission's entry in `permission_overrides` supplies (an override names only the fields it changes and inherits the rest). Coerce every policy value to int
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2211 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2211. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2212 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2212. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2213 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2213. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2214 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2214. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
> **Governance decision (2026-05-24 - #ACL-4146)** Marek: reviewer capacity cap: at most THREE queue rows per principal. The cap is a FINAL pass over the fully ordered queue, not applied during admission and not per principal before ordering: admit and order every decision under #ACL-4145, then walk the ordered queue from the top keeping the first three rows of each principal and discarding the rest. Which rows survive depends on the global order, so a decision ranked fourth within its principal is dropped even when it outranks a retained row belonging to another principal. Discarded rows contribute to no queue-derived summary field
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2215 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2215. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2216 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2216. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2217 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2217. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2218 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2218. A tabletop exercise replayed a revoked-role scenario in this scope; the rehearsal did not alter any approved parameter.
> **Governance decision (2026-05-28 - #ACL-4148)** Yusuf: risk_score, final, revising the #ACL-4012 draft and the floors of the #ACL-4115 interim: risk_score = permission_weight + contest_count + ceil(scope_specificity / 3) + 2 * suppressed_descendants, where permission_weight is the resolved policy value for the decision's permission. In integer arithmetic ceil(x/n) is -(-x // n). ROUNDING: scope_specificity // 3 = CEIL
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2219 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2219. Log retention for this scope was extended by one cycle at the auditors' request; no evaluator parameter changed.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2220 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2220. Quarterly recertification swept the group memberships in this scope; no binding was added or removed outside the governance process.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2221 — ledger (prod) scope
Access review lead logged a routine observation for ledger (prod) during recertification round 2221. A directory sync replayed nested-group membership for this scope; the export checksum matched and no evaluator behaviour changed.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2222 — settlement (prod) scope
Access review lead logged a routine observation for settlement (prod) during recertification round 2222. Break-glass usage in this scope was reviewed against the on-call roster; every activation had a matching ticket.
> **Governance decision (2026-06-02 - #ACL-4170)** Lena: group-alias expansion, final — this supersedes the #ACL-4004 draft and revises the #ACL-4106 interim, and it runs BEFORE any resolution. `/app/data/role_bindings.json` addresses most of its bindings to group handles rather than to principals, and `/app/data/expanded_bindings.json` still holds the previous cycle's shallow expansion, so that file is no longer authoritative and must be rebuilt from the bindings file and `/app/data/directory_export.json`. Walk the bindings in file order. A binding whose principal does not begin with `@` names a concrete principal and is copied through unchanged, keeping its position. A binding whose principal begins with `@` is expanded: the handle itself is level 0, the groups its `nested_groups` names are level 1, the groups those name are level 2 and so on, and the walk proceeds BREADTH FIRST one level at a time and stops after level 3 — a group first reached at level 4 or deeper contributes nothing, which revises the unbounded closure of #ACL-4106. Every group the walk expands contributes its own `members`. Because the walk is breadth first a group reachable by two nesting paths is expanded at its SHALLOWEST level and its own nested groups are measured from there; a depth-first walk that fixes a group at the first level it happens to reach loses members and is wrong. A group already expanded on this binding is never expanded again, and that is what terminates a nested-group cycle. The collected principals are DEDUPLICATED, so a principal reachable through two handles on one binding is bound exactly ONCE, revising #ACL-4106. A handle the directory does not define, and a handle whose collected principal set comes out EMPTY, produce NO binding at all rather than an inert one still carrying the handle, superseding #ACL-4004. Each surviving expanded record keeps its source binding's binding_id, role and scope and carries exactly one concrete principal, and its fields are exactly binding_id, principal, role and scope. The principals of one source binding are emitted in ASCENDING principal order and the source bindings stay in file order. Write the result to `/app/data/expanded_bindings.json` as a JSON array in exactly that order; nothing downstream re-orders it and the #ACL-4110 binding_id tie-break reads it as written, so a binding set expanded any other way yields a wrong decision set
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2223 — reporting (corp) scope
Access review lead logged a routine observation for reporting (corp) during recertification round 2223. The joiner-mover-leaver feed for this scope was reconciled against payroll; two stale handles were closed at source.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.

### Review entry 2224 — sandbox (stage) scope
Access review lead logged a routine observation for sandbox (stage) during recertification round 2224. An access dashboard tile for this scope lagged during a catalog refresh; attributed to cache staleness, not the evaluator.
Reviewers should reconcile behaviour questions against #ACL governance decisions rather than chat excerpts.

### Review entry 2225 — staging-payments (stage) scope
Access review lead logged a routine observation for staging-payments (stage) during recertification round 2225. Service-account key rotation ran in this scope on schedule; no permission decision was affected.
Thread archived; see the #ACL decision entries for anything affecting evaluator behaviour.

### Review entry 2226 — payments (prod) scope
Access review lead logged a routine observation for payments (prod) during recertification round 2226. A vendor ticket about duplicated group handles in this scope was closed; the duplicates were display names only.
No evaluator semantics changed in this entry; parameters remain as approved by the governance board.

### Review entry 2227 — identity (prod) scope
Access review lead logged a routine observation for identity (prod) during recertification round 2227. Change-board reviewed stale exception approvals touching this scope; owners were pinged before the next recertification round.
Spreadsheet exports of this review remain archived and non-authoritative for the JSON evaluator acceptance.
