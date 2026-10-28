# Agent Red Team vs Blue Team: Combined Report

- Batch: `20261027-222916`  |  Mode: **DEMO (scripted simulation)**  |  Model: `demo`  |  Targets: 3

| Target | Rounds | Train breach (R1 -> final) | Held-out breach (R1 -> final) | Utility (R1 -> final) | Converged | Final config |
|---|---|---|---|---|---|---|
| ShopCo retail customer-support agent | 3 | 94% -> 0% | 100% -> 0% | 100% -> 100% | yes | v2 |
| FinBank digital banking assistant | 3 | 94% -> 0% | 100% -> 0% | 100% -> 100% | yes | v2 |
| Acme Corp corporate IT/HR helpdesk agent | 3 | 94% -> 0% | 100% -> 0% | 100% -> 100% | yes | v2 |

Per-target reports with attack tables and the hardened configuration are in each target's folder.

## Weaknesses that were still unresolved

- none
