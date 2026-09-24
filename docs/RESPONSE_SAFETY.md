# SentinelAI Response Safety

SentinelAI is a portfolio/research platform. Automated response must be fail-safe.

## Default policy

1. Detection does not automatically imply compromise.
2. Response actions are disabled unless explicitly enabled.
3. Blocking/isolation targets must be allowlisted.
4. Administrative actions require authorization checks.
5. Every response action should generate an audit event.
6. A dry-run/simulation mode should be available before live enforcement.

## Recommended response states

`DETECTED → TRIAGED → APPROVED → EXECUTED → VERIFIED`

For unattended automation, use:

`DETECTED → POLICY_CHECK → DRY_RUN/ALLOWLIST_CHECK → EXECUTE`

and record the decision reason.

## High-impact actions

Process termination, endpoint isolation, firewall changes, account disabling, and IP blocking can disrupt legitimate operations. These actions should require explicit policy gates and safe recovery procedures.
