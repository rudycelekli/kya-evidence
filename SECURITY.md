# Security policy

This alpha is experimental; no independent security review has taken place. Fixture scores and report checksums cannot authorize real actions. Recompute from trusted inputs and isolate adapters from production secrets/accounts.

If the repository Security tab offers a private report button, use it. Otherwise do not post exploit details publicly: open a public issue titled Security contact request containing no technical details, and the maintainer will reply with a private channel. No response time is promised. Never send credentials, personal records or raw private traces. No security mailbox is promised and no monitored private channel is confirmed today.

Include affected version/release digest, sanitized reproduction, expected and actual behavior, severity rationale and affected trust boundaries. Maintainers should freeze affected promotion, reproduce, repair with adversarial/mutation tests, independently review and disclose a correction after an authorized fix is ready.

Updated policy snapshots can revoke keys, receipts and subjects. There is no live revocation service or automatic update system. Signatures prove bytes and key possession, not truthful execution. Review [THREAT-MODEL.md](docs/THREAT-MODEL.md).

Further reading: [cryptographic inventory and agility plan](docs/CRYPTO-AGILITY.md), [supply-chain security](docs/SUPPLY-CHAIN.md) and the draft [vulnerability disclosure policy](docs/VULNERABILITY-DISCLOSURE.md) (not in force until the owner adopts it).
