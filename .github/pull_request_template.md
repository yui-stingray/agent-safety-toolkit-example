## Summary

Describe the change and why it is needed.

## Verification

- [ ] `python3 -m pytest -q`
- [ ] `bash scripts/run_demo.sh`
- [ ] `agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml`
- [ ] `agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json`
- [ ] `python3 examples/evidence_consumer.py .agent-guard/evidence/agent-guard-report.json`

## Safety check

- [ ] No credentials, private paths, or private repository data are included.
- [ ] Safety-critical file digests were updated after intentional changes.
