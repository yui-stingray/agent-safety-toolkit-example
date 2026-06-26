## Summary

Describe the change and why it is needed.

## Verification

- [ ] `python -m pytest -q`
- [ ] `bash scripts/run_demo.sh`
- [ ] `agent-guard digest check --root . --policy .agent-guard/digest-policy.yaml`

## Safety check

- [ ] No credentials, private paths, or private repository data are included.
- [ ] Safety-critical file digests were updated after intentional changes.
