# Adoption Recipe

This demo is meant to be copied into a public repository and then adapted. Do
not copy local machine paths, generated private evidence, personal hook config,
or private repository examples.

## Copy These Files

Start with these files:

- `.agent-policy/policy.toml`
- `.agent-guard/api-policy.yaml`
- `.agent-guard/content-policy.yaml`
- `.agent-guard/context-policy.yaml`
- `.agent-guard/digest-policy.yaml`
- `.agent-guard/path-policy.yaml`
- `scripts/policy_admit.py`
- `scripts/run_demo.sh`
- `scripts/update_digests.py`
- `requirements/agent-safety-tools.txt`

Copy the GitHub Actions job from `.github/workflows/ci.yml` if the target repo
uses GitHub Actions. Keep repository permissions read-only unless the workflow
has a specific reason to write.

## Adapt Before Publishing

Replace the demo-specific values before linking the repository publicly:

- repository identifiers such as `yui-stingray/agent-safety-toolkit-example`;
- the action-to-capability map in `scripts/policy_admit.py`;
- the capability matrix in `.agent-policy/policy.toml`;
- content scan targets in `.agent-guard/content-policy.yaml`;
- API allow/deny rules in `.agent-guard/api-policy.yaml`;
- path rules for local artifacts, generated outputs, and private fixtures;
- branch names and workflow names in `.github/workflows/ci.yml`;
- digest pins in `.agent-guard/digest-policy.yaml`.

Regenerate digest pins after every intentional change to pinned files:

```bash
python3 scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/digest-policy.yaml --json
```

## First Verification Pass

Run the same checks locally before enabling the workflow:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/agent-safety-tools.txt
python -m pytest -q
bash scripts/run_demo.sh
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/digest-policy.yaml --format json
```

If dependency hashes do not match on the target platform, regenerate the lock
file for that platform instead of removing hash checking.

## Do Not Copy

Do not copy or publish:

- `.venv`, `.pytest_cache`, `__pycache__`, local logs, or local databases;
- `.env*` files, private keys, tokens, or credentials;
- private corpora, bypass corpora, red-team transcripts, or personal notes;
- generated evidence from a private repository unless it has been reviewed and
  is known to be sanitized;
- hook config with personal absolute paths.

The committed demo evidence is generated for this public-safe repository. Treat
it as a shape example, not proof that another repository is safe.

## What Maintainers Should Review

For each pull request that changes agent instructions, policy files, wrapper
logic, or CI guard commands, review:

- the `agent-policy` runtime admission decision or audit event;
- the `agent-guard` context inventory and context lock coverage;
- digest drift for pinned safety-critical files;
- workflow drift for required guard commands;
- whether the evidence omits raw prompts, snippets, hash values, secrets, and
  local paths.

This recipe is deliberately narrow. It does not add an LLM reviewer, issue
triage bot, model router, broad secret scanner, or governance framework.
