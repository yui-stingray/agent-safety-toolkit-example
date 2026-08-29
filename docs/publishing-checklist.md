# Publishing Checklist

Use this checklist before making a demo repository public or before linking it from project documentation.

- Runtime admission has both allowed and blocked examples.
- Static repository guards, including agent context checks, run in CI and locally.
- Surface inventory v2, drift v2, recommended conformance, and evidence-pack manifest v2 checks run in CI and locally.
- Each public audit event has a v2 content binding validated by both consumers with the same repository-relative path and recognized profile.
- CI has read-only repository permissions.
- GitHub Actions are pinned to commit SHAs.
- Dependencies are exact and hash-pinned.
- Before either upstream package is uploaded, its reviewed candidate wheel has
  passed `scripts/check_candidate_wheel_compatibility.py` from an exact Toolkit
  commit after the upstream package contract. The live lock and evidence remain
  pinned to published distributions.
- Public evidence handoffs do not include raw per-scanner JSON from a private repository.
- Executable negative payloads are generated during tests, not committed.
  Any committed adversarial fixtures are inert, dummy-valued, and fenced for
  static review only.
- Safety-critical digests were regenerated after the final content change.
- The adoption recipe has been de-personalized before linking or publishing.
- Repository metadata includes a license, contribution guide, security policy, issue template, pull request template, and relevant topics.
