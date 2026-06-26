# Publishing Checklist

Use this checklist before making a demo repository public or before linking it from project documentation.

- Runtime admission has both allowed and blocked examples.
- Static repository guards, including agent context checks, run in CI and locally.
- CI has read-only repository permissions.
- GitHub Actions are pinned to commit SHAs.
- Dependencies are exact and hash-pinned.
- Negative fixtures are generated during tests, not committed as payload files.
- Safety-critical digests were regenerated after the final content change.
- Repository metadata includes a license, contribution guide, security policy, issue template, pull request template, and relevant topics.
