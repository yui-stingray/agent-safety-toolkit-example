# Security Policy

## Supported Scope

This repository is a demo for public-safe agent workflow checks. The supported surface is the current `main` branch.

## Reporting

Open a GitHub issue for non-sensitive bugs in the demo policy, wrapper, tests, or CI configuration.

For sensitive reports, share a minimal description first and omit credentials, private paths, private repository names, and unreleased operational details until a maintainer provides a suitable private channel.

## Design Boundaries

- The demo does not store credentials.
- The demo does not publish packages or artifacts from CI.
- The demo does not use privileged pull request workflows.
- The demo generates negative test fixtures at runtime instead of committing risky payloads.
