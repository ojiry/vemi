# VEMI

VEMI runs on macOS and periodically performs static reviews of public GitHub PRs that request a review from a configured account. Claude Code reads the code in an isolated container, and the host posts only validated results as GitHub reviews.

By default, VEMI runs in dry-run mode. See the [operations guide](docs/security.md) for setup, review and approval rules, shutdown and recovery, and pre-publication checks.
