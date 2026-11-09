# Implementation Status

The initial implementation adds static reviews of public PRs, boundaries for posting and approval permissions, secret scanning, and stop procedures. Prepare the configuration, image, and execution paths according to the [operations guide](security.md).

Before starting operations, verify in the actual environment the Claude Code and Anthropic Messages API connection, GitHub API responses for fork PRs, test posts to GitHub, and stopping and re-registering the launchd job.
