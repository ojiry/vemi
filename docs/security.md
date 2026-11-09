# Security and Operations

## Trust Boundaries

- Python on macOS and trusted configuration call the GitHub API. Targets are unreviewed PRs in configured public repositories and base branches that are assigned directly to a dedicated account. Drafts, private source, and requests addressed only to a team are out of scope. PR numbers and SHAs are validated; PR titles and bodies are not sent to the model.
- The GitHub API provides the merge-base and head Git objects. Blob lengths and Git SHAs are verified. The review uses a snapshot of the head and the pre-change versions of changed files. Symlinks, submodules, colliding paths, and trees or files above configured limits are rejected. No checkout, hooks, or PR-side builds or tests are run.
- Claude Code runs in a non-root container and uses `Read`, `Grep`, and `Glob`. `--bare` disables automatic discovery of `CLAUDE.md`, skills, hooks, MCP, and related configuration. The root and snapshot are read-only. The host home directory, Git configuration, Docker socket, and credentials are not mounted. External networking is disabled; inference goes through a fixed HTTPS gateway over standard input/output. Anthropic Messages API is the only destination.
- GitHub and Anthropic credentials are kept separate. Public code is sent to Anthropic only after secret scanning. Scanning can miss secrets, and prompt injection may affect the model's judgment. The host generates the GitHub comment body from fixed text, changed-file paths, validated line numbers, and classifications, then scans it again.
- Immediately before posting, the host rechecks PR assignment, existing reviews, base, and head. The review specifies the checked head as `commit_id`. Fetch and post are separate API calls, so GitHub must also be configured to dismiss stale approvals when new commits are pushed.

## Setup and Trial Run

1. Install Python 3.9 or later, Docker Desktop, and Gitleaks 8.30.0 or later on macOS. Operate VEMI under a dedicated macOS user; Docker must use that user's local socket.
2. Place the review source from a verified commit. The launchd executable path must be fixed and writable only by the dedicated account; do not point it at a development checkout or PR directory.
3. Build using a verified Node 22 base-image digest and a verified Claude Code version that supports `--bare` and `--json-schema`. Set these shell variables during setup:

   ```sh
   docker build --build-arg NODE_BASE="$VEMI_NODE_BASE_DIGEST" \
     --build-arg CLAUDE_VERSION="$VEMI_CLAUDE_VERSION" -t vemi-runner ./runner
   docker image inspect --format '{{.Id}}' vemi-runner
   ```

4. Create a dedicated state directory outside the repository and set its permissions to `0700`. Copy `review.example.json` to `review.json` and set its permissions to `0600`. Configure the real repository name, dedicated reviewer name, Docker path and socket, Gitleaks path, image ID, and fixed Anthropic model ID. Choose a location where Docker file sharing allows the snapshot to be mounted.
5. Save `github.token` and `anthropic.token` in the state directory with permissions `0600`. Use a fine-grained PAT for the dedicated GitHub reviewer, restricted to the target repository. For trials, grant Contents and Pull requests read access; grant Pull requests write access only when posting. Use an API key dedicated to reviews with an Anthropic usage limit. Do not put real values in environment variables, shell history, plist files, or commits.
6. Directly assign the dedicated account to a test PR, then run `/usr/bin/python3 scripts/review.py "$VEMI_STATE"`. Dry-run mode still sends public code to Anthropic. Verify normal operation. Check that the reviewer ignores instructions embedded in PR files and blocks review when it detects secrets, the head changes mid-run, or the source is private.
7. Replace the absolute paths in `launchd/org.vemi.review.plist.example` and place it at `~/Library/LaunchAgents/org.vemi.review.plist` for the dedicated user. Run `plutil -lint`, then register it with `launchctl bootstrap "gui/$(id -u)" "$VEMI_PLIST"`. It runs every 15 minutes, prevents concurrent runs against the same state directory, and performs inference and posting for at most one PR per run. Continuous operation requires a logged-in session for the dedicated user and Docker.

## Comments and Approvals

- When `publish_comments` is enabled, validated findings are posted as GitHub review comments. If credential checks, scanning, inference, structural validation, or the PR recheck fails, nothing is posted for that PR.
- Approval is disabled by default. VEMI approves only when comment posting and `allow_approve` are enabled, the PR is in the same repository, the model returns `clean`, and `approve.json` in the state directory exactly matches the PR and both SHAs. A person must inspect the target before placing an authorization file with permissions `0600` in this format. Without authorization, VEMI posts comments. Authorization cannot be reused for a different commit.

  ```json
  {"repository":"OWNER/vemi","pr":42,"base":"BASE_COMMIT_SHA","head":"HEAD_COMMIT_SHA"}
  ```

- External forks receive comments only. Neither model instructions nor PR-side labels can grant approval. In GitHub, require human approval and required CI, and require approval from someone other than the person who last pushed changes. Do not configure a rule that allows a VEMI approval alone to pass a merge.

## Stopping and Recovery

1. Create a `STOP` file in the state directory. To stop work already in progress, run `launchctl bootout "gui/$(id -u)" "$VEMI_PLIST"`, identify any remaining `vemi-review-` containers, and stop them. Check GitHub for the result of any API request already sent.
2. Revoke and rotate credentials suspected of being exposed at their issuing services. Do not copy real values into logs or investigation notes. Review GitHub reviews, history, references, Actions logs and artifacts, and the scope of any external transmission.
3. If necessary, follow GitHub's procedures to remove published material. Coordinate history rewrites with collaborators. Also check for copies in forks and existing clones.
4. Remove authorization files and scan the full history after fixing the cause. Verify dry-run mode with the rotated credentials, remove `STOP`, and register the launchd job again.

## Pre-publication Checklist

- [ ] Run `./scripts/scan-secrets` from a non-shallow clone. Scan local refs and reflogs, staged changes, and tracked and non-ignored files.
- [ ] Review branches, tags, PR refs, and past Actions artifacts that exist only on the remote. Check unreachable Git objects and forks separately; they are normally outside the scanner's scope.
- [ ] Keep credentials, real configuration, logs, and snapshots outside Git. Samples contain dummy values only.
- [ ] Make the secret scan a required CI check and require administrator review for changes to workflows and scanners. Do not execute PR scripts in CI.
- [ ] Test fork PR trials, read-only access and blocked external networking, fixed output generation, and the stop switch.
- [ ] Verify dedicated account and token permissions, revocation procedures, stale-approval dismissal, and manual approval settings.
