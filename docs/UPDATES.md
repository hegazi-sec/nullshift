# Updates

How a NullShift install learns about, and optionally installs, a new
release from GitHub (2026-10). The Pro package already updates itself
(`nullshift pro sync`); this is about the core.

## Releases

A release is a **signed git tag** `vMAJOR.MINOR.PATCH` (e.g. `v0.3.0`) on
the repository the install was cloned from (public `hegazi-sec/nullshift`,
or the private repo). `app/version.py` holds `VERSION` ("0.3.0"); a release
bumps it (and `pyproject.toml`) in the commit the tag points to.

Tags are signed with Cyber-Pillar's **release SSH key**. Its public key is
embedded in `app/updater.py` (`ALLOWED_SIGNERS`, git's allowed-signers
format, principal `release@cyber-pillar.com`). An install verifies a tag
with **its own** embedded key (never one fetched with the update), so a
compromised GitHub repository cannot ship an update. Rotating the key is a
release signed by the old key that adds the new one. Until the key exists
`ALLOWED_SIGNERS` is empty: nothing verifies, so Auto never updates, and
Notify says the newer release "is not signed; update manually".

Unsigned tags (`v0.1.0`, `v0.2.0`) and any tag whose signature does not
verify are never installed automatically.

## Modes (Settings › Updates, admin)

| mode | what happens |
|---|---|
| **Off** | nothing is checked |
| **Notify** (default) | a daily check; admins see "Update available: vX.Y.Z" in Settings › Updates and a dot on the Settings link; `nullshift update --check` says the same |
| **Auto** | the daily check, then the update below, by itself |

Stored in config.db as `update_mode` (`off` \| `notify` \| `auto`), with
`update_state` (JSON: last check, latest tag seen, verified or why not, last
update and its result, the commit rolled back from).

## When an install can update itself

Only a **release checkout**: the NullShift folder is the top level of its
own git repository (`git rev-parse --show-toplevel` is this folder), the
working tree is clean (the same `_local_changes` filter `nullshift update`
uses), and HEAD is an ancestor of the new tag. Anything else (a development
tree where the git root is a parent folder, local edits, local commits, a
zip download without `.git`, Docker) is **notify only**, with the reason
shown. Docker is detected (`/.dockerenv` or `NULLSHIFT_IN_DOCKER`): the
message gives the rebuild steps (`git pull`, `docker compose build
--no-cache`, `docker compose up -d`) instead.

## The check (daily, plus "Check now")

- In a git checkout: `git fetch --tags --quiet origin`, then the highest
  `v*` semver tag above `VERSION`, then `git verify-tag` with
  `gpg.format=ssh` and an allowed-signers file written from
  `ALLOWED_SIGNERS` to a temp file. Its result is "verified" or the reason.
- Without git (zip, Docker image): the GitHub tags API of
  `NULLSHIFT_UPDATE_REPO` (default `hegazi-sec/nullshift`), notify only, no
  verification (nothing is installed from it).
- Never raises; a failure is recorded in `update_state` and retried next
  day. Timeouts 30 s. Runs in its own daemon thread, never on a request.

## The update (Auto, "Update now", `nullshift update`)

`nullshift update` changes from "pull origin/main" to "move to the newest
verified release tag"; `nullshift update --check` only reports;
`nullshift update --mode off|notify|auto` sets the mode. Steps:

1. **Wait for idle** (Auto only): no investigation in flight (`_INFLIGHT`),
   checked every minute for up to 6 hours, else skipped until tomorrow.
2. Record the current commit and requirements.
3. Install the **new** release's dependencies first, from
   `git show <tag>:requirements.txt` (so a `--reload` server never reloads
   onto missing packages).
4. `git merge --ff-only <tag>` (stays on the branch; refuses if not a
   fast-forward).
5. Restart: the server is restarted the way `nullshift restart` does it. An
   update started from the web UI runs as a detached `nullshift update`
   process so it survives the restart.
6. **Health check**: `/health` answers 200 within 90 s and the startup log
   has no traceback from `app.main`. Otherwise **roll back**:
   `git reset --hard <previous commit>`, reinstall the previous
   requirements, restart, and record "rolled back: <why>". A rolled-back
   tag is not tried again automatically.

Every step is logged (`nullshift.updater`) and the outcome stored in
`update_state`. The Pro package needs nothing here: the restarted server's
startup sync fetches the package for its `PRO_API`.

## UI and CLI

- Settings › **Updates** (admin): current version, mode selector, last
  check and its result, latest release and whether it verified, **Check
  now**, **Update now** (when an update is possible; confirm first), the
  last update's outcome, and the reason when this install can only be
  notified.
- A small dot on the Settings link for admins when a verified update is
  available (Notify).
- CLI: `nullshift update`, `nullshift update --check`, `nullshift update
  --mode …`; `nullshift license`/`status` unchanged.

## Release checklist (owner)

1. Once: create the release key with a passphrase and send its public half
   to be embedded:
   `ssh-keygen -t ed25519 -C release@cyber-pillar.com -f ~/.ssh/nullshift-release`
2. Bump `VERSION` (app/version.py) and `pyproject.toml`, commit, sync the
   public repo.
3. Sign and push the tag in **both** repositories:
   `git -c gpg.format=ssh -c user.signingkey=~/.ssh/nullshift-release.pub tag -s v0.3.0 -m "NullShift 0.3.0"`
   then `git push origin v0.3.0` (and the public remote).
4. If core changed what `app/pro` relies on, bump `PRO_API` and publish the
   Pro package first.
