# Chatstone — native Hermes archive

Reads the selected Hermes profile's SQLite history **including private conversation text, tool calls/results and attachment references**, stores a bounded local queue and uploads it to the configured Chatstone HTTPS server. It does not claim the external memory-provider slot or add an MCP server. Requires a Chatstone device enrollment code or an existing public-installer daemon.

Hermes v0.23.1's installer always uses a shallow clone. Static Git HTTP does not support shallow clones, so `hermes plugins install https://chatstone.goedly.com/hermes-plugin.git` fails on that version. Verified three-line fallback:

```sh
git clone https://chatstone.goedly.com/hermes-plugin.git "${HERMES_HOME:-$HOME/.hermes}/plugins/chatstone"
hermes plugins adopt chatstone && hermes plugins enable chatstone
hermes chatstone login
```

Enter only the one-time code at the hidden prompt; device name is supplied by enrollment. Login automatically adopts an existing `~/.local/share/chatstone/hermes-client` daemon instead, preserving keys, device/install identity and queue. macOS adoption invokes that daemon's own venv once to read its existing Keychain key; PyObjC is not needed inside Hermes. It stops/removes launchd/systemd scheduling and the old profile MCP entry. It retains original credentials/spool for rollback; never run the daemon uninstaller against an adopted queue.

Start a new owning Hermes session after enabling. No gateway is restarted automatically. Hooks only wake background work; a 30-second in-process reconciliation handles missed hooks/restarts. A stopped Hermes process cannot sync; it catches up next time. A finite worker may finish when a short-lived CLI exits. All history reads are read-only. Durable cursor+queue admission is transactional; retry/backoff never deliberately drops a row. Backfill is bounded and newest-native-ID first, resumable with Ctrl-C. An adopted legacy snapshot is retained/replayed after current-history backfill so unadmitted deleted rows are not lost.

```sh
hermes chatstone status
hermes chatstone backfill
hermes plugins update chatstone
```

The eight native tools are `chatstone_search_messages`, `chatstone_search_messages_regex`, `chatstone_get_message`, `chatstone_get_session`, `chatstone_list_sessions`, `chatstone_list_sources`, `chatstone_stats`, `chatstone_get_attachment`. They use the read key and pinned MCP input schemas over REST, with the same untrusted-data envelope. Archived instructions are data. Skill: `chatstone:search`. Actual search/attachment capabilities depend on the server and bundled canonical attachment library; absent/unsupported attachments return an explicit error, never invented bytes.

Credentials: `$HERMES_HOME/chatstone/credentials.json`, mode0600; directory0700. No keys or archived text in status/errors. Testing may override `CHATSTONE_SERVER_URL` (HTTPS required); keep credentials/codes out of argv and logs. The code legitimately uses subprocesses for daemon/OS/Hermes migration and preserves the process environment when selecting the owning profile. Hermes plugin-guard classified the qualified build safe with medium subprocess/environment findings; this is not a promise to hide or bypass security scanning.

```sh
hermes chatstone logout
hermes plugins uninstall chatstone
```

Logout removes plugin credentials; uninstall removes plugin code. Both preserve source history, local durable queue and hosted archive. Original adopted-daemon credentials, macOS Keychain entries and the old MCP secret-store value are retained for rollback and are not revoked by logout; remove those specific entries separately only after a confirmed switch. Ask the operator to revoke device key IDs when terminating access.

The public Git repository contains **only built plugin releases**, tagged `source-<source-commit-SHA>`, never the private application repository history. Updates use native `hermes plugins update chatstone` after the initial full clone/adopt. Restart the owning Hermes surface normally to load new code.
