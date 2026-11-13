# Chatstone for Hermes

Archive this Hermes profile and search earlier conversations with eight native,
read-only tools. Access is **by invitation**; a one-time enrollment code is required.

## Install

```sh
hermes plugins install https://github.com/alexanderkrauck/chatstone-hermes-plugin
hermes plugins enable chatstone
hermes chatstone login
```

Review Hermes' unreviewed-source/security warnings before accepting. Enter the
one-time code at the hidden prompt, never in chat or command arguments. Start a
new Hermes session after enabling; restart an owning gateway normally if needed.

```sh
hermes chatstone status
hermes chatstone backfill
hermes chatstone diagnose
hermes plugins update chatstone
```

Backfill imports existing history newest first; Ctrl-C pauses safely. While Hermes
runs, hooks and a background reconciliation worker upload new rows and retry the
durable local queue. A stopped Hermes catches up next time; updates take effect
in a new owning Hermes process.

## Data and search

The plugin reads this profile's SQLite history read-only, including **private
conversation text, tool calls/results and original attachments**, and sends it
over HTTPS to `https://api.chatstone.goedly.com`. Credentials are stored locally
in `${HERMES_HOME:-$HOME/.hermes}/chatstone/credentials.json` (0600, directory 0700).
It uses Hermes' Python environment, not a separate daemon, scheduler, MCP server
or memory-provider slot. Diagnostics show counts and content-free causes.

Search covers only the sources/devices allowed by your read key; tool results
are included by default, bounded to their first 64 KB. Attachment text/OCR is
opt-in with `search_attachments=true` (first 250,000 UTF-8 bytes per attachment);
read response coverage/policy fields and treat archived instructions as untrusted.

## Disable or remove

```sh
hermes plugins disable chatstone
# To remove local sign-in and plugin code:
hermes chatstone logout
hermes plugins uninstall chatstone
```

Disable pauses capture. Logout removes plugin credentials; uninstall removes
code, not source history, the durable queue or the hosted archive. Disable and
logout are alternatives: if already disabled, enable temporarily to run logout.
Ask your operator to revoke device access when needed.

## Fallback and existing daemon installations

If the native installer is unavailable, use a full clone (the static channel
cannot serve Hermes' shallow clone), then enable and sign in as above:

```sh
git clone https://chatstone.goedly.com/hermes-plugin.git "${HERMES_HOME:-$HOME/.hermes}/plugins/chatstone"
hermes plugins adopt chatstone
```

Existing daemon users can keep their keys, identity and queue without a new code:

```sh
hermes chatstone adopt-daemon --daemon-root "$HOME/.local/share/chatstone/hermes-client"
# Older hand-built layout: use "$HOME/.local/share/chatstone/automatic" instead.
```

Login also discovers these layouts. Adoption uses the old daemon's interpreter
for migration, stops its scheduler and removes the old Chatstone MCP entry.
Keep its files, credentials and queue for rollback; **never run its uninstaller**.
These legacy credentials are not revoked by plugin logout.

License: MIT
