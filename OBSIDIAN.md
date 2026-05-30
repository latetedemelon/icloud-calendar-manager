# Investigation: an Obsidian bridge

> Status: **investigation only — not implemented.** This documents whether (and
> how) Obsidian could be integrated, since it was requested alongside the CalDAV
> providers. Conclusion: Obsidian cannot be a calendar *provider*, but a
> one-directional **export bridge** to a vault is feasible as a separate,
> optional feature. Recorded here for a future decision.

## Why Obsidian is not a provider

Obsidian is a **local Markdown notes application**. It is not a CalDAV or
CardDAV server and exposes **no standard remote calendar API** to connect to.
There is no endpoint, principal, or collection to point this tool at, so it
cannot be added to the provider registry the way Nextcloud or Fastmail were.

Things that look like "Obsidian sync" are unrelated to calendar protocols:

- **Obsidian Sync** is Obsidian's proprietary, end-to-end-encrypted file sync
  for vault contents — not an API we can call.
- Community plugins (e.g. *Remotely Save*, *Obsidian Git*) sync the vault's
  **files** via WebDAV/S3/git. That is file replication, not CalDAV.
- Calendar-flavored plugins (*Full Calendar*, *Tasks*, *Dataview*, *Periodic
  Notes*) read/write **Markdown in the vault**; some *Full Calendar* setups can
  read a remote `.ics` URL, but Obsidian still isn't serving calendar data.

So any integration is really "**get my calendar/reminder data into (or out of)
a folder of Markdown/ICS files**", which is a file-export problem, not a
provider.

## Feasible designs (if pursued later)

### Option A — Markdown export into a vault (read-only, recommended)
Add an **export target** (not a provider) that writes events/reminders the tool
already fetches into a vault folder as Markdown with YAML front-matter, one file
per item, e.g.:

```markdown
---
uid: 1234-...
type: event
start: 2026-06-01T09:00:00
end: 2026-06-01T10:00:00
calendar: Home
location: HQ
---
# Standup
Daily sync.
```

- Plays well with *Dataview*/*Tasks*/*Full Calendar*, which query front-matter.
- Pure local file writes; no new network surface; easy to unit-test.
- One-directional (provider → vault). A `calendar-manager export obsidian
  --vault ~/Vault/Calendar [--provider ...] [--days N]` command.

### Option B — ICS files into a vault
Write standard `.ics` files into the vault for plugins that consume `.ics`
(e.g. *Full Calendar*'s local-calendar mode). Simpler payload, less queryable
than front-matter.

### Option C — Two-way sync (not recommended now)
Parse Markdown back into events and push to the provider. This needs conflict
resolution, change detection, and a stable Markdown↔iCalendar mapping — a large,
stateful feature at odds with the current **stateless client** design. Out of
scope unless there's a strong use case.

## Recommendation

If an Obsidian feature is wanted, implement **Option A** as an optional
`export` command/target, clearly separate from the provider system, and keep it
**one-directional** to preserve the stateless design (the provider remains the
source of truth). It would reuse the existing `EventInfo`/`ReminderInfo`
models and `--provider` selection, adding only a Markdown writer.

No code has been added for any of these options.
