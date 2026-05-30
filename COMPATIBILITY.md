# Provider compatibility matrix

This tool talks to calendar/reminder services over **CalDAV** (RFC 4791) and, for
Microsoft, the **Microsoft Graph** REST API. Any RFC-compliant CalDAV server
works via `--provider generic --url ...`; the named presets below add the
correct base URL / path and accurate capability flags so you don't have to look
them up.

Run `calendar-manager providers` (or `icloud-calendar providers`) to print this
list, with `--json` for machine-readable output.

## Hosted services

| Provider (`--provider`) | Events | Reminders | Auth | Notes |
|---|---|---|---|---|
| `icloud` | ✅ | ✅ (VTODO) | app password | Default. App-specific password required. |
| `fastmail` | ✅ | ✅ (VTODO) | app password | App password with the Calendars (CalDAV) scope. |
| `yahoo` | ✅ | ✅ (VTODO) | app password | App password from Yahoo account security. |
| `posteo` | ✅ | ✅ (VTODO) | password | Endpoint `posteo.de:8443`. |
| `mailbox` | ✅ | ✅ (VTODO) | password | mailbox.org (`dav.mailbox.org`). |
| `gmx` | ✅ | ✅ (VTODO) | password | `caldav.gmx.net`. |
| `google` | ✅ (CalDAV) | ✅ (Google Tasks) | OAuth2 | **Experimental.** Token or refresh-token. |
| `microsoft` | ✅ (Graph) | ✅ (To Do) | OAuth2 | **Experimental.** Token or refresh-token. |

## Self-hosted / open-source servers

All of these require `--url https://your-host` (no fixed host). The preset
appends the server's conventional DAV path for you (idempotent — passing the
full path also works), and `/.well-known/caldav` discovery is attempted where
supported.

| Provider (`--provider`) | Events | Reminders | Path appended | Notes |
|---|---|---|---|---|
| `nextcloud` | ✅ | ✅ | `/remote.php/dav` | Use an app password. |
| `owncloud` | ✅ | ✅ | `/remote.php/dav` | Use an app password. |
| `radicale` | ✅ | ✅ | — | Point `--url` at the collection root. |
| `baikal` | ✅ | ✅ | `/dav.php` | sabre/dav based. |
| `sogo` | ✅ | ✅ | `/SOGo/dav` | |
| `davical` | ✅ | ✅ | `/caldav.php` | |
| `zimbra` | ✅ | ✅ | `/dav` | |
| `synology` | ✅ | ✅ | — | Synology Calendar's CalDAV port (e.g. `:5001`). |
| `vikunja` | ❌ | ✅ (tasks) | `/dav` | **Tasks only** — Vikunja exposes no events; event commands raise a capability error. Experimental/alpha CalDAV. |
| `generic` | ✅ | ✅ | — | Any RFC-4791 server; full `--url` required. |

## How URL resolution works

- For a self-hosted preset, pass the **bare host**:
  `--provider nextcloud --url https://cloud.example.com`. The tool resolves this
  to `https://cloud.example.com/remote.php/dav`. Passing the full path is also
  fine — the suffix is not appended twice.
- `CALDAV_URL` can supply the host via the environment instead of `--url`.
- A trailing slash on the supplied URL is normalized away.

## Capability gating

Each provider declares whether it supports **events** and **reminders**. If you
call an unsupported operation (e.g. `events add` on Vikunja, or `reminders` on a
calendar-only CalDAV server), the tool raises a clear `CapabilityError` instead
of producing a confusing server error.

## What is **not** supported

- **CardDAV / contacts.** This tool is calendars + reminders only. Contacts
  (CardDAV, vCards) are a separate domain and are intentionally out of scope for
  now. See `DECISIONS.md`.
- **Obsidian and other note apps.** Obsidian is not a CalDAV/CardDAV server, so
  it cannot be a provider. See `OBSIDIAN.md` for an investigation of a possible
  file-based export bridge (not implemented).
- **Proprietary calendar APIs** without CalDAV (beyond Microsoft Graph, which is
  implemented). These would each need a dedicated backend.

## Notes on testing

The named presets are validated by unit tests for **URL/path resolution and
capability flags** (no network). End-to-end behavior against a live server still
depends on that server's configuration and credentials; the self-hosted and
OAuth (`google`, `microsoft`) providers have **not** been exercised against live
instances in CI.
