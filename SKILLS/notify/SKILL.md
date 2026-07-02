---
name: notify
description: "Use when a bug bounty finding is confirmed and its report is written, and you need to fire a real-time Discord (or Slack) alert that a finding landed — via projectdiscovery `notify`. One alert per confirmed finding, the moment the report `.md` is saved. Triggers: notify, notification, Discord alert, webhook ping, finding alert."
---

# /notify - Real-time finding alerts

Fire **one** real-time alert per confirmed finding so **Liodeus** sees bugs land the moment they're
written, without watching the terminal. Alerts go out via
[`notify`](https://github.com/projectdiscovery/notify) (projectdiscovery — installed by `install.sh`;
its Discord webhook lives in `~/.config/notify/provider-config.yaml`).

This is the alerting half of the report pipeline: `/report-yeswehack` writes the finding to a `.md`,
then calls **`/notify`** to ping the channel. Keep the alert mechanics here (single source of truth) —
the report skill just links to this one.

## When to fire — one alert per confirmed finding

Send an alert **only when all four reporting gates in `CLAUDE.md` are met** (vulnerability confirmed,
endpoint in scope, minimal PoC exists, impact is concrete) — i.e. the same moment `/report-yeswehack`
writes the report `.md`.

* **One alert per confirmed finding.** Never per draft, never per probe, never per recon hit.
* **Fire it right after the report `.md` is written.** Link the file path — don't paste the body.
* **Never block reporting on the alert.** The finding is already saved in the `.md`; the ping is a
  convenience, not a gate.

## The command

`notify` reads the message from **stdin** (v1.0.7 has no inline `-msg` flag). Pipe a formatted
finding block into it, with the report path interpolated via `printf`'s `%s`:

```bash
printf '🐛 Confirmed: IDOR on PATCH /api/v1/orders/{id} — cross-tenant order modification\nSeverity: High\nTarget: app.target.tld\nEndpoint: PATCH /api/v1/orders/{id} (id)\nReport: %s\n\nNo ownership check — any authed user reads/writes other tenants'\'' orders by incrementing id.' \
  "$(pwd)/report_idor_api-target-com_2026-06-30.md" \
  | notify -bulk -provider discord -id hunt
```

## Alert block format

Keep it a scannable **summary**, not the report:

```
🐛 Confirmed: <vuln> on <method> <endpoint> — <one-line impact>
Severity: <Critical|High|Medium|Low>
Target: <host>
Endpoint: <method> <path> (<param>)
Report: <absolute path to the .md>

<1-2 sentence why-it-matters>
```

## Rules

* **`-bulk` is mandatory — it's what makes the whole block ONE message.** Without `-bulk`, `notify`
  sends a separate message **per line** of stdin (a 6-line block → 6 messages). With `-bulk`, the
  entire piped block goes as a single message (chunked only past the char-limit). Always pass
  `-bulk`, never drop it.
* **Keep the block under ~1900 chars** (Discord's per-message limit) so it never chunks. This is a
  *summary* — the full write-up lives in the `.md`; link its path, don't paste the body.
* **Provider config is a secret.** `notify` reads its webhook from
  `~/.config/notify/provider-config.yaml` (gitignored, never committed). With only the `hunt` discord
  provider configured, `-provider discord -id hunt` are optional but explicit — pass them anyway.
* **Non-blocking.** If delivery fails (rate limit, bad config), the finding is still saved in the
  `.md`. Re-run the exact command to resend — never block or abandon reporting because the ping
  failed.

## Common mistakes

| Mistake | Fix |
|---|---|
| Dropped `-bulk` → N separate messages | Always pass `-bulk` |
| Pasted the full report body → chunked / spammy | Summary only; link the `.md` path |
| Fired on a probe / draft / recon hit | Only on a confirmed finding (all 4 gates met) |
| Used `-msg "..."` | No such flag in v1.0.7 — the message goes on **stdin** |
| Blocked reporting when the webhook failed | Non-blocking; the report is saved regardless — re-run to resend |
| One alert per request in a chain | One alert per **confirmed finding**, not per PoC step |
