<div align="center">

<img src="app/static/logo.svg" alt="NullShift logo" width="120"/>

# NullShift

### AI-Powered SOC Triage Assistant

*Turn a queue of raw detections into a queue of pre-investigated cases.*

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-00b4d8?style=flat-square)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-2a3a55?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Made by Ahmed Hegazi](https://img.shields.io/badge/Made_by-Ahmed_Hegazi-eab308?style=flat-square)](#author)

</div>

---

## What is NullShift?

**NullShift** is an open-source AI assistant for L1 SOC analysts. It plugs into your SIEM, retrieves the right playbook for the alert at hand, runs the deterministic investigation steps, enriches IOCs against threat intelligence, and produces a structured report — so analysts spend their time on the 5% of detections that matter, not the 95% that look suspicious but aren't.

It works with any major LLM provider — Anthropic Claude, OpenAI GPT, or a fully local Ollama model — and connects to **LimaCharlie**, **Wazuh**, **Splunk**, **Elastic**, or **Microsoft Sentinel** out of the box.

## Highlights

- **12 LLM providers** — Claude Agent SDK (use your Claude subscription, no API key), cloud APIs, or fully local Ollama (even hosted on another machine over Tailscale).
- **5 SIEM connectors, several at once** — Wazuh, LimaCharlie, Splunk, Elastic, Sentinel; every investigation queries all the connected ones (several at once is Pro; Community queries the primary).
- **RAG over your own playbooks** — drop markdown files into `data/kb/` and they're indexed automatically.
- **Structured investigation reports** — SECTION 1 (evidence) → SECTION 2 (reasoning) → SECTION 3 (verdict).
- **Case management & reports** — group investigations into cases (`INC-0001`…) with severity, status, verdict, and notes; export Markdown or print-ready HTML/PDF (export is Pro).
- **Webhook alert ingestion** — SIEMs push alerts straight into NullShift's inbox; one click turns an alert into a full investigation.
- **Autonomous SOC agents** *(Pro)* — Triage, Investigator and Reporter work the alert queue on their own. Start them in shadow mode, cap what they may decide by severity and confidence, limit them to after-hours, and keep host isolation behind a human approval.
- **Alert queue** — a dense table of the inbox with age against severity targets, a "Mine" filter, oldest-first sorting, bulk close / dismiss / add to case, one investigation for several related alerts, and keyboard triage.
- **Alert workbench** — each alert shows its key facts, the investigation's verdict and summary, and the next decision (close as false positive, escalate to case, ask a follow-up) on one page.
- **Built for the queue** — search alerts by host or IP across the raw payload, filter by status and severity, undo a dismissal, stop a running investigation, paste or drop screenshots, and move around with keyboard shortcuts.
- **Live dashboard** — the oldest unacknowledged alert, and with Pro the numbers a SOC lead runs on: mean time to acknowledge and to resolve, how much of the queue the agents picked up, and the rules to tune (most false positives, flagged at 80% or more); plus alert volume, severity, hosts and open cases. Click a count or a bar to open the matching alerts.
- **Automatic IOC enrichment** — IPs, domains, and hashes in each message are checked against VirusTotal automatically.
- **L1 → L2 handoff mode** — generates ticket-ready summaries with one command.
- **Per-user temperature, conversation search, verdict tracking, debug traces.**
- **CLI for daily ops** — `nullshift start/stop/status/logs`.
- **Single-command setup** — no config files, no manual steps.

## Quick Start

```bash
git clone https://github.com/hegazi-sec/nullshift.git
cd nullshift
python setup.py
```

The setup wizard creates a virtual environment, installs dependencies, generates a JWT secret, creates your admin account, walks you through SIEM + LLM configuration, and starts the server in the background.

When it finishes, open **http://localhost:58443** in your browser.

## CLI

After setup, manage the server from any terminal:

```bash
nullshift start      # start the server in the background
nullshift status     # check if it's running, see URL + PID + uptime
nullshift logs       # stream live server logs (Ctrl+C to exit)
nullshift stop       # stop the server
nullshift restart    # restart
nullshift update     # pull latest from GitHub, refresh deps, restart
nullshift setup      # re-run the configuration wizard
nullshift passwd     # set a user's password (nullshift passwd [username], default admin)
nullshift activate NS-XXXXX-XXXXX-XXXXX-XXXXX   # activate NullShift Pro with a product key
nullshift license    # show the edition, or load a .lic file: nullshift license acme.lic
nullshift license request-code <KEY>            # offline activation code for air-gapped networks
```

## Requirements

- Python **3.11+**
- macOS, Linux, or Windows 10+
- At least one LLM option configured (see below)

Optional: SIEM credentials (Wazuh / LimaCharlie / Splunk / Elastic / Sentinel) and a VirusTotal API key for IOC enrichment.

## LLM Options

NullShift is provider-agnostic. Pick whichever works for your environment:

### Claude Agent SDK *(no API key needed)*

If you have a **Claude.ai Pro or Max subscription**, NullShift can drive Claude directly through the local **`claude` CLI** — no API key, no per-token billing. NullShift's setup wizard detects the CLI and walks you through the one-time `claude login`.

Best for individual analysts and homelab SOCs running on a personal Claude subscription.

### Cloud API Keys

Paste a key in **Admin → LLM Providers** for any of:

- **Anthropic** (`claude-opus-5`, `claude-sonnet-5`, `claude-fable-5-1`, etc.)
- **OpenAI** (`gpt-6-sol`, `gpt-6-astra`, `gpt-6-luna`, etc.)
- **Google Gemini, Groq, xAI, DeepSeek, Perplexity, OpenRouter, Qwen, Kimi**

### Local Ollama *(fully offline)*

Run any Ollama-compatible model locally — `qwen2.5:14b`, `llama3.3:70b`, `deepseek-r1`, `phi4`, etc. **No API key**, no data leaves your network. Configure the Ollama URL in **Admin → LLM Providers**.

> **Ollama on another machine via Tailscale.** If your GPU lives on a separate box, install Ollama there and connect to it over your Tailscale network — just point NullShift's Ollama URL at the Tailscale IP, e.g. `http://100.x.x.x:11434`. Same setup works for Tailscale Funnel, Cloudflare Tunnel, or any reachable Ollama endpoint.

## Configuration

Almost everything is configured through the **Admin UI** at `/admin` — no restart needed for any setting to take effect.

- **LLM Providers** — pin an active provider, drag-and-drop the fallback chain, paste API keys.
- **Connectors** — connect one or more SIEMs (each with its credentials and a Test connection) + VirusTotal. Every investigation queries every connected SIEM; the first one connected is the primary, whose scale is used for alerts whose shape names no SIEM. The setup wizard connects one; add more here.
- **RAG** — embedding provider, model, live index status.
- **Users** — manage analyst accounts (admin, L1, L2 roles).

Settings are persisted in a SQLite database (`app/data/config.db`). All changes apply immediately thanks to the settings proxy layer in `app/config.py`.

## Using the Console

The left rail switches between **Investigations**, **Alerts**, **Cases**, **Dashboard** and **Agents**. Your name, **Settings** (admins), **Keyboard shortcuts**, **Notifications**, **Density** and **Log out** sit under the account button at the bottom of the rail; on a phone the rail becomes a bottom bar with these under **More**.

- **First run.** On a new install the empty console shows admins a checklist: connect a SIEM (set the webhook token), receive an alert (or **Send a test alert**), investigate it, and try Triage in shadow mode. It ticks itself off as you go and disappears when done, or with **Hide**.
- **Density.** **Compact** fits more rows in the alert queue, lists, dashboard and agent activity; the choice is per device, so a big monitor and a laptop can differ.
- **Get pinged when NullShift is in the background.** The tab title counts new alerts plus isolation proposals awaiting you. Turn on **Notifications** under the account button to get a browser notification for critical alerts, isolation approvals (they open the proposal) and finished investigations. Browsers allow this only over HTTPS or on localhost, and it is per browser, so your phone and desk machine choose separately. A phone only gets them while NullShift is open in its browser.
- **Investigations keep running when you leave.** Switch views, open another chat or reload: the investigation carries on and its reply lands in its own chat, with a notification if you're elsewhere.
- **Stop an investigation** with **Stop investigation**, shown above the message box while one runs. The chat frees up at once so you can ask again; a model call already underway finishes in the background and its answer is dropped.
- **Investigation reports** open with a summary card: verdict and confidence, a short summary, next steps, the IOCs as chips (VirusTotal status, search alerts for it, start an investigation, copy) and what was checked (sources, time window, queries and results). The full evidence sections fold underneath.
- **Attachments** — paste a screenshot straight into the message box, drop it anywhere on the chat, or use the paperclip. CSV files (up to 3, 5 MB each) are profiled and analyzed as data.
- **Options** next to the message box holds the debug trace and the response temperature; a chip shows either one when it isn't at its default.
- **Deletes and other one-way actions** ask in a dialog that names exactly what is affected. Dismissing an alert doesn't ask, because you can undo it.

| Shortcut | Action |
|---|---|
| `⌘K` / `Ctrl+K` | Search the current list |
| `⌘⇧O` / `Ctrl+Shift+O` | New investigation |
| `⌘/` / `Ctrl+/` | Go to the message box |
| `↑` `↓` | Move through the list |
| `Esc` | Close a menu, dialog or the list drawer |
| `?` | Show all shortcuts |
| `j` `k` · `x` · `e` · `d` | Alert queue: move · select · investigate · close as false positive |

## Case Management & Reports

Turn one-off chats into tracked cases and hand-off-ready reports.

**Create & manage a case**

1. Open an investigation, then click **Add to case** in the top bar.
2. Create a new case or attach the chat to an existing one. Each case gets a sequential number (`INC-0001`, `INC-0002`, …).
3. Open the **Cases** tab in the sidebar to see every case with a severity dot and status badge.
4. Click a case to set **severity** (low / medium / high / critical), **status** (open / investigating / closed), a final **verdict**, and free-form **analyst notes** — and to link or unlink multiple conversations. One case can span many chats. Changes save automatically.

**Export a report**

From an open case:

- **Export report (HTML)** — opens a clean, print-optimized page. Use your browser's **Print → Save as PDF** for a shareable artifact.
- **Export report (MD)** — downloads `INC-XXXX-report.md` for pasting into a ticket (TheHive, Jira, email).

Reports include case metadata, analyst notes, the **IOC verdict trail** across every linked chat, and the full investigation timeline. All chat content is escaped, so nothing in a conversation can inject markup into the report.

## Webhook Alert Ingestion

Let your SIEM push alerts directly into NullShift instead of analysts pasting them in. Alerts land in a shared **Alerts** inbox (sidebar tab) with a live unread badge.

Each alert opens as a **workbench**: the key facts pulled out of the raw payload (host, user, process, command line, IPs, hashes, domain, rule, MITRE technique, event time) beside the investigation, with the raw JSON one click away. **Investigate** runs the full pipeline right there; when it finishes, the verdict, a short summary, next steps and the IOCs appear on the alert together with the decision that follows — **Close as false positive** (or dismiss for another reason, with a note), **Escalate to case**, or **Ask a follow-up** in the chat behind it. If the Triage agent already looked at the alert, its verdict and reasoning show there too. Every dismissal can be undone (**Undo**, or **Restore alert** later).

**Alerts** opens as a queue table: severity, age, rule, host, source, status, owner, the agent's suggestion and the case. It starts on **New** alerts; switch to **Investigating** or **All**, filter by severity, show only **Mine**, sort oldest first to work the backlog, and search by title, source or anything in the raw payload — a hostname, IP or user finds its alerts even when it isn't in the title. An alert's age turns amber when it has waited past its severity's target (critical 15 min, high 1 h, medium 4 h, low 24 h) and red past twice that.

Select rows (shift-click for a range) to **Close as false positive**, **Dismiss…** for another reason, **Add to case…** (an open case or a new one), or **Investigate together** — one investigation for up to 25 related alerts that decides whether they are one incident. Keyboard: `j`/`k` move, `x` selects, `Enter` opens, `e` investigates, `d` closes as false positive, `Shift+A` selects all. A case lists the alerts added to it.

**1. Enable it**

Admin → **Connectors** → **Webhook Alert Ingestion** → **Generate token** → **Save**. Ingestion stays disabled until a token is set.

**2. Point your SIEM at the endpoint**

```
POST /api/alerts/ingest?source=<siem-name>
```

Authenticate with the token in **either**:

- the `X-Webhook-Token: <token>` header *(preferred — kept out of logs)*, or
- a `?token=<token>` query param *(for SIEMs that can't set custom headers)*

The body is any JSON (≤ 128 KB). NullShift auto-extracts a title / severity / source from Wazuh, LimaCharlie, Splunk, Elastic, Sentinel and generic payload shapes; anything unrecognized still ingests with the full raw payload preserved.

**Alert severity**

Each SIEM's own severity is read on that SIEM's scale. The sending SIEM is the `?source=` value, else the payload's shape, else the SIEM NullShift is connected to.

| SIEM | Field read (first present wins) | Default mapping to low · medium · high · critical |
|---|---|---|
| **LimaCharlie** | `priority` (the D&R report action's), then `detect_mtd.severity` | 0–2 · 3–4 · 5–7 · 8–10 (LimaCharlie's own Cases mapping) |
| **Wazuh** | `rule.level` | 0–6 · 7–9 · 10–12 · 13–15 |
| **Splunk** | `result.urgency` / `result.severity` (words or the 1–6 scale) | words as-is (informational → low); 1–3 · 4 · 5 · 6 |
| **Elastic** | `rule.severity`, then the risk score | words as-is; 0–21 · 22–47 · 48–73 · 74–100 |
| **Sentinel** | `properties.severity` / `AlertSeverity` | Informational and Low → low, Medium, High (Sentinel has no Critical) |

Admins can change each SIEM's thresholds and words, and pin a severity per rule (rule overrides win), under **Settings → Connectors → Alert severity**. Saving re-scores every alert already in the inbox. For LimaCharlie, the cleanest fix is a `priority` in each rule's report action:

```yaml
- action: report
  name: T1555.001 - Keychain Credential Access
  priority: 6   # 0-2 low, 3-4 medium, 5-7 high, 8-10 critical
```

**Quick test**

```bash
curl -X POST "http://localhost:58443/api/alerts/ingest?source=test&token=YOUR_TOKEN" \
  -H "Content-Type: application/json" -d '{"title":"Webhook test","severity":"high"}'
# → {"ok":true,"id":"..."}
```

**Per-SIEM setup**

| SIEM | Auth method | How to connect |
|---|---|---|
| **Wazuh** | Header | Custom integration script (below) referenced from `ossec.conf` |
| **Elastic** | Header | Kibana → Connectors → Webhook, add an `X-Webhook-Token` header |
| **Sentinel** | Header | Logic App playbook → HTTP action with the header |
| **LimaCharlie** | Query param | Output → Webhook, append `&token=` to the destination URL |
| **Splunk** | Query param | Alert action → Webhook, append `&token=` to the URL |

<details>
<summary><b>Wazuh integration script</b></summary>

Create `/var/ossec/integrations/custom-nullshift.py`:

```python
#!/usr/bin/env python3
import sys, json, requests
alert_file, token, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
with open(alert_file) as f:
    alert = json.load(f)
requests.post(hook_url,
    headers={"X-Webhook-Token": token, "Content-Type": "application/json"},
    data=json.dumps(alert), timeout=10)
```

```bash
chmod 750 /var/ossec/integrations/custom-nullshift.py
chown root:wazuh /var/ossec/integrations/custom-nullshift.py
```

Add to `/var/ossec/etc/ossec.conf` inside `<ossec_config>`:

```xml
<integration>
  <name>custom-nullshift</name>
  <hook_url>http://NULLSHIFT_HOST:58443/api/alerts/ingest?source=wazuh</hook_url>
  <api_key>YOUR_TOKEN</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Then `systemctl restart wazuh-manager`. Wazuh passes the alert file, `api_key` (→ token), and `hook_url` to the script; `<level>7</level>` sends only alerts level 7 and above.
</details>

**Exposing NullShift to cloud SIEMs**

If NullShift runs on your own machine and the SIEM is in the cloud (Sentinel, hosted LimaCharlie), it needs a reachable URL. Since NullShift already pairs well with Tailscale, **Tailscale Funnel** is the quickest option:

```bash
tailscale funnel --bg 58443     # serves your local :58443 publicly on https://<machine>.<tailnet>.ts.net
tailscale funnel status
```

Use the public URL **without a port** in your SIEM (`https://<machine>.<tailnet>.ts.net/api/alerts/ingest?...`) — Funnel serves on 443 and forwards to your local port internally. Cloudflare Tunnel or any reverse proxy works too.

> A query-param token can appear in the SIEM's own logs — prefer the header where supported, and regenerate the token if it's ever exposed.

## Autonomous SOC Agents

*NullShift Pro (see [Editions](#editions)).*

Agents work the alert inbox without an analyst at the keyboard. They investigate through the same pipeline as a chat (SIEM queries, playbooks, VirusTotal), acting as the user chosen under **Agents act as**, and every decision lands in the **Activity** list on the **Agents** view.

| Agent | What it does |
|---|---|
| **Triage** | Every minute: groups new alerts by source, rule and host, investigates each group, then dismisses confident false positives and opens a case for the rest. It only sees alerts that arrive after it is switched on. |
| **Investigator** | Every 2 minutes: an L2 investigation of each case Triage opened. Closes confirmed false positives, flags the rest for a human, raises the severity of malicious findings and proposes host isolation. |
| **Reporter** | Posts a shift report (alert volume, agent decisions, open and stale cases) as a new investigation, on a schedule. |
| **Containment** | Isolates a host in LimaCharlie **only after an admin or L2 analyst approves** the proposal. Needs a LimaCharlie API key allowed to task sensors. |

**Options** (each card's **More options**, plus the **Schedule** card)

| Setting | Choices | Default |
|---|---|---|
| Triage mode | **Shadow** — investigates and notes on each alert what it would do, changing nothing · **Autonomous** — dismisses and opens cases | Shadow |
| Triage: auto-dismiss alerts up to | Low · Medium · High · Critical severity; a group above it always gets a case | Medium |
| Investigator: confirmed false positives | Close automatically · Shadow (note it, a human closes) · Never close | Close automatically |
| Investigator: propose isolation at | Low · Medium · High confidence or higher | Medium |
| Reporter | First report at a local hour, then every 24, 12 or 8 hours; each covers the hours since the last one | 06:00, every 24h |
| Timezone | Any IANA zone (e.g. `Africa/Cairo`); the Reporter's times and active hours use it | UTC |
| Active hours | Run Triage and the Investigator only inside a local window (e.g. 18:00–08:00) plus whole days (e.g. Fri, Sat); the Reporter and **Run now** ignore it | Off |

**Staying in control**

- Switching an agent on only asks for confirmation when it can act without a human (Triage in autonomous mode, the Investigator closing cases). Shadow mode and switching off never ask.
- Autonomous dismissals and closures have **Undo** in Activity; **Stop run** ends a run after its current step, and **Stop all agents** switches everything off.
- **Triage shadow scorecard** (Agents view): compares what Triage would have done in shadow mode with what analysts then did — agreement per severity, *false dismissals* (Triage would have dismissed, an analyst escalated) and *too cautious* calls, plus the alerts where you disagreed. A severity counts as safe once it has 20 decided alerts, 95% agreement and no false dismissals; the card then offers **Go autonomous up to** that severity.
- A suggested rollout: set the timezone, turn Triage on in **Shadow**, work the queue as usual for a week or two, and switch to **Autonomous** when the scorecard says a severity is safe.

## IOC Auto-Enrichment (VirusTotal)

When a VirusTotal key is configured, NullShift automatically extracts IPs, domains, and file hashes from each message and enriches them against VirusTotal **before** the LLM reasons over the evidence — the analyst never has to ask.

**Enable:** Admin → **Connectors** → **VirusTotal** → paste a v3 API key → **Save** → **Test key**.

Enrichment is deliberately conservative: private / reserved IPs and filename look-alikes (`report.pdf`, `payload.exe`) are skipped, lookups are **capped at 4 per message** to respect the public API rate limit, and results are cached. Verdicts (`malicious` / `suspicious` / `clean`, engine counts, country, ASN owner) are attached to the evidence bundle and surfaced in the investigation.

## Architecture (Brief)

```
User message → FastAPI route
    ↓
Mode + intent detection (deterministic, no LLM)
    ↓
PlaybookRunner — best-match playbook fires its SIEM queries
    ↓
run_investigation() — fallback keyword-based SIEM hunt
    ↓
VirusTotal IOC enrichment
    ↓
RAG retrieval — pull relevant playbook chunks from Chroma
    ↓
LLM provider chain (Anthropic → OpenAI → Ollama → ...)
    ↓
Structured Markdown report (SECTION 1 / 2 / 3 with Verdict + Confidence)
```

## Repository Layout

```
nullshift/
├── app/
│   ├── main.py              FastAPI routes
│   ├── licensing.py         Editions: license check, seat and SIEM limits
│   ├── pro/                 NullShift Pro (proprietary, licensed installs only): agents,
│   │                        SOC-lead metrics, report export
│   ├── llm.py               LLM provider chain
│   ├── rag.py               Chroma-based playbook retrieval
│   ├── connectors/          SIEM + VirusTotal clients
│   ├── execution/           Investigation pipeline
│   ├── playbooks/           Playbook runner (YAML front-matter)
│   ├── db/                  SQLite stores
│   ├── static/              Logo, favicon
│   └── *.html               UI pages (chat, admin, login, setup)
├── data/
│   └── kb/                  Markdown playbooks (RAG corpus)
├── setup.py                 Interactive setup wizard
├── cli.py                   Daemon management CLI
└── requirements.txt
```

## Knowledge Base & Attribution

NullShift ships with **four NullShift-specific top-level playbooks** in `data/kb/` covering common L1 triage scenarios — SSH brute force, port scans, malware detection, and web attacks.

It also ships **SIEM query-reference knowledge bases** for LimaCharlie, Wazuh, Splunk, Elastic, and Microsoft Sentinel — each covering that platform's query syntax, field/table schema, and 60+ investigation patterns mapped to MITRE ATT&CK. RAG uses them so NullShift can generate correct, ready-to-run hunt queries for whichever SIEM you've connected.

The bulk of the indexed corpus comes from the **Anthropic-Cybersecurity-Skills** project:

> Knowledge base powered by **Anthropic-Cybersecurity-Skills** by **Mahipal** ([mukul975](https://github.com/mukul975)), Apache 2.0 — [github.com/mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)

**What we use from the upstream project:** NullShift ships only a curated subset of the original repository — specifically the **`skills/`** folder (753 SKILL.md playbooks across 26 cybersecurity domains) and the **`mappings/mitre-attack/`** folder (MITRE ATT&CK technique alignment). Repository meta-files, CI workflows, plugin manifests, and unrelated assets were removed to keep NullShift's install footprint lean.

Each indexed skill includes step-by-step procedures, tool commands, expected outputs, and MITRE ATT&CK mappings. The bundled copy in `data/kb/cybersecurity-skills/` retains the original `LICENSE`, `README.md`, and `CITATION.cff` in full compliance with Apache 2.0.

## Tech Stack

- **Backend** — [FastAPI](https://fastapi.tiangolo.com/) + [Pydantic](https://docs.pydantic.dev/) + [uvicorn](https://www.uvicorn.org/)
- **Frontend** — vanilla HTML + CSS + JS (no build step, no framework)
- **LLM SDKs** — [`anthropic`](https://github.com/anthropics/anthropic-sdk-python) + [`openai`](https://github.com/openai/openai-python) (provider-agnostic adapter layer)
- **RAG** — [ChromaDB](https://www.trychroma.com/)
- **Auth** — JWT (HS256) in HttpOnly cookies, `passlib` password hashing (pbkdf2_sha256)
- **Persistence** — two SQLite databases (WAL mode): `config.db` (settings) + `chat.db` (user data)

## Roadmap

- One-line setup for additional SIEMs (CrowdStrike, Microsoft Defender for Endpoint)
- **Case management** *(shipped)* — group multiple investigations into a single case with severity/status/verdict tracking and exportable reports
- **Inbound webhook alert ingestion** *(shipped)* — SIEMs push alerts into NullShift's inbox
- **Autonomous triage, investigation and shift reports** *(shipped)* — with shadow mode, severity/confidence limits and active hours
- **Host isolation with human approval** *(shipped, LimaCharlie)*
- Webhook notifications (Slack / Teams / email) on verdict reached, and shift reports delivered there
- Outbound response actions for other SIEMs/EDRs (block IP, isolate host)
- Scheduled hunts (recurring queries with diff-based alerting)
- Multi-tenant L2 escalation queue

## Contributing

PRs welcome. Fork the repo, create a feature branch in your fork, and open a PR against `main`. See `CONTRIBUTING.md` for code style, commit conventions, and the PR checklist.

## Support & Project Status

This is an actively maintained project — I'm building NullShift to be a tool we can all rely on, not just a side experiment. **Your feedback shapes the roadmap.**

**If anything doesn't work the way you expect**, please [open an issue](https://github.com/hegazi-sec/nullshift/issues) on GitHub. I'll do my best to respond quickly and ship a fix.

### Connector Maturity

| Status | Connector | Notes |
|---|---|---|
| **Production-ready** | **LimaCharlie** | Most thoroughly tested. Recommended for production. |
| **Production-ready** | **Wazuh** | Most thoroughly tested. Recommended for production. |
| **Beta — under active testing** | **Splunk** | Functional. Updates pushed as edge cases are found. |
| **Beta — under active testing** | **Elasticsearch** | Functional. Updates pushed as edge cases are found. |
| **Beta — under active testing** | **Microsoft Sentinel** | Functional. Updates pushed as edge cases are found. |

If you're using one of the beta connectors and run into a problem, **please tell me** — that's the fastest way to get it fixed and promoted to production-ready status.

## Editions

| | Community | Pro |
|---|---|---|
| Chat investigations, RAG playbooks, alert inbox & queue, cases, VirusTotal | ✓ | ✓ |
| SIEMs queried | the primary one | all connected |
| Active users | 3 | per license |
| Autonomous SOC agents | — | ✓ |
| SOC-lead dashboard metrics (MTTA, MTTR, agent share, rules to tune) | — | ✓ |
| Case report export (HTML / Markdown) | — | ✓ |

**Activating Pro.** Enter your product key (`NS-XXXXX-XXXXX-XXXXX-XXXXX`) in **Settings › License** or run `nullshift activate <KEY>`: NullShift exchanges it with the Cyber-Pillar license server for a license signed for this install, checked offline from then on. The license is tied to the install's ID (shown in Settings › License), so reinstalling or rebuilding with `app/data` kept never uses up an activation.

**Free Pro (offer).** From time to time Cyber-Pillar opens a free Pro offer. While it is open, **Settings › License** shows a *Try NullShift Pro free* card on any install without a valid license of its own (`nullshift pro free` on the CLI): one click turns Pro on with no product key, as a license that renews itself with the daily check-in. When the offer closes, Pro ends at the next check-in and the install continues as Community with nothing lost; Settings › License then says the offer has ended. A product key activated at any time replaces the offer's license.

**Machine binding.** The license is also bound to the machine it was activated on: NullShift hashes a hardware ID (Linux `/etc/machine-id`, the macOS platform UUID, the Windows `MachineGuid`, or `NULLSHIFT_MACHINE_ID`) and only that fingerprint, never the raw ID, is sent or stored. Settings › License and `nullshift license` show its first 12 characters. A copy of the install on other hardware shows the state **moved** and runs as Community until it is activated there.

**Moving to a new server.** Activate the key on the new server. If the key is already on its maximum installs, Settings › License offers **Move the license to this install** (`nullshift activate <KEY> --transfer` on the CLI): the license moves at once and the old install loses Pro at its next check-in. Moves are self-service, at most 3 per 30 days; past that, contact Cyber-Pillar.

**Docker.** A container's own `/etc/machine-id` changes when the image is rebuilt, after which the license shows **moved** (NullShift logs a warning at startup when it runs in a container without `NULLSHIFT_MACHINE_ID`). Give the container a stable ID: on a Linux host mount the host's, on a Windows host set `NULLSHIFT_MACHINE_ID` to the output of `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid`:

```yaml
services:
  nullshift:
    environment:
      NULLSHIFT_MACHINE_ID: "<the host MachineGuid>"   # Windows host: the MachineGuid (or any stable value, 32+ characters)
    volumes:
      - /etc/machine-id:/etc/machine-id:ro                             # Linux host: the host's ID instead
```

`NULLSHIFT_MACHINE_ID` and `NULLSHIFT_LICENSE_SERVER` are process environment variables (compose `environment:` or `docker run -e`); a line in `.env` works too. A value of `uninitialized` or shorter than 32 characters is ignored and the next source is tried. Without any, the install is unbound: it works, but the license is not tied to the hardware.

**Clock.** NullShift remembers the latest time it has seen; a clock more than 24 hours behind it reads as a rollback and turns Pro off (state **clock**). A clock that was set ahead by mistake and then corrected recovers by itself at the next license-server check-in (the server's signed time is the one trusted). For an offline license there is no server to ask: `nullshift license reset-clock` on the server sets the clock to now (it is logged with the old and new values).

**Air-gapped networks.** Settings › License (or `nullshift license request-code <KEY>`) shows a request code for your key. Send it to Cyber-Pillar, receive a `.lic` file, and load it in Settings › License or with `nullshift license <file>`. Such a license never phones home.

**The Pro code.** `app/pro/` is not in this repository: it downloads from the license server once a license with a Pro feature is active (at activation, at `nullshift start` and with the daily check-in; `nullshift pro sync` any time), as a package signed by the server and checked here before a byte of it is unpacked. Air-gapped installs receive a `nullshift-pro-<N>.nspro` bundle with the `.lic` and load it with `nullshift pro install <file>`. A new package is loaded at the next restart (`nullshift start` reloads by itself); Settings › License and `nullshift pro status` show what is installed. A checkout that already holds the Pro source is never overwritten.

**Staying on.** An online license checks in with the license server once a day to pick up renewals; a network failure never changes anything. Only three things turn Pro off: a revocation signed by the server for this very license and install (a key revoked, or moved to another server), expiry (after a 14-day grace period), or a system clock rolled back more than 24 hours. The install then continues as Community: logins and alert ingestion never stop, and users over the limit keep their access (only new seats are refused).

## License

NullShift Community is released under the [Apache License 2.0](LICENSE). NullShift Pro (`app/pro/`) is proprietary and ships only to licensed installs.

## Author

Built and maintained by **Ahmed Hegazi**.
