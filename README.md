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

- 🧠 **12 LLM providers** — Claude Agent SDK (use your Claude subscription, no API key), cloud APIs, or fully local Ollama (even hosted on another machine over Tailscale).
- 🔌 **5 SIEM connectors** — Wazuh, LimaCharlie, Splunk, Elastic, Sentinel.
- 📚 **RAG over your own playbooks** — drop markdown files into `data/kb/` and they're indexed automatically.
- 📋 **Structured investigation reports** — SECTION 1 (evidence) → SECTION 2 (reasoning) → SECTION 3 (verdict).
- 🗂️ **Case management & reports** — group investigations into cases (`INC-0001`…) with severity, status, verdict, and notes; export Markdown or print-ready HTML/PDF.
- 📥 **Webhook alert ingestion** — SIEMs push alerts straight into NullShift's inbox; one click turns an alert into a full investigation.
- 🛡️ **Automatic IOC enrichment** — IPs, domains, and hashes in each message are checked against VirusTotal automatically.
- 🎯 **L1 → L2 handoff mode** — generates ticket-ready summaries with one command.
- 🔧 **Per-user temperature, conversation search, verdict tracking, debug traces.**
- 💻 **CLI for daily ops** — `nullshift start/stop/status/logs`.
- ⚡ **Single-command setup** — no config files, no manual steps.

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
```

## Requirements

- Python **3.11+**
- macOS, Linux, or Windows 10+
- At least one LLM option configured (see below)

Optional: SIEM credentials (Wazuh / LimaCharlie / Splunk / Elastic / Sentinel) and a VirusTotal API key for IOC enrichment.

## LLM Options

NullShift is provider-agnostic. Pick whichever works for your environment:

### 🆓 Claude Agent SDK *(no API key needed)*

If you have a **Claude.ai Pro or Max subscription**, NullShift can drive Claude directly through the local **`claude` CLI** — no API key, no per-token billing. NullShift's setup wizard detects the CLI and walks you through the one-time `claude login`.

Best for individual analysts and homelab SOCs running on a personal Claude subscription.

### 🌐 Cloud API Keys

Paste a key in **Admin → LLM Providers** for any of:

- **Anthropic** (`claude-sonnet-4-6`, `claude-opus-4-7`, etc.)
- **OpenAI** (`gpt-4.1`, `gpt-4o`, etc.)
- **Google Gemini, Groq, xAI, DeepSeek, Perplexity, OpenRouter, Qwen, Kimi**

### 🖥️ Local Ollama *(fully offline)*

Run any Ollama-compatible model locally — `qwen2.5:14b`, `llama3.3:70b`, `deepseek-r1`, `phi4`, etc. **No API key**, no data leaves your network. Configure the Ollama URL in **Admin → LLM Providers**.

> 💡 **Ollama on another machine via Tailscale.** If your GPU lives on a separate box, install Ollama there and connect to it over your Tailscale network — just point NullShift's Ollama URL at the Tailscale IP, e.g. `http://100.x.x.x:11434`. Same setup works for Tailscale Funnel, Cloudflare Tunnel, or any reachable Ollama endpoint.

## Configuration

Almost everything is configured through the **Admin UI** at `/admin` — no restart needed for any setting to take effect.

- **LLM Providers** — pin an active provider, drag-and-drop the fallback chain, paste API keys.
- **Connectors** — SIEM credentials + VirusTotal. Test connection before saving.
- **RAG** — embedding provider, model, live index status.
- **Users** — manage analyst accounts (admin, L1, L2 roles).

Settings are persisted in a SQLite database (`app/data/config.db`). All changes apply immediately thanks to the settings proxy layer in `app/config.py`.

## Case Management & Reports

Turn one-off chats into tracked cases and hand-off-ready reports.

**Create & manage a case**

1. Open an investigation, then click **+ Case** in the top bar.
2. Create a new case or attach the chat to an existing one. Each case gets a sequential number (`INC-0001`, `INC-0002`, …).
3. Open the **Cases** tab in the sidebar to see every case with a severity dot and status badge.
4. Click a case to set **severity** (low / medium / high / critical), **status** (open / investigating / closed), a final **verdict**, and free-form **analyst notes** — and to link or unlink multiple conversations. One case can span many chats.

**Export a report**

From an open case:

- **Export report (HTML)** — opens a clean, print-optimized page. Use your browser's **Print → Save as PDF** for a shareable artifact.
- **Export report (MD)** — downloads `INC-XXXX-report.md` for pasting into a ticket (TheHive, Jira, email).

Reports include case metadata, analyst notes, the **IOC verdict trail** across every linked chat, and the full investigation timeline. All chat content is escaped, so nothing in a conversation can inject markup into the report.

## Webhook Alert Ingestion

Let your SIEM push alerts directly into NullShift instead of analysts pasting them in. Alerts land in a shared **Alerts** inbox (sidebar tab) with a live unread badge. An analyst clicks **Investigate** to auto-create a chat seeded with the alert and run it through the normal pipeline, or **Dismiss** to clear it.

**1. Enable it**

Admin → **Connectors** → **Webhook Alert Ingestion** → **Generate token** → **Save**. Ingestion stays disabled until a token is set.

**2. Point your SIEM at the endpoint**

```
POST /api/alerts/ingest?source=<siem-name>
```

Authenticate with the token in **either**:

- the `X-Webhook-Token: <token>` header *(preferred — kept out of logs)*, or
- a `?token=<token>` query param *(for SIEMs that can't set custom headers)*

The body is any JSON (≤ 128 KB). NullShift auto-extracts a title / severity / source from Wazuh, LimaCharlie, Splunk, Elastic, and generic payload shapes; anything unrecognized still ingests with the full raw payload preserved.

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

> 🔒 A query-param token can appear in the SIEM's own logs — prefer the header where supported, and regenerate the token if it's ever exposed.

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
│   ├── llm.py               LLM provider chain
│   ├── rag.py               Chroma-based playbook retrieval
│   ├── reports.py           Incident report builders (Markdown + HTML)
│   ├── connectors/          SIEM + VirusTotal clients
│   ├── execution/           Investigation pipeline
│   ├── playbooks/           Playbook runner (YAML front-matter)
│   ├── db/                  SQLite stores
│   ├── static/              Logo, favicon
│   └── *.html               UI pages (chat, admin, login, setup)
├── data/
│   └── kb/                  Markdown playbooks (RAG corpus)
├── tests/                   pytest unit tests
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
- ✅ **Case management** *(shipped)* — group multiple investigations into a single case with severity/status/verdict tracking and exportable reports
- ✅ **Inbound webhook alert ingestion** *(shipped)* — SIEMs push alerts into NullShift's inbox
- Webhook notifications (Slack / Teams / email) on verdict reached
- Outbound response actions (block IP, isolate host) from a playbook
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
| ✅ **Production-ready** | **LimaCharlie** | Most thoroughly tested. Recommended for production. |
| ✅ **Production-ready** | **Wazuh** | Most thoroughly tested. Recommended for production. |
| 🧪 **Beta — under active testing** | **Splunk** | Functional. Updates pushed as edge cases are found. |
| 🧪 **Beta — under active testing** | **Elasticsearch** | Functional. Updates pushed as edge cases are found. |
| 🧪 **Beta — under active testing** | **Microsoft Sentinel** | Functional. Updates pushed as edge cases are found. |

If you're using one of the beta connectors and run into a problem, **please tell me** — that's the fastest way to get it fixed and promoted to production-ready status.

## License

NullShift is released under the [Apache License 2.0](LICENSE).

## Author

Built and maintained by **Ahmed Hegazi**.

## Acknowledgments

Developed with AI-assisted engineering by **Claude** ([Claude Code](https://claude.com/claude-code), Anthropic) — feature development, SIEM query-reference knowledge bases, and code review.
