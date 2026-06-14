# Security Policy

NullShift handles SIEM credentials, analyst investigations, and security telemetry — reports of vulnerabilities are treated as a priority and triaged ahead of normal feature work.

## Supported Versions

Only the latest minor release receives patches.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately by either:

- Emailing the maintainer at **ahmedislam23@gmail.com**
- Or using GitHub's [private vulnerability reporting](https://github.com/hegazi-sec/nullshift/security/advisories/new) feature on this repository

### What to Expect

- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Fix released** within 30 days for high-severity issues, sooner for critical
- **Credit** in the release notes and CHANGELOG (unless you prefer to remain anonymous)

## In Scope

Reports are welcome for:

- Authentication / authorization issues (JWT, session management, role checks)
- Data leakage from `config.db`, `chat.db`, or the RAG vector store
- Injection vulnerabilities in tool execution paths or LLM prompt boundaries
- Vulnerabilities in the dependency chain (Python packages, ChromaDB, etc.)
- Cross-user data access (one analyst seeing another's conversations or verdicts)
- Bypasses of the tool allowlist in `app/execution/tool_runner.py`

## Out of Scope

- Self-XSS requiring local console access
- Issues that require admin credentials to exploit (NullShift assumes the admin is trusted)
- Denial of service via API rate limit abuse from an authenticated session
- Findings against deprecated `0.0.x` development builds

## Deployment Security Considerations

NullShift is designed for use **inside a trusted SOC environment** behind a VPN or zero-trust network. If you expose NullShift to the open internet, you take on additional responsibility:

- Terminate TLS at a reverse proxy (nginx, Caddy, Traefik)
- Place the server behind an authenticating proxy (Cloudflare Access, Tailscale Funnel)
- Rotate the JWT secret periodically
- Restrict admin endpoints to specific IPs at the network layer
- Keep dependencies up to date — Dependabot is enabled on this repository

## Sensitive Data Handling

- API keys, SIEM credentials, and the JWT secret live in `app/data/config.db` (SQLite, file mode 0600). They never leave the host.
- Analyst conversations are stored in `app/data/chat.db` scoped per user.
- LLM requests are sent to the provider you configure — NullShift does not send telemetry to any third party.

— Ahmed Hegazi
