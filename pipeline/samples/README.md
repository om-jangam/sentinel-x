# Demo telemetry

A small, coherent attack story for demos and tests. All addresses use RFC 5737 documentation ranges
and all domains use the reserved `.example` TLD. Nothing here points at real infrastructure.

| File | Parser | Story |
|------|--------|-------|
| `linux_auth.log` | `linux_auth` | SSH password spray against `web-01` from `203.0.113.45`, ending in a successful login as `deploy`; background key-based logins by `alice`. |
| `windows_security.jsonl` | `windows_security` | Failed network logons for `jsmith` on `WS-FIN-07` from `198.51.100.23`, then an RDP logon, encoded PowerShell and discovery commands, then logoff. |
| `ocsf_network.jsonl` | `ocsf` | `WS-FIN-07` beaconing to `192.0.2.66:443` every 60s after resolving `cdn-telemetry-sync.example`. |

Load it into a running stack (timestamps are rebased so events land in the hot tier):

```bash
cd backend
uv run sentinelx load-demo --api-url http://127.0.0.1:8000
```
