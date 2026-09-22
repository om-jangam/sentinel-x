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
uv run sentinelx load-demo
```

Expected result: 12 findings and **two** incidents. The first is web-01's SSH spray ending in the `deploy`
login. The second is WS-FIN-07's logon burst, RDP logon, encoded PowerShell, discovery and beaconing (the
Windows and Zeek records join on the host name). Nothing in the evidence connects the two attackers, so they
stay separate. Alice's logins, the morning console logon and the SMB session stay out of both.
