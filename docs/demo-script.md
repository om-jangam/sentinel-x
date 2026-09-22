# Demo script

A 10–12 minute walkthrough of Sentinel-X for a project review, using the two sample attacks. Each step
says what to click, what the audience sees, and what to say.

## Before the audience arrives (15 minutes ahead)

1. Start Docker Desktop and wait until it says it is running.
2. In PowerShell:
   ```powershell
   cd D:\Sentinel-X
   $env:SENTINELX_BOOTSTRAP_ADMIN_PASSWORD = '<your admin password>'
   docker compose --env-file sentinelx.env up -d
   ```
   `sentinelx.env` (in the project folder, never committed) switches on the demo threat-intel feed and the
   AI assistant. To use OTX as well, open it and paste your own key after `SENTINELX_OTX_API_KEY=`. Ollama
   must be running for the AI. Without the file, those two stages show as "not configured".
3. If the Incidents page is empty, load the samples **once**:
   ```powershell
   docker compose run --rm --no-deps -v ./pipeline/samples:/samples:ro api sentinelx load-demo --samples /samples
   ```
   Wait about a minute, then refresh. A second run would add a second copy of each incident.
4. **Run the AI analysis in advance.** On this laptop it takes 2–6 minutes. Open the critical incident,
   **AI analysis** tab, **Analyse with AI**, and let it finish. In the demo you show the stored result.
5. Sign in at http://localhost:8080, press **Ctrl+Shift+R**, and leave the browser on the Overview page.

## The walkthrough

### 1. The problem (1 minute, no clicking)

> "When an attack happens, the evidence is spread across thousands of log lines from different
> machines. An analyst has to work out which lines belong together and in what order. Sentinel-X does
> that reconstruction automatically, and it never claims anything it can't point to in the logs."

Say what it is **not**: not an antivirus, not a firewall. It doesn't block anything; it explains what
happened. (Blocking is the job of the companion project, Aegis.)

### 2. Overview page (1 minute)

Point at **How Sentinel-X works**, left to right:

| Stage | Say |
|-------|-----|
| Collect | "Windows, Linux and network logs converted into one standard format, OCSF, and stored unchanged." |
| Detect | "Fixed, testable rules flag suspicious events. No AI here, so detection is predictable." |
| Correlate | "Findings that share a machine, user or address are joined into one incident, and every join records the events that justify it." |
| Threat intel | "Outside addresses and file hashes are checked against intelligence sources. That's context, never proof." |
| AI explanation | "A local AI model summarises the incident, and code removes anything it can't back up with evidence." |

Then the tiles: **2 open incidents, both high or critical**.

### 3. The critical incident: ws-fin-07 (4 minutes)

Click the **Critical** row under **Needs attention**.

**Header.** Read the title: logon after failures from `198.51.100.23`, then execution, defense evasion,
discovery and command and control on `ws-fin-07`. Point at **Why this severity**: the severity is
explained, not just stated.

**Timeline tab.** Walk down it; this is the story:

1. A burst of failed logons for one account from `198.51.100.23`: password guessing
   (MITRE ATT&CK T1110).
2. Then a **successful** logon from the same address: the guess worked.
3. About two minutes later, PowerShell started with an **encoded command**: hiding what it runs (T1059.001, T1027).
4. Seconds after that, `whoami` and `net group "Domain Admins"`: the attacker looks around (T1033, T1069.002).
5. Then repeated connections to the same outside address: a command-and-control beacon (T1071).

Click any step. The inspector shows the **original log record** behind it.
> "Every step is backed by a stored event. Nothing on this screen is made up."

**Graph tab.**
> "Same evidence, as relationships: the attacker's address, the account, the machine, the processes,
> the outside server. A line only exists if a single log event states that relationship."

**Findings & links tab.** Show why the findings were joined: *shared entity* (same host and account) and
*logon after failures*, each with its events.

**Threat intel tab** (if the env file was used). Each source's answer is shown separately, with when it
was retrieved.
> "One source saying 'malicious' doesn't make Sentinel-X say 'malicious'."

**AI analysis tab.** Show the analysis you ran in advance:
- every statement is labelled **FACT**, **INFERENCE** (with reasoning) or **UNCERTAINTY** (with what's
  missing);
- click a citation to open the real event;
- show **removed items**, if any: what the model said that code threw out because it couldn't be backed
  up.
> "The AI can be wrong, but it cannot show an analyst a claim without evidence behind it."

### 4. Work the incident (1 minute)

Click **Start investigating**, add a note in **Notes**, then **Close incident** as a true positive.
> "Two analysts editing at once can't overwrite each other: the second one is told and reloaded."

### 5. The second incident: web-01 (1 minute)

Back on **Incidents**, open the **High** one: SSH password guessing against `web-01` from
`203.0.113.45` across many accounts, including ones that don't exist, then a success.
> "These are two separate incidents because nothing in the evidence connects them. Merging them would
> mean inventing a relationship."

### 6. Accountability (1 minute)

- **Audit log:** every sign-in and change is listed, including the status change you just made.
  **Re-verify** recomputes the hash chain.
  > "If anyone edits the history in the database, verification shows exactly where."
- **Roles & permissions:** seven built-in roles; a viewer can read, only analysts can ask the AI, and
  only admins manage users. Permissions are checked on every request, not cached in the login.

### 7. Close (30 seconds)

> "Logs in; detection by rules; correlation that cites evidence; a timeline and graph; threat intel as
> context; and an AI that is only allowed to explain what the evidence shows."

## Questions you're likely to get

| Question | Honest answer |
|----------|---------------|
| Is this real attack data? | No. It's two realistic, hand-built scenarios using documentation IP ranges (198.51.100.0/24, 203.0.113.0/24), so nothing real is implicated. |
| Why not let the AI detect attacks? | Rules are predictable and testable. A model can miss or invent. AI explains; it doesn't decide. |
| What if the AI makes something up? | Code checks every citation and every IP or hash it mentions against the evidence and removes what doesn't match. Removed items are kept on record. It can still mislabel an inference as a fact; that's why it's presented for an analyst to check. |
| Which model? | `qwen2.5:3b`, running locally through Ollama, so incident data never leaves the machine. It scored 100% citation validity on both samples. |
| Does it scale? | It's a modular monolith with a Redis Streams worker and OpenSearch for events. Tested with Docker Compose on one machine, not load-tested at scale. |
| Can it stop the attack? | No, by design. Response is out of scope. |
| How is it tested? | 471 backend tests (including PostgreSQL) and 50 frontend tests, plus an AI evaluation (`sentinelx evaluate-assistant`). |

## If something goes wrong

| Symptom | Fix |
|---------|-----|
| `required variable SENTINELX_BOOTSTRAP_ADMIN_PASSWORD is missing` | Set it in this PowerShell window (step 2). |
| `no configuration file provided` | You're in the wrong folder: `cd D:\Sentinel-X`. |
| "Invalid email or password" | Wrong password. After 10 wrong tries, wait 5 minutes (rate limit). |
| Page looks old or a link is missing | Ctrl+Shift+R. |
| AI analysis says unavailable | Ollama isn't running, or the env file wasn't passed. Show the analysis you ran in advance. |
| Threat intel tab says not configured | The env file wasn't passed. Say it's optional and move on. |
