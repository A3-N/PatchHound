# PatchHound

Credential importer + “Owned” tagging for **BloodHound Community Edition (CE)**.

> Inspired by [knavesec/Max](https://github.com/knavesec/Max)

![screenshot](img/11.png)

---

## TL;DR

- **auth** — log in to BloodHound CE and cache a JWT (used by other commands for API).
- **patch** — read a **potfile** (cracked creds) + **NTLM file**, parse, stats, and update graph nodes in Neo4j.  
- **policy** — offline password audit using the same **potfile** + **NTLM file**; no Neo4j or API needed.
  - Always sets:
    - `Patchhound_has_hash` **(bool)**
    - `Patchhound_has_pass` **(bool)** – true when a cracked password is known
  - With `-t/--temp` **also** writes (temporary values):
    - `Patchhound_nt`  – NTLM hash
    - `Patchhound_pass` – plaintext password  
    _These two are expected to be ephemeral; BloodHound CE does not persist custom node props across container restarts by default._
  - With `-o/--owned` **after** patching, discover eligible SIDs via **Neo4j** and then **append** “Owned” selectors via the BloodHound **v2 HTTP API**.  
    - Lookups (who to own) happen **only in Neo4j**; the API is used **only** to append the Owned selectors.

Colors can be disabled with `--no-color`. 
Verbose output via `-v`, I love verbose, can't miss an import.

![screenshot](img/5.png)

---

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install neo4j requests
```

Defaults live in **`src/conn.py`**:
- `DEFAULT_URI`
- `DEFAULT_USER`
- `DEFAULT_PASS`  (BH CE default is `bloodhoundcommunityedition`)

You can override these defaults directly via the CLI flags `--db-uri`, `--db-user`, and `--db-pass`.

---

## Usage

### Help
```bash
python3 PatchHound.py --help
python3 PatchHound.py [--no-color] [subcommand] -h
```

### 1) Authenticate (stores JWT for other commands)
```bash
python3 PatchHound.py auth -u http://localhost:8080/ -U admin -p 'Exclude -p for PassPrompt' [-v]
```
- Writes a session file at: `${TMPDIR}/patchhound.session.json`
- Stores the BloodHound username with the JWT so long `patch -o` runs can renew an expired token.

### 2) Patch (parse files, set minimal flags; optional temp writes)
```bash
python3 PatchHound.py patch -c crack.potfile -n ntds.txt [-t] [-o] [-v]
```

For unattended long `-o/--owned` uploads, provide API renewal credentials through environment variables instead of putting the API secret in shell history:

```bash
export PATCHHOUND_API_USER=admin
export PATCHHOUND_API_PASS='BloodHound password or secret'
python3 PatchHound.py patch -c crack.potfile -n ntds.txt -o
```

**What it reads**
- `-c/--clears` **potfile** — expected format: `<32hex_ntlm>:<password>`  
  - `$HEX[...]` values are decoded; in verbose you’ll see lines like:
    ```
    nthash:$HEX[hex...]:decoded-password
    ```
  - Any line that doesn’t match the expected schema is **excluded** and listed (verbose) with a reason.
- `-n/--ntlm` **hash file** — consumes lines containing one or more 32-hex NTLMs and an account token:
  - prefers `DOMAIN\SAM`; captures explicit UPN tokens where present; **synthesizes** UPN as `SAM@fqdn` when possible.
  - Non-conforming lines are excluded with reasons (verbose).

**How matching works (Neo4j)**
- By default, PatchHound builds a local lookup of BloodHound `User`, `AZUser`, and `Computer` nodes once, matches input rows in Python, and then writes matched nodes back to Neo4j by node ID in large batches. This avoids repeated Cypher scans for large NTDS imports.
- Matching still follows the same fields:
  - `(:User {name})`
  - `(:User).samaccountname`
  - `(:User).userprincipalname | userPrincipalName`
  - `(:AZUser).userprincipalname | userPrincipalName`
  - `(:Computer).samaccountname`
- Comparisons for SAM/UPN are case-insensitive (`toUpper` on both sides).  
- Nodes are de-duplicated and updated idempotently.

**What gets written**
- Always:
  - `Patchhound_has_hash = true`
  - `Patchhound_has_pass = (pwd != null)`
- With `-t/--temp`:
  - `Patchhound_nt = <ntlm>`
  - `Patchhound_pass = <password>`

**Output**
- Non-verbose:
  ```
  [+] JWT valid
  [+] Potfile Check
  [+] NTLM Check
  [+] Neo4j auth OK
  [+] Waiting for Neo4j
  Applying [████████████████████████████] 14598/14598 (100%)
  [+] Updated nodes: 1234
  ```
- Verbose also prints pretty stats, decoded HEX, and excluded input lines.

### 3) “Owned” append via API (with `-o`)
- After patching (or even when nothing is applied), `-o` will:
  1. Query **Neo4j** for users where `Patchhound_has_pass = true` and a non-empty SID (`u.objectid`).
  2. Count how many of those SIDs have a matching `:AZUser` on‑prem SID (several property names supported).
  3. Best-effort query existing Owned selectors and skip duplicate SIDs on re-runs.
  4. **Append** those SIDs to the configured **asset group tag** via BHCE v2 API.
  5. Renew the BHCE token and retry the in-flight selector if the API returns `401`.

- For large imports, use `--owned-seeds-per-selector` to group many SID seeds into each selector request. This can reduce API calls by orders of magnitude. A value of `100`–`500` is usually appropriate when the BloodHound API accepts multi-seed selectors.

- Non-verbose:
  ```
  [+] Waiting for Neo4j and API
  Owned API [████████████████████████████] 1876/1876 (100%)
  [+] Owned API: attempted 1876/1876 seed(s) in 4/4 request(s), added 1800, already existed 76, failed 0, pre-skipped 0, 429 retries 3
  ```

- Verbose final summary (printed **after** all logic):
  ```
  [*] Owned summary:
      users_with_password_true  : 1876
      with_sid                  : 1876
      distinct_sids_sent        : 1876
      sids_with_azuser_link     : 0
      asset_group_tag_id        : 2
      owned_attempted           : 1876
      owned_added               : 1800
      owned_existing_or_conflict: 76
      owned_pre_skipped         : 0
      owned_failed              : 0
      owned_429_retries         : 3
      owned_selector_requests   : 4/4
      example_request:
        POST http://localhost:8080/api/v2/asset-group-tags/2/selectors
        payload: {"name":"PatchHound Owned 20260923123456 000001","seeds":[{"type":1,"value":"S-1-5-21-..."},{"type":1,"value":"S-1-5-21-..."}]}
  ```

---

### 4) Policy (offline password audit)
```bash
python3 PatchHound.py policy -c crack.potfile -n ntds.txt [-e] [-v]
```

Runs entirely offline — no Neo4j, no API, no session required.  
Correlates the potfile against the NTLM dump and prints a tabular audit covering:

- **Overview** — total accounts, cracked vs. uncracked, empty/blank passwords, unique password count. Use `--enabled` to restrict every report to entries marked `(status=Enabled)`.
- **Password Length Distribution** — bucketed counts (1-4, 5-7, 8-10, 11-14, 15+ chars).
- **Top Reused Passwords** — most shared passwords across accounts.
- **Service / Privileged Accounts** — cracked accounts whose SAM name contains `svc`, `admin`, `sql`, `backup`, `adm`, or `dev`.
- **Recurring Patterns** — most frequent substrings (3-12 chars) found across passwords (e.g. `@123`, `corp`, `2024!`).
- **Special Character Usage** — per-character frequency table for punctuation/symbols.

With `-v`, a full table of every cracked account and its password is appended at the end.

---

## Flags (current)

- `-v, --verbose` — verbose output (stats, excluded lines, HEX decodes, summaries)
- `--no-color` — disable colored/ASCII output
- `patch`:
  - `-c, --clears` — path to potfile (**required**)
  - `-n, --ntlm` — path to NTLM hash file (**required**)
  - `-t, --temp` — write `Patchhound_nt` and `Patchhound_pass`
  - `-o, --owned` — append “Owned” selectors via API based on Neo4j discovery
  - `--db-uri`, `--db-user`, `--db-pass` — override Neo4j connection defaults
  - `--owned-seeds-per-selector` — group multiple SID seeds into each Owned selector request
- `auth`:
  - `-u, --url`
  - `-U, --username`
  - `-p, --password`
- `policy`:
  - `-c, --clears` — path to potfile (**required**)
  - `-n, --ntlm` — path to NTLM hash file (**required**)
  - `-e, --enabled` — include only NTDS entries marked `(status=Enabled)`

---

## Screenies

![s1](img/7.png)
![s2](img/8.png)
![s2](img/9.png)
![s3](img/12.png)
![s4](img/10.png)
