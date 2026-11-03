# CPTC AD Scripts — Quick Reference ("which one do I run now?")

Fast index for mid-competition. One line each. Full detail in **SCRIPTS-REFERENCE.md**.

All scripts share `lib/common.sh`, default their target to the first line of `scope.txt`
(override with `-t`), take domain context from `domain.env` (override with `-d` / `--netbios`
/ `--dc-ip` / `--dc-hostname`), read/write creds in `creds.json`, and append a redacted
record to `~/cptc-logs/master.log`. Add `-q` to silence the screen (the log still gets
everything). Every script supports `-h`/`--help` for a condensed quick-reference.

**Atomic** = runs straight through. **Composite** = pauses between sub-steps (`y`/`n`/`q`).

---

## Typical order through the chain

| Phase | Script | Reach for it when… |
|-------|--------|--------------------|
| Recon | `01_recon.sh` | You have a target/subnet and need open ports + services. Start here. |
| Recon (deep) | `recon_advanced.sh` | Deeper follow-up — AutoRecon fans out per-service enumeration on a host worth the time. |
| Enum (no creds) | `02_enum_nocreds.sh` | Pre-credential: null/guest SMB, RPC, SNMP, Kerberos user enum, DNS. Builds a user list. |
| Get first cred | `asreproast.sh` | You have a username list but no password — grab AS-REP hashes and crack. |
| Get first cred | `kerberoast.sh` | You already have *any* valid cred — roast SPN accounts for a better one. |
| Get first cred | `spray.sh` | You have a userlist + a few candidate passwords — spray safely (lockout-gated). |
| Enum (creds) | `03_enum_creds.sh` | You hold a cred — full LDAP/BloodHound/RID/GPP sweep for attack paths. |
| Analyze paths | `bloodhound_query.sh` | BloodHound data is collected — run high-value Cypher queries (DA paths, roastable, DCSync…). |
| Escalate (ACL) | `dacl_abuse.sh` | BloodHound shows an ACL edge (GenericAll, WriteDACL, ForceChangePassword…). |
| Escalate (deleg) | `delegation_abuse.sh` | RBCD opportunity, or a host with unconstrained delegation to coerce. |
| Escalate (PKI) | `adcs_abuse.sh` | AD CS is present — auto-detect the vulnerable ESC class(es) and exploit them. |
| Loot the DC | `dcsync.sh` | You have replication rights (DA or granted DCSync) — pull hashes incl. krbtgt. |
| Persist | `goldenticket.sh` | You have the krbtgt hash — forge a Golden Ticket (domain persistence PoC). |
| Move | `lateral_shell.sh` | You have working creds and want a shell (WinRM/psexec/wmiexec). |
| Move (reuse) | `cred_spray_internal.sh` | Test a known cred — or all creds — across hosts for reuse (lockout-gated with --all-creds). |
| Loot a host | `snaffler_hunt.sh` | Hunt a share/host you can reach for exposed creds & sensitive files (Snaffler). |
| Loot a host | `local_creds.sh` | On a host you own: local SAM/LSA dump + config-file credential sweep. |
| Local privesc | `hostprivesc.sh` | You're a low-priv user on a Windows host and have WinPEAS output to triage. |
| Any time | `add_cred.sh` | A teammate/phishing/other source handed you a credential — stash it in creds.json. |

---

## One-liners

- **`01_recon.sh`** *(atomic)* — host discovery + full nmap `-p-` service sweep; records open ports to shared state.
- **`recon_advanced.sh`** *(atomic)* — deeper follow-up: runs AutoRecon (its own scan + automatic per-service enumeration) into the loot dir. Slower than `01`; separate from it.
- **`02_enum_nocreds.sh`** *(composite)* — unauthenticated enum: anonymous LDAP attribute harvest (description/info/comment, password-shaped values flagged), SMB null/guest, RPC, SNMP (if 161 open), kerbrute userenum, DNS AXFR/SRV.
- **`03_enum_creds.sh`** *(composite)* — authenticated enum: netexec LDAP users/groups/policy, ldapdomaindump, BloodHound collection, RID-brute, GPP/SYSVOL cpassword, authenticated LDAP attribute harvest (with password flagging), bloodyAD read pass (get search/object/writable), authenticated rpcclient (users/groups/domain/LSA/privs).
- **`kerberoast.sh`** *(atomic)* — request SPN tickets, save hashcat hashes, optional crack, store cracked passwords.
- **`asreproast.sh`** *(atomic)* — AS-REP roast (with or without a cred), save hashes, optional crack, store results.
- **`spray.sh`** *(atomic)* — password-spray a userlist with a mandatory lockout-safety gate (refuses if passwords/account would reach the threshold; `--i-know-the-risk` to override); stores hits.
- **`dacl_abuse.sh`** *(atomic)* — ACL abuse via bloodyAD/certipy: `ForceChangePassword` / `AddMember` / `ShadowCred` / `DCSync` (pick with `-T`).
- **`delegation_abuse.sh`** *(atomic)* — `-m rbcd` (add computer → RBCD → S4U ticket) or `-m unconstrained` (krbrelayx capture + PetitPotam/printerbug coercion).
- **`adcs_abuse.sh`** *(atomic)* — certipy `find -vulnerable`, then auto-detect and exploit whatever ESC class(es) apply (ESC1/2/3/9/10/13/16 via `req`/`auth` → TGT + NT hash; ESC8/11 reported for relay). `--esc`/`--ca`/`--template` to force one.
- **`bloodhound_query.sh`** *(atomic, read-only)* — run predefined high-value Cypher queries (shortest paths to DA, Kerberoastable, AS-REP roastable, unconstrained delegation, DCSync) against BloodHound CE's API; saves results to the loot dir. `--queries` to pick a subset.
- **`dcsync.sh`** *(atomic)* — secretsdump DCSync, `-m full` or `-m single --account`; stores hashes, tags krbtgt, records domain SID.
- **`goldenticket.sh`** *(atomic)* — forge a Golden Ticket from the stored krbtgt hash + domain SID.
- **`lateral_shell.sh`** *(atomic)* — interactive shell via evil-winrm / psexec / wmiexec (`-m auto` picks for you).
- **`cred_spray_internal.sh`** *(atomic)* — credential-reuse scouting: try one stored cred (default) or `--all-creds` across hosts; same lockout gate as `spray.sh` for `--all-creds`. Logs where each identity worked.
- **`snaffler_hunt.sh`** *(atomic)* — run Snaffler (via mono, or on a Windows foothold) against a path/share to surface exposed creds & sensitive files; findings to the loot dir.
- **`local_creds.sh`** *(composite)* — on a host you own: (1) local SAM/LSA dump → creds.json, (2) sweep shares for unattend/web.config/sysprep/config secrets. Pauses between the two.
- **`hostprivesc.sh`** *(composite)* — triage a WinPEAS file down a ranked privesc list, pausing before each; names the staged tool to use.
- **`add_cred.sh`** *(atomic)* — manually add a credential (domain/user/type/value) obtained outside the toolkit into creds.json, via the shared write-helper.

---

## Shared conventions (cheat sheet)

- **Target:** first non-comment line of `scope.txt`, or `-t <ip|cidr|host>` per run.
- **Domain context:** `domain.env` (`DOMAIN`, `NETBIOS`, `DC_IP`, `DC_HOSTNAME`); `BASE_DN` is auto-derived from `DOMAIN`. Override any value per-run with `-d` / `--netbios` / `--dc-ip` / `--dc-hostname`. A missing value is prompted for (one-off; saved back only if you confirm).
- **Domain resolution order:** `-d` flag > `domain.env` > the selected credential's domain. **DC:** `--dc-ip` > `domain.env` `DC_IP` > `--target`.
- **Creds:** `creds.json` (flat JSON array). Scripts auto-pick the first usable one (password > NTLM > AES).
- **Log:** `~/cptc-logs/master.log` — every command + output, **credential values redacted**. Full untrimmed output per run under `~/cptc-logs/runs/<script>-<ts>/`.
- **Loot:** tool artifacts (hashes, dumps, BloodHound bundles, AutoRecon/Snaffler output, query results) land in a per-run folder `~/cptc-loot/<run-id>/`, logged at the start of each run that produces them.
- **Quiet:** `-q` hides live screen output only; the log is identical.
- **Self-check:** `bash lib/common.sh --selftest` proves redaction removes a known secret.
