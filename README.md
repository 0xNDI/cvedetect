# cvedetect

Detect Windows **local Elevation-of-Privilege** patch-level CVEs over SMB by reading
the OS build (from the SMB negotiate response) and the **UBR** (Update Build
Revision) from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion!UBR` via
RemoteRegistry.

It is the same pure patch-level heuristic NetExec's `enum_cve` module uses — it does
**not** probe for the actual bug, does **not** verify the vulnerable component is
present, and does **not** check for mitigations. The only novelty over `enum_cve` is
correct disambiguation of the `(10,0,26100)` build collision (Win11 24H2 client vs
Server 2025, which have divergent UBR timelines).

These CVEs are all `AV:L/PR:L` (CVSS 7.8): the check runs remotely over an
authenticated SMB login, but is only actionable once you hold a low-priv local shell.

## Install

```bash
uv tool install git+https://github.com/0xNDI/cvedetect   # installs the `cvedetect` command
# or run without installing:
uvx --from git+https://github.com/0xNDI/cvedetect cvedetect --help
```

## Authentication

Identical to impacket's `smbclient.py`:

```
cvedetect [[domain/]username[:password]@]<target> [options]
```

| Option       | Meaning                                                                  |
|--------------|--------------------------------------------------------------------------|
| `-hashes`    | NTLM hashes, `LMHASH:NTHASH`                                             |
| `-no-pass`   | Don't prompt for a password (useful with `-k`)                           |
| `-k`         | Kerberos auth (ccache via `KRB5CCNAME`, or CLI creds)                    |
| `-aesKey`    | AES key for Kerberos (128/256 bit)                                       |
| `-dc-ip`     | Domain controller IP (Kerberos)                                          |
| `-target-ip` | Target IP (defaults to the address in `target`)                         |
| `-port`      | SMB port, `139` or `445` (default `445`)                                 |

## Usage

```bash
# password
cvedetect alex.turner:'Checkpoint2024!'@checkpoint.htb

# NetLM/NT hash
cvedetect -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 user@dc01

# Kerberos
KRB5CCNAME=/tmp/user.ccache cvedetect -k user@DC01.CORP.LOCAL

# filter to specific CVEs and show exploitation refs
cvedetect -c CVE-2026-50343,CVE-2026-49176 -e user@10.10.10.10

# list the CVE database without connecting
cvedetect --list

# machine-readable JSON output for automation
cvedetect --json user@10.10.10.10
```

## Covered CVEs

Detection is a pure version+UBR patch-level comparison (same heuristic as
NetExec's `enum_cve`). It does **not** probe the bug or verify the vulnerable
component is present.

**Network / relay / DC / AD-CS** (ported from `enum_cve`):

| CVE            | Alias            | Notes                                     |
|----------------|------------------|-------------------------------------------|
| CVE-2025-33073 | NTLM reflection  | signing-aware message                     |
| CVE-2025-58726 | Ghost SPN        | signing-aware message                     |
| CVE-2025-54918 | NTLM MIC Bypass  | DC-only                                   |
| CVE-2025-53779 | BadSuccessor     | DC-only                                   |
| CVE-2024-49019 | ESC15 / EKUwu    | AD-CS                                     |
| CVE-2026-54121 | Certighost       | AD-CS; 26100 keyed Server-2025-only       |

**Local Elevation-of-Privilege** (CVSS 7.8, `AV:L/PR:L`):

| CVE            | Alias                                        | Patch Tuesday |
|----------------|----------------------------------------------|---------------|
| CVE-2025-55680 | Cloud Files Mini Filter (`cldflt.sys`) EoP   | 2025-10-14    |
| CVE-2026-42980 | WMI integer-underflow → NT Kernel EoP        | 2026-06-09    |
| CVE-2026-50343 | "Dark Elevator" (`InstallService`) EoP       | 2026-07-14    |
| CVE-2026-49176 | `WalletService` link-following EoP           | 2026-07-14    |

The `(10,0,26100)` collision (Win11 24H2 client vs Server 2025) is disambiguated
from the SMB negotiate OS string — unlike `enum_cve`, which lumps it and is wrong
for one of the two products.

## Output

By default only **vulnerable** CVEs are printed, one line each:

```
$ cvedetect checkpoint.htb/alex.turner:'Checkpoint2024!'@checkpoint.htb
cvedetect — Windows patch-level CVE detection over SMB (heuristic)
Target  Windows 11 / Server 2025 Build 26100  (10.0.26100.32860)  signing=required DC
CVE-2026-54121 Certighost                          (UBR 32860 < 33158)
CVE-2026-42980 WMI integer-underflow -> NT Kernel EoP  (UBR 32860 < 32995)
CVE-2026-50343 Dark Elevator (InstallService) EoP  (UBR 32860 < 33158)
CVE-2026-49176 WalletService link-following EoP    (UBR 32860 < 33158)
```

`-e/--exploitation` appends the exploitation reference to each line. `--list`
prints the full reference table (no connection).

### JSON mode

`--json` emits machine-readable JSON (no colors/markup) for automation. It works
with a target scan or `--list --json` (full CVE database). On errors it emits
`{"error": ...}` with the appropriate exit code instead of a human message.

```
$ cvedetect --json checkpoint.htb/alex.turner:'Checkpoint2024!'@checkpoint.htb
{
  "target": "checkpoint.htb",
  "os": "Windows 11 / Server 2025 Build 26100",
  "major": 10,
  "minor": 0,
  "build": 26100,
  "ubr": 32860,
  "version": "10.0.26100.32860",
  "signing_required": true,
  "is_dc": true,
  "tier": "server-2025",
  "vulnerable": true,
  "warnings": [],
  "cves": [
    {
      "cve": "CVE-2026-54121",
      "alias": "Certighost",
      "ubr": 32860,
      "patched_ubr": 33158,
      "message": "AD-CS; 26100 keyed Server-2025-only",
      "dc_only": true,
      "msrc": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121"
    }
  ]
}
```

Each CVE entry includes `ubr` (detected) vs `patched_ubr` (the fix threshold);
add `-e` to also include an `exploitation` field per CVE.

## Exit codes

| Code | Meaning                                            |
|------|----------------------------------------------------|
| 0    | Scan completed (CVEs decided, vulnerable or not)   |
| 1    | Usage error / invalid target                       |
| 2    | SMB login / connection failure                     |
| 3    | Nothing could be decided (no UBR, out of scope)    |
