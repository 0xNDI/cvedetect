# CVE Detection — Design Notes for a New Tool

Derived from studying `nxc/modules/enum_cve.py` (NetExec) and the NVD/MSRC records for
the target CVEs. This document captures how the existing module detects
vulnerabilities and exactly what is needed to detect the four CVEs below the same way.

---

## 1. How `enum_cve` detects vulnerabilities

`enum_cve` is a **pure patch-level comparison** — it never probes for the actual bug.
Flow:

1. **Get the OS build** from the SMB negotiate response (already populated on the
   connection object):
   `connection.server_os_major`, `server_os_minor`, `server_os_build`
   (e.g. `10.0.26100`).
2. **Get the UBR** (Update Build Revision — the 4th dotted number) over SMB →
   RemoteRegistry:
   - `connection.trigger_winreg()` then bind `\winreg` (`rrp.MSRPC_UUID_RRP`)
   - open `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
   - query the `UBR` `REG_DWORD` value.
3. **Compare** per CVE: each entry has a `patches` dict mapping
   `(major, minor, build) → min_patched_ubr`. `is_vulnerable()` returns
   `ubr < min_patched_ubr`. Unknown build → `None` (skip). `ubr is None`
   (RemoteRegistry off) → skip.
4. **Gates / messaging:** `dc_only` (only check on DCs via `connection.is_host_dc()`),
   and `signing_message` when `connection.conn.isSigningRequired()`.

The module's own disclaimer is the crux:

> *"these checks solely rely on the OS version and UBR reported in the registry,
> and do not check for the actual presence of the vulnerable components or mitigations."*

### Key insight for the new tool

The minimum patched UBR is a property of **(product-build, Patch-Tuesday-month)**,
**not** of the individual CVE. Every flaw fixed in the same monthly cumulative update
for a given build gets the same UBR threshold. Confirmed against the existing module:

- **Oct 2025** → Ghost SPN (`CVE-2025-58726`) uses UBRs
  `7919/6456/4294/6060/1913/6899` — identical to **CVE-2025-55680** below.
- **Jul 2026** → Certighost (`CVE-2026-54121`) uses `9020/5386/33158` — identical to
  **CVE-2026-50343** and **CVE-2026-49176** below.

A cleaner design for the new tool is therefore *"which Patch Tuesday is this host on?"*
→ map to the CVE set, rather than per-CVE tables.

---

## 2. The four target CVEs (all detectable the same way: version + UBR)

All four are **local Elevation-of-Privilege** (CVSS 7.8, `AV:L/PR:L`) — they require
an authenticated low-priv foothold, unlike the current module's network-relay CVEs.
Detection logic is identical to `enum_cve`; the `dc_only` gate does **not** apply.

Patch UBRs below are from NVD CPE configurations (`versionEndExcluding`),
cross-checked against MSRC. `(major, minor, build)` tuples mirror `enum_cve`'s format.

### CVE-2025-55680 — Cloud Files Mini Filter `cldflt.sys` TOCTOU EoP
Patch Tuesday **Oct 14 2025** (same month as Ghost SPN). CWE-367.

```
(10,0,17763): 7919   # Server 2019 / Win10 1809
(10,0,19044): 6456   # Win10 21H2
(10,0,19045): 6456   # Win10 22H2            <- enum_cve omits this; add it
(10,0,20348): 4294   # Server 2022
(10,0,22621): 6060   # Win11 22H2
(10,0,22631): 6060   # Win11 23H2            <- enum_cve omits this; add it
(10,0,25398): 1913   # Server 2022 23H2
(10,0,26100): 6899   # Win11 24H2 / Server 2025  (collision — see caveat)
(10,0,26200): 6899   # Win11 25H2
```

### CVE-2026-42980 — WMI integer-underflow → NT OS Kernel EoP
Patch Tuesday **Jun 9 2026**. CWE-191/122, "Exploitation More Likely."

```
(10,0,14393): 9234   # Server 2016 / Win10 1607
(10,0,17763): 8880   # Server 2019 / Win10 1809
(10,0,19044): 7417   # Win10 21H2
(10,0,19045): 7417   # Win10 22H2
(10,0,20348): 5256   # Server 2022
(10,0,22631): 7219   # Win11 23H2
(10,0,26100): 8655 (Win11 24H2 client) / 32995 (Server 2025)   # collision
(10,0,26200): 8655   # Win11 25H2
(10,0,28000): 2269   # Win11 26H1
```

Sources also mention Server 2012 / 2012R2 (EOL) — NVD lists them with no version
bound, so exclude.

### CVE-2026-50343 — "Dark Elevator", InstallService EoP
Patch Tuesday **Jul 14 2026** (same month as Certighost + WalletService). CWE-269.
Does **not** affect 14393.

```
(10,0,17763): 9020   # Server 2019 / Win10 1809
(10,0,19044): 7548   # Win10 21H2
(10,0,19045): 7548   # Win10 22H2
(10,0,20348): 5386   # Server 2022
(10,0,26100): 8875 (Win11 24H2 client) / 33158 (Server 2025)  # collision
(10,0,26200): 8875   # Win11 25H2
(10,0,28000): 2269 (x64) / 2525 (arm64)   # Win11 26H1
```

### CVE-2026-49176 — WalletService EoP (link-following)
Patch Tuesday **Jul 14 2026**. CWE-59/269. Same UBRs as 50343 **plus** 1607:

```
(10,0,14393): 9339   # Server 2016 / Win10 1607
(10,0,17763): 9020   # Server 2019 / Win10 1809
(10,0,19044): 7548   # Win10 21H2
(10,0,19045): 7548   # Win10 22H2
(10,0,20348): 5386   # Server 2022
(10,0,26100): 8875 (Win11 24H2 client) / 33158 (Server 2025)  # collision
(10,0,26200): 8875   # Win11 25H2
(10,0,28000): 2269 (x64) / 2525 (arm64)   # Win11 26H1
```

---

## 3. Patch-Tuesday → UBR quick reference (shared across CVEs)

Because UBR thresholds are per-(build, month), you can reuse one table per month.

| Build (product) | Oct 2025 | Jun 2026 | Jul 2026 |
|-----------------|----------|----------|----------|
| 14393 (Srv2016/1607) | — | 9234 | 9339 |
| 17763 (Srv2019/1809) | 7919 | 8880 | 9020 |
| 19044 (Win10 21H2)   | 6456 | 7417 | 7548 |
| 19045 (Win10 22H2)   | 6456 | 7417 | 7548 |
| 20348 (Srv2022)      | 4294 | 5256 | 5386 |
| 22621 (Win11 22H2)   | 6060 | — | — |
| 22631 (Win11 23H2)   | 6060 | 7219 | — |
| 25398 (Srv2022 23H2) | 1913 | — | — |
| 26100 (Win11 24H2 client) | 6899 | 8655 | 8875 |
| 26100 (Server 2025)  | 6899 | 32995 | 33158 |
| 26200 (Win11 25H2)   | 6899 | 8655 | 8875 |
| 28000 (Win11 26H1)   | — | 2269 | 2269 (x64) / 2525 (arm) |

---

## 4. What the new tool must handle (gaps vs `enum_cve`)

1. **The `(10,0,26100)` collision is real and matters.** Win11 24H2 client and
   Server 2025 share build `26100` but have **divergent UBR timelines** (Jul 2026:
   client `8875` vs Server `33158`; Jun 2026: client `8655` vs Server `32995`). The
   current module lumps them into one UBR and is therefore wrong for one of the two
   products. The new tool should disambiguate using `connection.server_os`
   ("Windows Server 2025" vs "Windows 11 ...") or `is_host_dc()`. Treat `26100` as
   two keyed entries (server vs client). Same vigilance for `28000`
   (x64 `2269` vs arm `2525`) and `26200` (Win11 25H2 only, no server).

2. **Don't collapse the sibling builds.** Keep both `19044`/`19045` and
   `22621`/`22631` (they share UBRs but are distinct products).

3. **Operational framing differs from the current module.** These are local EoP, so
   the useful report is *"host is at a vulnerable patch level for these local-priv
   CVEs"* — the check still runs from a remote SMB login (just reads UBR), but it's
   only actionable once you have a low-priv local shell. No `signing_message` /
   `dc_only` semantics apply.

4. **Same inherited caveat:** it's a patch-level heuristic, not a confirmation that
   the vulnerable binary (e.g. `cldflt.sys`, `InstallService`, `WalletService`) is
   present/reachable or that no mitigation is in place.

5. **Data source for the tables:** regenerate from MSRC CVRF/CSAF or NVD CPE
   `versionEndExcluding`. The NVD v2 API is the most reliable machine-readable source:
   `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` → iterate
   `configurations[].nodes[].cpeMatch[]` where `vulnerable == true` and product
   contains `microsoft:windows`; the `versionEndExcluding` field is the minimum
   patched UBR for that build.

---

## 5. Minimal detection recipe (pseudo-code)

```python
# inputs from SMB session:
#   major, minor, build  = connection.server_os_{major,minor,build}
#   ubr                  = read from HKLM\...\CurrentVersion!UBR via winreg
#   os_string            = connection.server_os           # to disambiguate 26100
#   is_server_2025       = "Server 2025" in os_string      # or is_host_dc()+build


def key(major, minor, build, is_server_2025=False):
    # split 26100 into two logical keys
    if build == 26100:
        return (major, minor, build, "srv2025" if is_server_2025 else "client")
    return (major, minor, build)


def vulnerable(cve_patches, k, ubr):
    if ubr is None:
        return None  # RemoteRegistry off / unknown
    min_patched = cve_patches.get(k)
    if min_patched is None:
        return None  # product not in scope
    return ubr < min_patched
```

Each CVE entry:

```python
CVE = {
    "alias": "...",
    "patches": { (major, minor, build[, tier]): min_patched_ubr, ... },
    "message": "...",
    "exploitation": "<url>",
    # no dc_only / no signing_message for these local-EoP CVEs
}
```

---

## 6. DC-only domain-takeover CVEs (KerberLoss, ResetNightmare)

Both come from the same Semperis "Identity Crisis" research and exploit **identity
confusion on a Domain Controller** to take over the domain. They are therefore
`dc_only` (only evaluated on a DC, like BadSuccessor) and **server-only**: the
patched component ships to every SKU, but a DC never reports a client build, so only
server builds need a threshold. The `(10,0,26100)` Server-2025 split is keyed
`srv2025` (a 26100 DC is always Server 2025; a Win11 24H2 client is out of scope).

Thresholds come from NVD **`cpeMatch.versionEndExcluding`** — the same field used for
every other CVE here. Server 2012 / 2012 R2 receive **no** `cpeMatch` bound in NVD
(ESU/EOL products), so their thresholds are taken instead from NVD's newer
`affected[].affectedData[].versions[].lessThan`. These legacy DCs are exactly the
real-world targets for a domain takeover and are clearly patched, so they are kept
rather than dropped.

### CVE-2026-25177 — KerberLoss (AD DS name confusion → Kerberos downgrade / takeover)

Patch Tuesday **2026-03-10**. CVSS 8.8 `AV:N/AC:L/PR:L/S:U/C:H/I:H/A:H`. CWE-641.

```
(6,2,9200):   25973   # Server 2012            (affectedData; no cpeMatch bound)
(6,3,9600):   23074   # Server 2012 R2         (affectedData; no cpeMatch bound)
(10,0,14393): 8957    # Server 2016 / Win10 1607
(10,0,17763): 8511    # Server 2019 / Win10 1809
(10,0,20348): 4830    # Server 2022
(10,0,25398): 2207    # Server 2022 23H2
(10,0,26100): 32463   # Server 2025  (srv2025 tier)
```

### CVE-2026-27912 — ResetNightmare (Kerberos UPN/SamAccountName confusion → takeover)

Patch Tuesday **2026-04-14**. A low-priv user with Write/create-object rights over
any user/computer confuses the DC's UPN↔SamAccountName mapping and resets a
privileged account's password → instant Domain Admin.

```
(6,2,9200):   26026   # Server 2012            (affectedData; no cpeMatch bound)
(6,3,9600):   23132   # Server 2012 R2         (affectedData; no cpeMatch bound)
(10,0,14393): 9060    # Server 2016 / Win10 1607
(10,0,17763): 8644    # Server 2019 / Win10 1809
(10,0,20348): 5020    # Server 2022
(10,0,25398): 2274    # Server 2022 23H2
(10,0,26100): 32690   # Server 2025  (srv2025 tier)
```

Same inherited caveat as the rest: this is a patch-level heuristic, not a probe of
the bug. Source:
<https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/>.
