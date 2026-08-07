# AGENTS.md

Guidance for AI coding agents (and human contributors) working on **cvedetect**.

## What this tool is

A patch-level CVE detector over SMB. It reads a host's OS build + UBR (the 4th
dotted number, via RemoteRegistry) and compares `ubr < min_patched_ubr` against
per-CVE tables. It is a **pure version heuristic** — it never probes for the bug or
any mitigation. Detection == "host is on a patch level below the fix."

## Repo orientation

| Path | Role |
|------|------|
| `cvedetect/cvedb.py` | **The data.** `Cve` dataclass + `CVE_DATABASE` patch tables. This is where almost every edit lands. |
| `cvedetect/detector.py` | `evaluate()`, `host_key()`, `HostInfo`. |
| `cvedetect/reporter.py` | Human + `--json` output. |
| `tests/test_detector.py` | Locks exact UBR values + tier disambiguation. |

## Adding a CVE — how to find the correct UBR thresholds

This is the error-prone part. Two bugs we shipped (CVE-2025-54918 missing a row;
CVE-2025-53779 using the hotpatch value) both came from skipping this discipline.

### Source hierarchy (most → least authoritative)

1. **MSRC page** — `https://msrc.microsoft.com/update-guide/vulnerability/<CVE>`.
   The **"Released"** date is the authoritative Patch-Tuesday month. Do **not** trust
   memory or blog timing (BadSuccessor looked like a late-2025 fix but MSRC says
   Aug 12 2025).
2. **KB support pages** (`support.microsoft.com/.../help/<KB>`) and **Windows
   release-health** (`learn.microsoft.com/en-us/windows/release-health/...`). These
   give the exact OS build the monthly cumulative installs. **This is the ground
   truth for the threshold value.**
3. **NVD CVE API** `versionEndExcluding` — a good starting point and usually right,
   **but** it carries a hotpatch trap (see below). Never trust it alone for Server
   2022 / Server 2025.

### ⚠️ The hotpatch trap (the single most important lesson)

NVD's `versionEndExcluding` for **Server 2022 (`20348`) and Server 2025 (`26100`)**
sometimes cites the **Azure hotpatch** build instead of the standard Patch-Tuesday
cumulative that real hosts install. The hotpatch is *lower* (by ~60–100), so using
it makes the tool report hosts as patched when they are still vulnerable
(false negative). NVD is **sporadically** wrong here — correct for some months,
wrong for others — so each Server value must be checked individually.

**Always confirm a Server 2022/2025 value against the KB support page.** Examples
we hit during the audit:

| Product / month | Standard cumulative — **USE THIS** | Azure hotpatch (NVD) |
|---|---|---|
| Srv2022 Jun 2025 | KB5060526 → `20348.3807` | `20348.3745` |
| Srv2022 Sep 2025 | KB5065432 → `20348.4171` | `20348.4106` |
| Srv2025 Aug 2025 | KB5063878 → `26100.4946` | `26100.4851` |
| Srv2025 Mar 2026 | KB5078740 → `26100.32522` | `26100.32463` |

Client builds (24H2 client, Win10/11, Server 2016/2019) have no hotpatch, so there
NVD = standard and is reliable.

### Finding the standard cumulative build for a month

- KB support-page URL pattern:
  `support.microsoft.com/.../servicing/os/windows-server/<YYYY>/<MM>/<month>-<day>-<YYYY>-kb<KB>-os-build-<build>-<UBR>`.
- The release-health *resolved-issues* pages cite each month's KB + resulting build
  (e.g. "OS Build 26100.32995 [KB5094125]").
- The NVD-vs-cvedb diff script used in the audit (NVD JSON cached in `/tmp`) flags
  every value where cvedb ≠ NVD; after an edit, every remaining divergence must be a
  deliberate standard-cumulative override you can justify with a KB number.

### The shared-month property (free cross-check)

The threshold is a property of **(build, Patch-Tuesday-month)**, not the individual
flaw: every bug fixed in the same month's cumulative for a given build shares one
UBR. Exploit this to catch errors — if two CVEs are the same month + same build,
their UBRs **must** match. This is how we discovered CVE-2025-33073 was really
June 2025, not September (its values disagreed with the same-month CVE-2025-54918).

### Tier rules (build collisions)

Build numbers collide and **must** be disambiguated with a 4th tuple element
(`tier`):

- **`26100`** → `"client"` (Win11 24H2) vs `"srv2025"` (Server 2025). Their UBR
  timelines diverged hard by 2026 (client ~8xxx, Server 2025 ~32xxx). Store separate
  tiered values when they differ (e.g. 42980: client `8655` / srv2025 `32995`).
  - For a **server-only / `dc_only`** flaw, key `26100` as `"srv2025"` **only**
    (Certighost, BadSuccessor, KerberLoss, ResetNightmare) — a Win11 24H2 client is
    out of scope. nxc wrongly lumps these and false-flags clients.
  - For 2024–2025 relay CVEs, client and Server 2025 were UBR-*aligned*, so a single
    un-tiered (`None`) value is correct for that era.
- **`28000`** → `"x64"` vs `"arm"` (Win11 26H1). Architecture isn't reliably exposed
  over SMB: x64 is assumed; `arm` only when the OS string says so. NVD lists both
  UBRs — map them to both tiers.
- Everything else → `None` tier (unambiguous build).

### Don't drop sibling builds

Always include **both** of a pair when the product is affected — they are distinct
SKUs and omitting one is a silent false-negative on those hosts (nxc omits these in
several places):

- `19044` (Win10 21H2) **and** `19045` (Win10 22H2) — same UBR.
- `22621` (Win11 22H2) **and** `22631` (Win11 23H2) — same UBR.

### `dc_only` / server-only scoping

- `dc_only=True` → evaluated only on DCs. A DC never reports a client build, so for
  `dc_only` CVEs list **only server builds** (no `19044`/`22621`/`26200`/`28000`
  client rows).
- Server-only AD-CS flaws (e.g. Certighost) aren't `dc_only` but should be keyed
  `srv2025`-only to avoid false-flagging clients.

### EOL / ESU builds (`6003`, `7601`, `9200`, `9600`)

Server 2008/R2 and 2012/2012 R2 get **no** NVD `cpeMatch` bound. Source them from
NVD `affected[].affectedData[].versions[].lessThan` or MSRC. These are inherently
fuzzy (ESU products): 2012/R2 (ESU extended ~2026) are real targets; 2008/R2 (ESU
ended 2023) are effectively unpatchable — any UBR is "vulnerable." Keep them, don't
strive for exactness.

## The `patch_tuesday` field

Set to the actual Patch-Tuesday date from MSRC's "Released" field (`YYYY-MM-DD`).
It is **metadata only** (shown in `--list`, not used for detection) but keep it
correct — three were wrong in the original data (33073 Sep→Jun; 49019 Dec→Nov;
53779 Jan→Aug).

## Add-entry checklist

1. Add a `Cve(...)` block in `cvedetect/cvedb.py` — builds sorted ascending, inline
   `# product` comments, matching the existing style.
2. Append it to `CVE_DATABASE` (order: relay / DC / AD-CS first, then local EoP).
3. Add exact-value cases to the `test_threshold_values` parametrize in
   `tests/test_detector.py` — at minimum the `26100` client/srv2025 tiers, the
   `28000` x64/arm tiers, and any build you had to verify against a KB.
4. Add an `evaluate()` regression test: a low-UBR real host → `vulnerable is True`;
   at the threshold → `vulnerable is False`.
5. Add the CVE id to `test_all_cves_present` if it's new.
6. `python -m pytest tests/test_detector.py -q` — must stay green.

## Common mistakes to avoid

- Trusting NVD `versionEndExcluding` for Server 2022/2025 without a KB cross-check
  (hotpatch trap).
- Copying nxc's tables verbatim — they omit `19045`/`22631`, and inherited the same
  hotpatch/NVD errors. cvedb is a strict superset + corrections.
- Forgetting a build pair (`19044` without `19045`, etc.).
- Keying a server-only / `dc_only` flaw on the un-tiered `26100` so it false-flags
  Win11 24H2 clients.
- Setting `patch_tuesday` from memory instead of MSRC's "Released" date.
