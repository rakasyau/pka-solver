---
name: pka-solver-local
description: "Use when working with Cisco Packet Tracer .pka/.pkt assignment files — decrypting them, reading the answer key or assessment rubric, producing a completed 100% file, or opening one in Packet Tracer. Works fully locally with no Docker and no AI. Gunakan saat mengerjakan soal Packet Tracer .pka: decrypt, baca rubrik assessment, buat file 100%, atau buka di Packet Tracer — lokal tanpa Docker."
---

# pka-solver-local

Solve Cisco Packet Tracer `.pka` activities locally. Pure Python, no Docker,
no LLM in the solving path.

Plugin: `C:\Users\rakas\AppData\Local\hermes\plugins\pka-solver\`
Full reference: `CONFIGURATION.md` inside that folder.

## Desktop app (Hermes Desktop)

Three unrelated plugin systems exist in Hermes — they share no code:

| Half | File | Gives you |
|---|---|---|
| agent | `plugin.yaml` | the `pka_*` tools |
| dashboard | `dashboard/plugin_api.py` | REST at `/api/plugins/pka-solver/` |
| desktop | `desktop/plugin.js` | sidebar row + `/pka-solver` page |

One folder serves all three. The desktop half registers a route and a
`SIDEBAR_NAV_AREA` row, loaded uncompiled from
`$HERMES_HOME/desktop-plugins/<id>/plugin.js`.

The desktop app loads plugins at startup — **restart the app** after adding
or changing `plugin.js`. If it doesn't show up: ⌘K → Reload desktop plugins,
or Rescan on the Plugins page.

The desktop half's backend is gated twice, by design:
- `dashboard/plugin_api.py` is imported only when the plugin is in
  `plugins.enabled` in config.yaml;
- the app holds a per-process session token, so a bare `curl` to these
  routes gets 401. Use the UI, not curl, to check them.

Backend routes restrict file access to an allow-list of coursework roots. A
browser-reachable route that decrypts arbitrary paths would be a file-read
primitive, so widen `ALLOWED_ROOTS` deliberately if you need it.

## Workflow

```bash
cd C:/Users/rakas/AppData/Local/hermes/plugins/pka-solver

# 1. what is this file? devices, addressing, instructions, rubric
python -c "import tools; print(tools.pka_inspect({'path':'SOAL.pka'}))"

# 2. produce the completed file (+ markdown report), open in PT
python -c "import tools; print(tools.pka_solve({'path':'SOAL.pka','open':True}))"

# 3. confirm the expected config actually landed
python -c "import tools; print(tools.pka_verify({'path':'SOAL-SOLVED.pka','must_contain':['router ospf']}))"
```

From inside Hermes, call the tools directly instead: `pka_inspect`,
`pka_solve`, `pka_verify`, `pka_doctor`.

## PKA → XML only

`pka_decrypt` is the converter with no grading step: it decrypts and writes
`<filename>.pka.xml` beside the source, returning `output`, `xml_bytes`,
`blocks`, `pt_version`. The UI exposes it as the **PKA → XML** button, backed
by `POST /api/plugins/pka-solver/to-xml`. A 17 MB XML from a 1 MB `.pka`.
It also auto-detects legacy `.pkt` XOR format, `.nets`, and log files,
reporting the mode instead of writing XML.

Two things make it time out if you change them:

- **Keep the route handlers `def`, never `async def`.** FastAPI runs `async
  def` on the event loop, so the decrypt blocks every other route — including
  the `/api/status` liveness poll — and the desktop app reports "Timed out
  connecting to Hermes backend". Sync `def` goes to the threadpool.
- **Raise `timeoutMs` in the UI.** `ctxRestPost` sends 300000; the desktop
  fetch default is 30 s (an idle-socket ceiling, not a total budget).

Speed comes from the native Twofish, not from any of the above: pure-Python
is ~6x slower (3.2s vs 0.5s on a 1 MB `.pka`). If `pka_doctor` still reports
`twofish_backend: twofish-pure`, the `_twofish.cp3XX-*.pyd` is not in the site-
packages of the interpreter that actually serves the backend. On Windows the
bundled interpreter's folder name contains a literal `*`, so never glob it in a
shell to write into it — resolve the path with
`sysconfig.get_paths()['platlib']` or `find -name` instead.

`pka_solve` parameter names are `path`, `output`, `report`, `fix_interfaces`,
`open_after` — not `out`/`open`.

## What the solver actually does

It does not invent an answer. It moves the answer key that is already inside
the file (block 2 of 3 `<PACKETTRACER5>` blocks) into the workspace, adds the
`no shutdown` the key omits, and re-encrypts.

Packet Tracer stores no score. It grades at runtime by comparing device
configs against the `<COMPARISONS>` tree, so 100% means the config matches —
there is no score tag to set.

## Reading the assessment

`pka_inspect` returns `rubric` — the graded leaves of `<COMPARISONS>`, each
with `path`, `points`, `check_type`, `expected`.

Ignore `check_type == 0`. A typical activity has ~18000 COMPARISONS nodes
but only ~75 real graded items; `rubric` already filters to the latter.

Filter for real items:

```python
items = insp.graded_items(xml)      # checkType != "0" only
```

## Rules that matter

- **Write the graded state into all three blocks.** PT boots and grades from
  block 0 and may reset the workspace on open; patching only the answer key
  scores 0% everywhere.
- **Never transplant individual sections.** Replace whole blocks. Sections
  are cross-referenced by per-block device IDs and partial edits give
  "corrupted Physical Workspace data".
- **Block 0 keeps its own `<VERSION>` and `<PIXMAPBANK>`**, otherwise the
  canvas comes up blank.
- **Keep each block's own IDs, serials, MAC/BIA, coordinates and links.**
- **`no shutdown` goes in as `<LINE> no shutdown</LINE>`** (with the leading
  space). Grepping `<LINE>no shutdown` finds nothing.

## The two EAX details people get wrong

```
OMAC_0 = OMAC_K(0^15 ‖ 0x00 ‖ N)      # zero-prefixed, domain-separated
OMAC_1 = OMAC_K(0^15 ‖ 0x01 ‖ H)      # header, empty in .pka
OMAC_2 = OMAC_K(0^15 ‖ 0x02 ‖ C)
tag    = OMAC_0 ⊕ OMAC_1 ⊕ OMAC_2
C      = CTR_K(iv = OMAC_0)(M)        # counter starts AT OMAC_0, not 0
```

Getting the zero-prefix or the counter start wrong yields a plausible
implementation that fails with a bad tag on every file.

## Verifying a change to the crypto layer

```bash
python selftest.py "SOAL.pka"
```

Four layers: Twofish KAT (book B.2, I=3), native-vs-pure backend parity,
EAX against pycryptodome across 14 header/length combinations, and a
real-file roundtrip. The pycryptodome check skips cleanly when that package
is absent — a skip, not a failure.

`encrypt_pka` output may differ from the original in bytes because zlib
levels differ between Python builds. The invariant to assert is
`decrypt_pka(encrypt_pka(xml)) == xml`.

## When it does not work

- **`EAX tag verification failed`** — wrong file, wrong PT version, or
  corrupt. Check the reported version via `pka_inspect`.
- **`expected 3 <PACKETTRACER5> blocks`** — not a `.pka` activity file; it
  may be a `.pkt` topology.
- **`block 2 holds no RUNNINGCONFIG`** — the file has no answer key. It has
  never been graded. Read the instructions with `pka_inspect` and configure
  the devices by hand.

Use the `pka-solver` skill instead when the task is to author a `.pka` from
scratch (XML building, packets, cabling); this skill is for reading and
finishing existing ones.