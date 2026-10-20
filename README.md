# PKA Solver

A [Hermes Agent](https://hermes-agent.nousresearch.com/docs) plugin that works with
Cisco Packet Tracer `.pka` / `.pkt` assignments **entirely offline**: no Docker, no
WSL, no C++ toolchain, no AI in the solving path.

It decrypts a `.pka` to plain XML, reads the answer key and the assessment rubric
that ship inside the file, writes a completed `.pka` that grades 100%, and renders
a Markdown walkthrough of the configuration it applied.

```
.pka ──decrypt──> XML ──inspect──> devices · links · instructions · rubric
                      │
                      ├── to XML      (plain, for reading or diffing)
                      └── solve       ──> *-SOLVED.pka  (grades 100%)
                                          *-SOLVED.md   (config walkthrough)
```

## Why it exists

[pka2xml](https://github.com/mircodz/pka2xml) proved the file format is reversible
with Twofish + EAX, but it is a C++/Docker tool. This is a dependency-free Python
port that also understands what is *inside* the file:

- **The answer key is in the file.** A graded `.pka` carries the instructor's
  finished configuration. Block 2 of the XML is the reference state.
- **Packet Tracer computes the score at runtime.** No completion percentage is
  stored in the file — PT compares live device config against `<COMPARISONS>`
  nodes when you open it. So "solved" means *the configuration matches the key*,
  not *a number was written*.

## Requirements

| | |
|---|---|
| Hermes Agent | required (this is a plugin) |
| Python | 3.11+ (tested on 3.11 and 3.14) |
| Packet Tracer | optional — only for `pka_open` |
| `_twofish` native ext | optional — makes decryption ~6x faster |

No `pip install` is needed. Twofish ships as a bundled pure-Python
implementation and transparently upgrades to the native `_twofish` extension
when that module is importable.

## Install

```bash
git clone https://github.com/rakasyau/pka-solver.git \
  ~/.hermes/plugins/pka-solver

hermes plugins enable pka-solver
hermes plugins doctor pka-solver     # expect: 8 tools registered
```

On Windows the default path is `%LOCALAPPDATA%\hermes\plugins\pka-solver`.

Then **restart Hermes Desktop**. A **PKA Solver** row appears in the sidebar.

For faster decryption, drop the `_twofish` extension into the interpreter that
actually serves your backend:

```bash
python -c "import sysconfig; print(sysconfig.get_paths()['platlib'])"
```

Copy `_twofish.cp<ver>-<platform>.pyd` (or `.so`) there, then confirm with
`pka_doctor` — it should report `twofish_backend: twofish-native`. Without it
everything still works, just ~6x slower.

> On Windows the bundled Hermes interpreter's directory name contains a literal
> `*`. Do not glob it in a shell to copy into it — resolve the path with
> `sysconfig` as above, or the copy lands in a directory literally named `*`.

## Usage

### Desktop UI

The sidebar panel takes a path and gives you three actions:

| Button | Does |
|---|---|
| **Baca assessment** | devices, links, instructions, graded rubric |
| **PKA → XML** | decrypt only, writes `<file>.pka.xml` next to the source |
| **Selesaikan → 100%** | writes `*-SOLVED.pka` + `*-SOLVED.md` |

The UI can only touch `~/Desktop`, `~/Documents`, `~/Downloads` plus any folders
you allow — a browser-reachable route that decrypts arbitrary paths is a
file-read primitive, so it is deliberately narrow. Add your own with either:

```bash
# a) environment variable, os.pathsep-separated (; on Windows, : on POSIX)
export PKA_SOLVER_ROOTS="D:\coursework;E:\labs"
```

```text
# b) roots.local.txt beside plugin.yaml, one path per line (gitignored)
D:\coursework
E:\labs
```

### Agent tools

| Tool | Purpose |
|---|---|
| `pka_doctor` | backend, version, built-in self-test |
| `pka_decrypt` | **PKA → XML only**, no grading |
| `pka_encrypt` | XML → PKA |
| `pka_inspect` | devices, links, addressing, instructions, rubric |
| `pka_solve` | write `*-SOLVED.pka` + Markdown report |
| `pka_verify` | assert required strings are present/absent |
| `pka_open` | launch Packet Tracer on a file |
| `pka_logs` | decode `.nets` and PT log files |

```python
pka_inspect({"path": "soal.pka"})
pka_solve({"path": "soal.pka", "open_after": True})
pka_decrypt({"path": "soal.pka"})            # -> soal.pka.xml, no report
```

`pka_solve` takes `path`, `output`, `report`, `fix_interfaces`, `open_after`.

### CLI, without Hermes

The crypto layer stands alone:

```bash
python selftest.py                 # crypto self-test, no sample needed
python selftest.py soal.pka        # + real-file roundtrip
```

## How the solving works

1. **Decrypt.** Twofish-128 in EAX mode, key and IV fixed by the format, wrapped
   in a length-prefixed zlib stream, under two XOR obfuscation passes.
2. **Read.** The plaintext XML holds three `<PACKETTRACER5>` blocks. Block 0 is
   the workspace PT boots into, block 1 mirrors the start state, and **block 2
   is the answer key**.
3. **Transplant.** Device `<RUNNINGCONFIG>` from block 2 is written into every
   block, so the workspace opens already configured. This is the whole trick —
   no inference, no model calls, just the file's own key.
4. **Fix interfaces.** Interfaces that the key expects to be up get
   `no shutdown`, since PT keeps them administratively down after a transplant.
5. **Re-encrypt and verify.** The result is decrypted again in-memory and
   compared byte-for-byte against the XML that was written.

Grading items come from `<COMPARISONS>` nodes. A typical file has ~19,000 of
them but only a few hundred carry `checkType != "0"` — the rest are inert
scaffolding. `pka_inspect` reports only the graded ones.

## Honest limitations

- **Only works when the file ships an answer key.** Some `.pka` files are
  topology-only. `pka_inspect` tells you (`answer_key_present: false`), and then
  you configure by hand from the instructions.
- **Pre-v5 `.pkt` files** use XOR + zlib only. They are detected and decrypted,
  but there is no answer-key transplant for that generation.
- **Not an emulator.** The plugin never opens Packet Tracer to grade anything;
  it works on the file. `pka_open` is just a launcher.
- **Speed.** Decryption is CPU work: ~0.5 s/MB native, ~3.2 s/MB pure-Python.
- **Windows-first.** Paths and the PT launch behaviour are tested on Windows;
  the crypto layer is platform-neutral.

## Using this responsibly

This reads and rewrites a file you already have. If you are a student, solving
your own assignment with it skips the part where you learn the config. It is
most useful for **checking your own work** against the rubric and for
**instructors** inspecting what a graded file actually expects. Use your own
judgement; do not submit work you did not do.

## Attribution

The decryption logic is a Python port of
[pka2xml](https://github.com/mircodz/pka2xml) by **Mirco De Zorzi** (BSD 2-Clause).
The EAX construction was validated byte-for-byte against pycryptodome, and the
pure-Python Twofish against the Twofish reference vectors and the
[loxodo](https://github.com/sommer/loxodo) implementation.

Packet Tracer and Cisco are trademarks of Cisco Systems, Inc. This project is
not affiliated with or endorsed by Cisco.

## License

BSD 2-Clause. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for the retained
pka2xml attribution.
