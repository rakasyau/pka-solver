"""Markdown solution report for a solved .pka."""
import os
from datetime import datetime

import pka_inspect as insp


def _table(rows, headers):
    if not rows:
        return "_(none)_\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def _fenced(lines):
    return "```\n" + "\n".join(lines) + "\n```\n"


def build(original_xml: str, solved_xml: str, info: dict, args: dict) -> str:
    bs = insp.blocks(solved_xml)
    starter = insp.blocks(original_xml)
    answer = bs[2] if len(bs) >= 3 else (bs[-1] if bs else "")
    devs = insp.devices(answer)
    routers = [d for d in devs if "Router" in d["type"]]

    L = []
    A = L.append
    A("# Solusi — %s\n" % os.path.basename(args.get("input", "assignment")))
    A("Dibuat %s · Packet Tracer %s · %d perangkat, %d router\n"
      % (datetime.now().strftime("%Y-%m-%d %H:%M"),
         insp.version(solved_xml), len(devs), len(routers)))
    A("> File asli **tidak** diubah. Hasil: `%s`\n"
      % os.path.basename(args.get("output", "SOLVED.pka")))

    steps = insp.instructions(original_xml)
    if steps:
        A("\n## 1. Langkah pada Activity Instructions\n")
        A(steps + "\n")

    A("\n## 2. Topologi & perangkat\n")
    A(_table([[d["name"], d["type"], d["x"], d["y"]] for d in devs],
             ["Perangkat", "Tipe", "X", "Y"]))

    lk = insp.links(answer, devs)
    if lk:
        A("\n### Kabel / link\n")
        A(_table([[l["from"], l["from_port"], l["to"], l["to_port"], l["type"]]
                  for l in lk], ["Dari", "Port", "Ke", "Port", "Tipe"]))

    addr = insp.addressing(answer)
    A("\n## 3. Tabel pengalamatan\n")
    A(_table([[a["device"], a["interface"], a["address"], a["mask"]] for a in addr],
             ["Perangkat", "Interface", "IP", "Mask"]))

    routing = insp.routing_summaries(answer)
    if routing:
        A("\n## 4. Protabel routing\n")
        for name, procs in sorted(routing.items()):
            A("**%s**\n" % name)
            for p in procs:
                A("- `router %s %s` — network: %s%s"
                  % (p["protocol"], p["id"],
                     ", ".join(p["networks"]) or "-",
                     ("; redistribute: " + ", ".join(p["redistribute"])) if p["redistribute"] else ""))
            A("")

    A("\n## 5. CLI per perangkat\n")
    for d in routers:
        lines = insp.config_lines(d["config"])
        if lines:
            A("### %s\n" % d["name"])
            A(_fenced(lines))

    rub = insp.graded_items(solved_xml)
    if rub:
        A("\n## 6. Butir penilaian (assessment)\n")
        A("Packet TracerPW memeriksa butir berikut; file ini sudah berisi "
          "jawaban untuk semuanya.\n")
        A(_table([[r["path"], r.get("points", "")] for r in rub[:80]],
                 ["Butir", "Poin"]))
        if len(rub) > 80:
            A("_… %d butir lagi._\n" % (len(rub) - 80))
    elif not insp.proficiency_model(solved_xml):
        A("\n## 6. Penilaian\n")
        A("Tidak ada `PROFICIENCY_MODEL` pada file ini — penilaian dilakukan "
          "manual / berbasis konektivitas, jadi yang dinilai adalah topologi, "
          "pengalamatan, dan konfigurasi perangkat.\n")

    A("\n## 7. Verifikasi\n")
    A(_fenced([
        "show ip interface brief   # semua interface terpakai harus up/up",
        "show ip route              # route connected + learned ada",
        "show ip protocol           # proses routing berjalan",
        "ping <ip-tujuan>           # dari PC, lintas area",
    ]))
    A("`no shutdown` ditambahkan pada %d interface agar semua porta aktif "
      "(answer key asli tidak memuatinya).\n" % info.get("interfaces_brought_up", 0))

    A("\n## 8. Cara membuka\n")
    A("```bash\n%s \"%s\"\n```\n" % (
        r'"C:\Program Files\Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe"',
        args.get("output", "SOLVED.pka")))
    A("PT 9 memunculkan dialog *User Profile* (Guest) lebih dulu — tekan OK. "
      "Indikator `Completion: NN%` berada pada baris di atas `Time:` di panel "
      "instructions. Tunggu 2–3 menit bila memakai OSPF/EIGRP agar konvergen.\n")
    return "\n".join(L)


def write_markdown(path: str, original_xml: str, solved_xml: str, info: dict, args: dict) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    text = build(original_xml, solved_xml, info, args)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path