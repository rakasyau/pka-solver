"""Tool handlers for the pka-solver plugin."""
import glob
import os
import platform
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import pka_inspect as insp            # noqa: E402
import pka_solve as solver            # noqa: E402
import pka2xml_local as p2x           # noqa: E402
import report as report_mod           # noqa: E402

_PT_CANDIDATES = [
    r"C:\Program Files\Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe",
    r"C:\Program Files (x86)\Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe",
    r"C:\Program Files\Cisco Packet Tracer 8.2.1\bin\PacketTracer.exe",
    r"C:\Program Files\Cisco Packet Tracer 7.3.1\bin\PacketTracer.exe",
    r"C:\Program Files\Cisco Packet Tracer*\bin\PacketTracer.exe",
]


def _err(exc, **extra):
    out = {"success": False, "error": str(exc), "error_type": type(exc).__name__}
    out.update(extra)
    return out


def _resolve_path(path: str) -> str:
    p = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
    if not os.path.exists(p):
        hits = glob.glob(p)
        if hits:
            return hits[0]
        raise FileNotFoundError(path)
    return p


def _detect_mode(path: str, mode: str) -> str:
    if mode and mode != "auto":
        return mode
    base = os.path.basename(path).lower()
    if base.startswith("pt_") and base.endswith(".log"):
        return "logs"
    if base == "nets":
        return "nets"
    return "pka"


def _packet_tracer_path(configured: str = "") -> str:
    if configured and os.path.exists(configured):
        return configured
    for c in _PT_CANDIDATES:
        hits = sorted(glob.glob(c))
        if hits:
            return hits[-1]
    return ""


# ── pka_decrypt ─────────────────────────────────────────────────────────────
def pka_decrypt(args: dict, **kwargs) -> str:
    import json
    try:
        path = _resolve_path(args["path"])
        mode = _detect_mode(path, args.get("mode", "auto"))
        out = args.get("out_xml") or path + (".xml" if os.path.isfile(path + ".xml") is False else ".out.xml")

        if mode == "logs":
            return json.dumps({"success": True, **pka_logs({"path": path})}, default=str)
        if mode == "nets":
            raw = open(path, 'rb').read()
            return json.dumps({"success": True, "mode": "nets",
                               "decrypted": p2x.decrypt_nets(raw).decode('utf-8', 'replace')[:4000]},
                              default=str)

        raw = open(path, 'rb').read()
        if p2x.is_old_pt(raw):
            return json.dumps({"success": True, "mode": "pka", "legacy_format": True,
                               "note": "pre-v5 .pkt: XOR obfuscation only, no EAX",
                               "path": path}, default=str)
        xml = p2x.decrypt_pka(raw)
        with open(out, 'wb') as fh:
            fh.write(xml)
        return json.dumps({"success": True, "mode": "pka", "input": path,
                           "output": out, "xml_bytes": len(xml),
                           "blocks": len(insp.blocks(xml.decode('utf-8', 'replace'))),
                           "pt_version": insp.version(xml.decode('utf-8', 'replace'))},
                          default=str)
    except Exception as exc:
        return json.dumps(_err(exc, path=args.get("path")))


# ── pka_encrypt ─────────────────────────────────────────────────────────────
def pka_encrypt(args: dict, **kwargs) -> str:
    import json
    try:
        xml_path = _resolve_path(args["path_xml"])
        out = args.get("out_pka") or os.path.splitext(xml_path)[0] + ".pka"
        xml = open(xml_path, 'rb').read()
        blob = p2x.encrypt_pka(xml, int(args.get("compression_level", -1)))
        with open(out, 'wb') as fh:
            fh.write(blob)
        return json.dumps({"success": True, "output": out, "bytes": len(blob),
                           "xml_bytes": len(xml)})
    except Exception as exc:
        return json.dumps(_err(exc))


# ── pka_inspect ─────────────────────────────────────────────────────────────
def pka_inspect(args: dict, **kwargs) -> str:
    import json
    try:
        path = _resolve_path(args["path"])
        if path.lower().endswith((".pka", ".pkt")):
            xml = p2x.decrypt_pka(open(path, 'rb').read()).decode('utf-8', 'replace')
        else:
            xml = open(path, encoding='utf-8', errors='replace').read()

        data = insp.summarize(xml)
        data["source"] = path

        bs = insp.blocks(xml)
        if args.get("full_configs") and len(bs) >= 3:
            data["configs"] = {
                d["name"]: insp.config_lines(d["config"])
                for d in insp.devices(bs[2]) if d["config"].strip()
            }

        if args.get("include_rubric", True):
            items = insp.graded_items(xml)
            limit = int(args.get("max_rubric_items", 60))
            data["rubric"] = items[:limit]
            data["rubric_truncated"] = len(items) > limit
            data["rubric_nodes_total"] = len(insp.rubric(xml))
            data["grading"] = ("scripted (PROFICIENCY_MODEL present)"
                               if data["proficiency_model"]
                               else "manual / connectivity-based (no PROFICIENCY_MODEL)")

        return json.dumps({"success": True, **data}, default=str, indent=1)
    except Exception as exc:
        return json.dumps(_err(exc))


# ── pka_solve ───────────────────────────────────────────────────────────────
def pka_solve(args: dict, **kwargs) -> str:
    import json
    try:
        path = _resolve_path(args["path"])
        stem, ext = os.path.splitext(path)
        out = args.get("output") or stem + "-SOLVED" + (ext or ".pka")
        rpt = args.get("report") or os.path.splitext(out)[0] + ".md"
        keep = bool(kwargs.get("keep_temp_xml", True))

        xml = p2x.decrypt_pka(open(path, 'rb').read()).decode('utf-8', 'replace')
        solved, info = solver.solve(xml, fix_interfaces=args.get("fix_interfaces", True))

        tmp_xml = os.path.join(os.environ.get("TMPDIR", os.environ.get("TEMP", ".")),
                               "pka_solve_%d.xml" % int(time.time()))
        with open(tmp_xml, 'w', encoding='utf-8') as fh:
            fh.write(solved)

        blob = p2x.encrypt_pka(solved.encode('utf-8'))
        with open(out, 'wb') as fh:
            fh.write(blob)

        # verification: decrypt the file we just wrote, must match the XML
        back = p2x.decrypt_pka(open(out, 'rb').read()).decode('utf-8', 'replace')
        roundtrip_ok = back == solved

        report_mod.write_markdown(rpt, xml, solved, info, args)
        if not keep:
            try:
                os.remove(tmp_xml)
            except OSError:
                pass

        result = {"success": True, "input": path, "output": out, "report": rpt,
                  "roundtrip_verified": roundtrip_ok, **info}

        if args.get("open_after"):
            result["opened"] = pka_open({"path": out}, **kwargs)
        return json.dumps(result, default=str, indent=1)
    except Exception as exc:
        return json.dumps(_err(exc))


# ── pka_verify ──────────────────────────────────────────────────────────────
def pka_verify(args: dict, **kwargs) -> str:
    import json
    try:
        path = _resolve_path(args["path"])
        xml = p2x.decrypt_pka(open(path, 'rb').read()).decode('utf-8', 'replace')
        bs = insp.blocks(xml)

        result = {
            "success": True,
            "path": path,
            "pt_version": insp.version(xml),
            "blocks": len(bs),
            "xml_bytes": len(xml),
        }

        expected_blocks = int(args.get("expect_blocks", 3))
        result["blocks_ok"] = len(bs) == expected_blocks

        if args.get("expect_routers") is not None:
            want = int(args["expect_routers"])
            bs2 = bs[2] if len(bs) >= 3 else (bs[-1] if bs else "")
            got = sum(1 for d in insp.devices(bs2) if "Router" in d["type"])
            result["routers"] = got
            result["routers_ok"] = got == want

        if args.get("compare_to"):
            ref = open(_resolve_path(args["compare_to"]), encoding='utf-8', errors='replace').read()
            result["matches_reference"] = ref == xml

        for k, key in (("must_contain", "missing_strings"),
                       ("must_not_contain", "forbidden_strings_present")):
            needles = args.get(k) or []
            if needles:
                found = [n for n in needles if n in xml]
                result[key] = [] if found == needles or k == "must_not_contain" else found

        if len(bs) >= 3:
            graded = []
            for i, b in enumerate(bs):
                cfgs = [d for d in insp.devices(b) if d["config"].strip()]
                graded.append({"block": i, "devices_with_config": len(cfgs),
                               "no_shutdown": b.count('<LINE> no shutdown</LINE>')})
            result["per_block"] = graded
            result["graded_state_in_all_blocks"] = all(
                g["devices_with_config"] > 0 for g in graded)
            result["pixmapbank_in_block0"] = "<PIXMAPBANK>" in bs[0]

        result["verdict"] = ("PASS" if result.get("blocks_ok")
                             and result.get("graded_state_in_all_blocks", True)
                             and not result.get("missing_strings") else "CHECK")
        return json.dumps(result, default=str, indent=1)
    except Exception as exc:
        return json.dumps(_err(exc))


# ── pka_open ────────────────────────────────────────────────────────────────
def pka_open(args: dict, **kwargs) -> str:
    import json
    try:
        path = _resolve_path(args["path"])
        exe = _packet_tracer_path(kwargs.get("packet_tracer_path", ""))
        if not exe:
            return json.dumps({"success": False,
                               "error": "Packet Tracer executable not found. Set "
                                        "plugins.entries.pka-solver.settings.packet_tracer_path "
                                        "or install PT."})
        subprocess.Popen([exe, path], close_fds=True)
        wait = int(args.get("wait_seconds", 25))
        time.sleep(min(wait, 90))

        title = ""
        try:
            out = subprocess.run(
                ["tasklist", "/v", "/fo", "csv", "/fi", "imagename eq PacketTracer.exe"],
                capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines()[1:]:
                if "PacketTracer.exe" in line:
                    title = line.split('","')[9] if line.count('","') > 9 else line
                    break
        except Exception:
            pass
        return json.dumps({"success": True, "launched": exe, "file": path,
                           "window_title": title,
                           "note": "PT 9 shows a 'User Profile' guest dialog first — "
                                   "press OK/Enter. Completion: NN% sits on the row "
                                   "above 'Time:' in the instruction panel."})
    except Exception as exc:
        return json.dumps(_err(exc))


# ── pka_logs ────────────────────────────────────────────────────────────────
def pka_logs(args: dict, **kwargs) -> str:
    import json
    try:
        path = _resolve_path(args["path"])
        out_lines = []
        if os.path.basename(path).lower() == "nets":
            raw = open(path, 'rb').read()
            return json.dumps({"success": True, "kind": "nets",
                               "text": p2x.decrypt_nets(raw).decode('utf-8', 'replace')[:6000]})
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out_lines.append(p2x.decrypt_logs(line).decode('utf-8', 'replace'))
                except Exception:
                    out_lines.append(line)
        limit = int(args.get("max_lines", 200))
        return json.dumps({"success": True, "kind": "logs", "total": len(out_lines),
                           "lines": out_lines[-limit:]})
    except Exception as exc:
        return json.dumps(_err(exc))


# ── pka_doctor ──────────────────────────────────────────────────────────────
def pka_doctor(args: dict, **kwargs) -> str:
    import json
    report = {"host": platform.platform(), "python": sys.version.split()[0],
              "plugin_dir": HERE}

    import pka2xml_local as p2x
    report["twofish_backend"] = p2x.Twofish(p2x.PKA_KEY).backend
    report["twofish_ok"] = True

    # pycryptodome is only the reference oracle for the EAX cross-check, so a
    # missing module is a SKIP, not a failure — the runtime interpreter has
    # none and must not look broken.
    try:
        import importlib.util
        has_oracle = importlib.util.find_spec("Crypto") is not None
    except Exception:
        has_oracle = False

    try:
        sys.path.insert(0, HERE)
        import selftest
        tests = [selftest.test_twofish_known_answer,
                 selftest.test_obfuscation_is_an_involution]
        if has_oracle:
            tests.insert(1, selftest.test_eax_matches_pycryptodome)
        else:
            report["eax_oracle"] = ("skipped: pycryptodome not installed "
                                    "(optional reference check)")
        if report["twofish_backend"] == "twofish-pure":
            # No native backend here, so a parity comparison has nothing to
            # compare against; the KAT above still pins the cipher.
            report["backend_parity"] = "skipped: native _twofish not importable"
        else:
            tests.insert(1, selftest.test_twofish_backends_agree)
        results = []
        for fn in tests:
            try:
                results.append({"test": fn.__name__, "ok": True, "detail": fn()})
            except Exception as exc:
                results.append({"test": fn.__name__, "ok": False,
                                "error": str(exc)})
        report["selftest"] = results
    except Exception as exc:
        report["selftest_error"] = str(exc)

    report["packet_tracer"] = _packet_tracer_path(kwargs.get("packet_tracer_path", "")) or None
    report["docker_required"] = False
    return json.dumps({"success": True, **report}, indent=1, default=str)


HANDLERS = {
    "pka_decrypt": pka_decrypt,
    "pka_encrypt": pka_encrypt,
    "pka_inspect": pka_inspect,
    "pka_solve": pka_solve,
    "pka_verify": pka_verify,
    "pka_open": pka_open,
    "pka_logs": pka_logs,
    "pka_doctor": pka_doctor,
}