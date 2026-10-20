"""Read a decrypted .pka XML: devices, links, answer-key configs, rubric, steps.

Pure stdlib + regex, same style as the XML that Packet Tracer emits.
"""
import base64
import html
import re
from xml.etree import ElementTree as ET

_BLOCK = re.compile(r'<PACKETTRACER5>(.*?)</PACKETTRACER5>', re.DOTALL)


# ── blocks ──────────────────────────────────────────────────────────────────
def blocks(xml_text: str):
    """Return the inner text of every <PACKETTRACER5> block (activity, workspace, answer)."""
    return [m.group(1) for m in _BLOCK.finditer(xml_text)]


def version(xml_text: str) -> str:
    m = re.search(r'<VERSION>([^<]+)</VERSION>', xml_text)
    return m.group(1) if m else "unknown"


def _tag(block: str, name: str):
    """First <name> element's inner text.

    Only the top-level (shallowest) match counts: a <DEVICE> nests <MODULE>
    and <SLOT> subtrees that contain their own <TYPE>, and picking those up
    reports every router as 'eNonRemovableModule'.
    """
    m = re.search(r'<%s\b[^>]*>(.*?)</%s>' % (name, name), block, re.DOTALL)
    return m.group(1) if m else ""


# ── devices ─────────────────────────────────────────────────────────────────
def devices(block: str):
    """[{name, type, ref_id, x, y, config, startup}] for one block."""
    out = []
    for m in re.finditer(r'<DEVICE>(.*?)</DEVICE>', block, re.DOTALL):
        d = m.group(1)
        name = re.search(r'<ENGINE>\s*<NAME[^>]*>([^<]+)</NAME>', d)
        if not name:
            name = re.search(r'<NAME[^>]*>([^<]+)</NAME>', d)
        out.append({
            "name": name.group(1).strip() if name else "?",
            "type": (_tag(d, "TYPE") or "?").strip(),
            "ref_id": (_tag(d, "SAVE_REF_ID") or "").strip(),
            "x": _first(d, r'<X>([-\d.]+)</X>'),
            "y": _first(d, r'<Y>([-\d.]+)</Y>'),
            "config": _tag(d, "RUNNINGCONFIG"),
            "startup": _tag(d, "STARTUPCONFIG"),
        })
    return out


def _first(text: str, pattern: str):
    m = re.search(pattern, text)
    return float(m.group(1)) if m else None


def config_lines(config_xml: str):
    """RUNNINGCONFIG element text -> list of CLI lines (strip the LINE wrappers)."""
    if not config_xml:
        return []
    lines = re.findall(r'<LINE>([^<]*)</LINE>', config_xml)
    if lines:
        return [l.replace('&lt;', '<').replace('&gt;', '>')
                 .replace('&amp;', '&').replace('&quot;', '"') for l in lines]
    # some blocks store the config as one text blob with literal newlines
    return config_xml.replace('&lt;', '<').replace('&gt;', '>').splitlines()


# ── links ───────────────────────────────────────────────────────────────────
def links(block: str, devs=None):
    """[{from, from_port, to, to_port, type}] with device names resolved."""
    by_ref = {}
    for d in (devs or devices(block)):
        if d["ref_id"]:
            by_ref[d["ref_id"]] = d["name"]
    lb = _tag(block, "LINKS")
    out = []
    for m in re.finditer(r'<LINK>(.*?)</LINK>', lb, re.DOTALL):
        lk = m.group(1)
        fr = _tag(lk, "FROM")
        to = _tag(lk, "TO")
        out.append({
            "from": by_ref.get(_tag(fr, "SAVE_REF_ID").strip(),
                               _tag(fr, "SAVE_REF_ID").strip()),
            "from_port": _tag(fr, "PORT").strip(),
            "to": by_ref.get(_tag(to, "SAVE_REF_ID").strip(),
                             _tag(to, "SAVE_REF_ID").strip()),
            "to_port": _tag(to, "PORT").strip(),
            "type": _tag(lk, "LINKTYPE").strip(),
        })
    return out


# ── addressing ──────────────────────────────────────────────────────────────
def addressing(block: str):
    """[{device, interface, address, mask}] from interface stanzas."""
    out = []
    for d in devices(block):
        lines = config_lines(d["config"])
        cur = None
        for ln in lines:
            s = ln.strip()
            if s.startswith("interface "):
                cur = s.split(None, 1)[1].strip()
            m = re.match(r'ip address (\d+\.\d+\.\d+\.\d+) ?(\d+\.\d+\.\d+\.\d+)?', s)
            if m and cur and "no ip address" not in s:
                out.append({"device": d["name"], "interface": cur,
                            "address": m.group(1),
                            "mask": m.group(2) or "/32"})
            for proto in ("ospf ", "eigrp ", "bgp ", "rip ", "isis "):
                if s.startswith("network ") and proto in d["config"]:
                    pass
    return out


def routing_summaries(block: str):
    """Per-device protocol summary: which routing processes exist."""
    out = {}
    for d in devices(block):
        if "Router" not in d["type"]:
            continue
        lines = config_lines(d["config"])
        procs = []
        cur = None
        for ln in lines:
            s = ln.strip()
            m = re.match(r'router\s+(rip|ospf|eigrp|bgp|isis)\b(.*)', s)
            if m:
                cur = {"protocol": m.group(1), "id": m.group(2).strip() or "(none)",
                       "networks": [], "redistribute": []}
                procs.append(cur)
            elif cur is None:
                continue
            elif s.startswith("network "):
                cur["networks"].append(s.split(None, 1)[1].strip())
            elif s.startswith("redistribute "):
                cur["redistribute"].append(s)
            elif re.match(r'^\S', ln) and not s.startswith(("network", "redistribute")) \
                    and cur is not None and not ln.startswith((" ", "\t")) \
                    and s.startswith(("!", "end", "line", "interface", "ip route")):
                cur = None
        if procs:
            out[d["name"]] = procs
    return out


# ── assessment ──────────────────────────────────────────────────────────────
def instructions(xml_text: str) -> str:
    """Plain text of the Activity Instructions (HTML CDATA, tags stripped)."""
    m = re.search(r'<INSTRUCTIONS\b[^>]*>(.*?)</INSTRUCTIONS>', xml_text, re.DOTALL)
    if not m:
        return ""
    body = m.group(1)
    body = re.sub(r'<style.*?</style>', ' ', body, flags=re.DOTALL | re.I)
    body = re.sub(r'<script.*?</script>', ' ', body, flags=re.DOTALL | re.I)
    body = re.sub(r'<br\s*/?>', '\n', body, flags=re.I)
    body = re.sub(r'</(p|div|li|tr|h\d)>', '\n', body, flags=re.I)
    body = re.sub(r'<li[^>]*>', '• ', body, flags=re.I)
    body = re.sub(r'<[^>]+>', '', body)
    body = html.unescape(body)
    body = re.sub(r'[ \t]+', ' ', body)
    body = re.sub(r'\n\s*\n+', '\n', body)
    return "\n".join(l.strip() for l in body.splitlines() if l.strip())


def _xml_to_dict(el):
    d = {"tag": el.tag, "attrs": dict(el.attrib)}
    if el.text and el.text.strip():
        d["text"] = el.text.strip()
    kids = list(el)
    if kids:
        d["children"] = [_xml_to_dict(k) for k in kids]
    return d


def rubric(xml_text: str):
    """Graded leaves of the <COMPARISONS> tree — the assessment rubric.

    Packet Tracer puts the grading attributes on the <NAME> child of each
    <NODE> (<NAME variableEnabled="true" nodeValue="…">), with siblings <ID>,
    <COMPONENTS> and <POINTS>. A proper XML parse is used because the nodes
    nest — a regex cannot pair them correctly.
    """
    m = re.search(r'<COMPARISONS>(.*?)</COMPARISONS>', xml_text, re.DOTALL)
    if not m:
        return []
    try:
        root = ET.fromstring(m.group(1))
    except ET.ParseError:
        return []

    out = []

    def walk(el, path):
        name_el = el.find("NAME")
        label = (name_el.text or "").strip() if name_el is not None else ""
        here = path + ([label] if label else [])
        graded = name_el is not None and name_el.get("variableEnabled") == "true"
        kids = [k for k in el if k.tag == "NODE"]
        if graded:
            pts = el.findtext("POINTS") or ""
            node_id = el.findtext("ID") or ""
            out.append({"path": " / ".join(p for p in here if p),
                        "id": node_id.strip(),
                        "points": pts.strip(),
                        "check_type": (name_el.get("checkType") or ""),
                        "expected": (name_el.get("nodeValue") or "").strip()})
        for k in kids:
            walk(k, here)

    for child in root:
        walk(child, [])
    return out


def graded_items(xml_text: str):
    """The subset of rubric leaves Packet Tracer actually checks.

    A .pka's COMPARISONS tree carries ~20k nodes — one per attribute of every
    device — and the vast majority are inert defaults with checkType="0"
    (display-only). Only checkType 1/2 nodes represent a real graded item, so
    those are what a solution report should list.
    """
    return [r for r in rubric(xml_text) if r.get("check_type") != "0"]


def proficiency_model(xml_text: str) -> bool:
    """False when the .pka has no scripted grader (grading is manual/connectivity)."""
    m = re.search(r'<PROFICIENCY_MODEL>(.*?)</PROFICIENCY_MODEL>', xml_text, re.DOTALL)
    return bool(m and m.group(1).strip())


# ── topology image ──────────────────────────────────────────────────────────
def topo_image(block0: str):
    """Base64 PNG of the workspace background image, if the file embeds one."""
    m = re.search(r'<IMAGE_PATH>([^<]+)</IMAGE_PATH>', block0)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1).strip())
    except Exception:
        return None


# ── one-call summary ────────────────────────────────────────────────────────
def summarize(xml_text: str):
    bs = blocks(xml_text)
    out = {
        "version": version(xml_text),
        "blocks": len(bs),
        "proficiency_model": proficiency_model(xml_text),
        "instructions": instructions(xml_text),
        "rubric_total": len(rubric(xml_text)),
        # PT writes one COMPARISONS node per device attribute; only the
        # non-default ones carry checkType!="0" and are worth listing.
        "rubric_items": len(graded_items(xml_text)),
    }
    if len(bs) >= 3:
        answer = devices(bs[2])
        out["answer_devices"] = [{"name": d["name"], "type": d["type"],
                                  "x": d["x"], "y": d["y"]} for d in answer]
        out["answer_links"] = links(bs[2], answer)
        out["addressing"] = addressing(bs[2])
        out["routing"] = routing_summaries(bs[2])
        out["starter_devices"] = [d["name"] for d in devices(bs[1])] or None
        out["answer_key_present"] = any(d["config"].strip() for d in answer)
    return out