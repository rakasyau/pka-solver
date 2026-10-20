"""Backend routes for the pka-solver desktop half.

Mounted at /api/plugins/pka-solver/. Wraps the same handlers the agent tools
use, so the desktop UI and the agent tools can never drift apart.

ponytail: handlers are plain `def`, not `async def`. FastAPI runs `async def`
routes directly on the event loop, so a multi-second blocking Twofish decrypt in
one request can starve other routes — including the `/api/status` liveness poll
the desktop app uses to detect a live backend, which surfaces as "Timed out
connecting to Hermes backend". A sync `def` is dispatched to the threadpool, so
the loop keeps serving. Keep them sync; do not "optimize" to `async def` without
moving the crypto into an explicit thread/executor.
"""

import os
import sys

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

# Load by explicit path: a stdlib/3rd-party module named `tools` is already
# imported in the gateway process, and `sys.path` insertion would not win
# against sys.modules.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location("pka_solver_tools", os.path.join(ROOT, "tools.py"))
tools = _ilu.module_from_spec(_spec)
sys.modules["pka_solver_tools"] = tools
_spec.loader.exec_module(tools)

router = APIRouter()

# Paths the UI is allowed to touch. A browser-reachable route that decrypts
# arbitrary files is a file-read primitive, so keep it to a small set of
# user-facing folders rather than the whole disk.
#
# Extra roots, in precedence order:
#   1. $PKA_SOLVER_ROOTS            (os.pathsep-separated)
#   2. roots.local.txt beside this file, one path per line, '#' comments
# (2) exists so a clone can point at a coursework folder without committing a
# machine-specific path to git — it is in .gitignore.
def _allowed_roots():
    roots = ["~/Desktop", "~/Documents", "~/Downloads"]
    extra = os.environ.get("PKA_SOLVER_ROOTS", "")
    roots += [p for p in extra.split(os.pathsep) if p.strip()]
    local = os.path.join(ROOT, "roots.local.txt")
    try:
        with open(local, encoding="utf-8") as fh:
            roots += [ln.strip() for ln in fh
                      if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        pass
    return tuple(os.path.expanduser(p.strip()) for p in roots)


ALLOWED_ROOTS = _allowed_roots()


def _check(path: str) -> str:
    full = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(full):
        raise HTTPException(400, detail="not a file: %s" % full)
    low = full.lower()
    if not any(low.startswith(os.path.abspath(r).lower() + os.sep)
               or low == os.path.abspath(r).lower()
               for r in ALLOWED_ROOTS if os.path.isdir(r)):
        raise HTTPException(
            403, detail=("path outside the allowed folders: %s\nAllowed: %s"
                         % (full, ", ".join(ALLOWED_ROOTS))))
    return full


@router.get("/doctor")
def doctor():
    import json
    return json.loads(tools.pka_doctor({}))


@router.get("/inspect")
def inspect(path: str, max_rubric_items: int = 200):
    import json
    full = _check(path)
    args = {"path": full, "max_rubric_items": max(1, min(max_rubric_items, 1000))}
    return json.loads(tools.pka_inspect(args))


@router.post("/solve")
def solve(body: dict):
    """Solve and write the output file. Never launches PT — the UI does not."""
    import json
    src = _check(body.get("path", ""))
    args = {"path": src}
    # Match the handler's own schema: output/report/fix_interfaces, and
    # open_after (not `open`) — pka_open is a separate tool on purpose.
    for k in ("output", "report", "fix_interfaces"):
        if body.get(k) is not None:
            args[k] = body[k]
    result = json.loads(tools.pka_solve(args))
    if result.get("success") and result.get("report"):
        result["report_text"] = _read_text(result["report"])
    return result


@router.post("/to-xml")
def to_xml(body: dict):
    """Decrypt a .pka to plain XML on disk. No grading logic, no report."""
    import json
    src = _check(body.get("path", ""))
    args = {"path": src}
    if body.get("out_xml"):
        args["out_xml"] = _check_out(body["out_xml"])
    return json.loads(tools.pka_decrypt(args))


def _check_out(path: str) -> str:
    """Validate a destination path: must stay inside an allowed root."""
    full = os.path.abspath(os.path.expanduser(path))
    low = full.lower()
    if not any(low.startswith(os.path.abspath(r).lower() + os.sep)
               for r in ALLOWED_ROOTS if os.path.isdir(r)):
        raise HTTPException(403, detail="output outside the allowed folders: %s" % full)
    return full


@router.post("/verify")
def verify(body: dict):
    import json
    full = _check(body.get("path", ""))
    args = {"path": full,
            "must_contain": body.get("must_contain") or [],
            "must_not_contain": body.get("must_not_contain") or []}
    return json.loads(tools.pka_verify(args))


@router.get("/download")
def download(path: str):
    """Serve a solved .pka so the user can save it from the browser."""
    return FileResponse(_check(path), filename=os.path.basename(path))


@router.get("/report")
def report(path: str):
    return PlainTextResponse(_read_text(_check(path)))


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""