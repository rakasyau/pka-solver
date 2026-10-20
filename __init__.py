"""pka-solver — solve Cisco Packet Tracer .pka assignments locally.

Pure-Python port of https://github.com/mircodz/pka2xml (BSD-2-Clause): decrypt,
read the answer key + assessment rubric, rebuild a 100% file, open it in PT.
No Docker, no WSL, no LLM in the solving path.
"""
import logging
import os

from . import schemas, tools

logger = logging.getLogger(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLSET = "pka"

CLI_HELP = "Solve Cisco Packet Tracer .pka assignments locally (no Docker)"


def register(ctx):
    settings = {
        "packet_tracer_path": ctx.get_config("packet_tracer_path", default=""),
        "keep_temp_xml": ctx.get_config("keep_temp_xml", default=False),
    }

    def _wrap(name):
        fn = tools.HANDLERS[name]

        def handler(args, **kwargs):
            merged = dict(settings)
            merged.update(kwargs)
            return fn(args or {}, **merged)

        return handler

    for schema in schemas.ALL:
        name = schema["name"]
        ctx.register_tool(
            name=name,
            toolset=TOOLSET,
            schema=schema,
            handler=_wrap(name),
            check_fn=_requirements_ok,
        )

    ctx.register_cli_command(
        name="pka",
        help=CLI_HELP,
        setup_fn=_setup_argparse,
        handler_fn=_cli_handler,
    )


def _requirements_ok() -> bool:
    """Hide every tool when the Twofish backend is missing."""
    try:
        import importlib.util
        return importlib.util.find_spec("_twofish") is not None
    except Exception:
        return False


# ── `hermes pka …` ──────────────────────────────────────────────────────────
def _setup_argparse(subparser):
    subs = subparser.add_subparsers(dest="pka_command")

    d = subs.add_parser("decrypt", help="Decrypt a .pka/.pkt to XML")
    d.add_argument("path")

    e = subs.add_parser("encrypt", help="Encrypt XML back to .pka")
    e.add_argument("path_xml")
    e.add_argument("-o", "--out")

    i = subs.add_parser("inspect", help="Show topology, addressing, rubric")
    i.add_argument("path")
    i.add_argument("--full-configs", action="store_true")

    s = subs.add_parser("solve", help="Produce a solved 100% .pka + markdown")
    s.add_argument("path")
    s.add_argument("-o", "--out")
    s.add_argument("--report")
    s.add_argument("--open", action="store_true", dest="open_after")

    v = subs.add_parser("verify", help="Round-trip + content checks")
    v.add_argument("path")
    v.add_argument("--compare-to")
    v.add_argument("--routers", type=int)

    o = subs.add_parser("open", help="Launch Packet Tracer with the file")
    o.add_argument("path")

    subs.add_parser("doctor", help="Check the local toolchain")
    subparser.set_defaults(func=_cli_handler)


def _cli_handler(args):
    cmd = getattr(args, "pka_command", None)
    if cmd == "decrypt":
        return tools.pka_decrypt({"path": args.path})
    if cmd == "encrypt":
        return tools.pka_encrypt({"path_xml": args.path_xml, "out_pka": args.out})
    if cmd == "inspect":
        return tools.pka_inspect({"path": args.path,
                                  "full_configs": args.full_configs})
    if cmd == "solve":
        return tools.pka_solve({"path": args.path, "output": args.out,
                                "report": args.report,
                                "open_after": args.open_after})
    if cmd == "verify":
        return tools.pka_verify({"path": args.path, "compare_to": args.compare_to,
                                 "expect_routers": args.routers})
    if cmd == "open":
        return tools.pka_open({"path": args.path})
    if cmd == "doctor":
        return tools.pka_doctor({})

    return ("hermes pka <command>\n\n"
            "  decrypt <file.pka>        decrypt to XML\n"
            "  encrypt <file.xml>        encrypt XML back to .pka\n"
            "  inspect <file.pka>        topology, addressing, rubric\n"
            "  solve   <file.pka>        solved 100% .pka + markdown report\n"
            "  verify  <file.pka>        round-trip and content checks\n"
            "  open    <file.pka>        launch Packet Tracer\n"
            "  doctor                    check the local toolchain\n")