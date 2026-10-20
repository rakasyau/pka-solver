"""Tool schemas — what the model reads to decide when to call these."""

PKA_DECRYPT = {
    "name": "pka_decrypt",
    "description": (
        "Decrypt a Cisco Packet Tracer .pka/.pkt file to readable XML, locally "
        "(no Docker, no network). Use when you need to read the topology, the "
        "answer key, the instructions or the grading rubric of an assignment "
        "file. Also reads Packet Tracer's ~/.packettracer/nets and pt_*.log files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the .pka/.pkt file."},
            "out_xml": {
                "type": "string",
                "description": "Where to write the XML. Defaults to <path>.xml.",
            },
            "mode": {
                "type": "string",
                "enum": ["pka", "nets", "logs", "auto"],
                "default": "auto",
                "description": "auto picks pka vs logs/nets from the file name.",
            },
        },
        "required": ["path"],
    },
}

PKA_ENCRYPT = {
    "name": "pka_encrypt",
    "description": (
        "Encrypt XML back into a Cisco Packet Tracer .pka/.pkt file, locally. "
        "This is the reverse of pka_decrypt and the last step of producing a "
        "solved assignment file."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path_xml": {"type": "string", "description": "Path to the XML file."},
            "out_pka": {
                "type": "string",
                "description": "Output .pka path. Defaults to <path_xml>.pka",
            },
            "compression_level": {
                "type": "integer", "default": -1,
                "description": "zlib level; -1 = Packet Tracer's own default.",
            },
        },
        "required": ["path_xml"],
    },
}

PKA_INSPECT = {
    "name": "pka_inspect",
    "description": (
        "Read a .pka/.pkt file and report its topology, addressing table, "
        "routing-protocol summary, the Activity Instructions text and the "
        "assessment rubric (the graded items Packet Tracer checks). Call this "
        "after pka_decrypt, or directly with the .pka path — it decrypts "
        "internally. Use `full_configs: true` to get each device's exact CLI."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to a .pka/.pkt file, or to decrypted XML.",
            },
            "full_configs": {
                "type": "boolean", "default": False,
                "description": "Include each device's full RUNNINGCONFIG CLI.",
            },
            "include_rubric": {
                "type": "boolean", "default": True,
                "description": "Include the list of graded assessment items.",
            },
            "max_rubric_items": {"type": "integer", "default": 60},
        },
        "required": ["path"],
    },
}

PKA_SOLVE = {
    "name": "pka_solve",
    "description": (
        "Solve a Packet Tracer .pka assignment: decrypt it, transplant the "
        "answer key into all three file blocks, bring every addressed interface "
        "up, re-encrypt and verify the result round-trips. Produces a file that "
        "opens in Packet Tracer at Completion: 100%. The original file is never "
        "modified. Returns a markdown solution report next to the output."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "The .pka assignment file."},
            "output": {
                "type": "string",
                "description": "Solved .pka path. Default: <name>-SOLVED.pka beside the input.",
            },
            "report": {
                "type": "string",
                "description": "Markdown solution path. Default: same name with .md.",
            },
            "fix_interfaces": {
                "type": "boolean", "default": True,
                "description": "Insert `no shutdown` on addressed interfaces (answer keys omit it).",
            },
            "open_after": {
                "type": "boolean", "default": False,
                "description": "Launch the solved file in Packet Tracer when done.",
            },
        },
        "required": ["path"],
    },
}

PKA_VERIFY = {
    "name": "pka_verify",
    "description": (
        "Verify a .pka file: decrypt it back and confirm the XML matches what "
        "was written, then report device/link/config counts and whether the "
        "graded state is present in all three blocks. Use after any build — a "
        "passing round-trip is necessary but not sufficient for Packet Tracer "
        "to accept the file."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "The .pka file to verify."},
            "compare_to": {
                "type": "string",
                "description": "Optional XML file the decrypted payload must equal.",
            },
            "expect_blocks": {"type": "integer", "default": 3},
            "expect_routers": {
                "type": "integer",
                "description": "Fail if the file does not hold this many routers.",
            },
            "must_contain": {
                "type": "array", "items": {"type": "string"},
                "description": "Substrings that must appear, e.g. ['router ospf 1', 'no shutdown'].",
            },
            "must_not_contain": {
                "type": "array", "items": {"type": "string"},
                "description": "Substrings that must be absent, e.g. ['router rip'].",
            },
        },
        "required": ["path"],
    },
}

PKA_OPEN = {
    "name": "pka_open",
    "description": (
        "Open a .pka/.pkt file in Cisco Packet Tracer and report the window "
        "title, so you can confirm the file loads and check the Completion "
        "percentage. A PT 9 .pka shows a 'User Profile' guest dialog first — "
        "press OK/Enter."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "The .pka/.pkt file to open."},
            "wait_seconds": {"type": "integer", "default": 25},
        },
        "required": ["path"],
    },
}

PKA_LOGS = {
    "name": "pka_logs",
    "description": (
        "Decrypt Packet Tracer log files (pt_*.log, base64 lines) or the nets "
        "file, locally. Useful to see which version wrote a file and whether a "
        "load raised an error. Note that log markers are unreliable for .pka on "
        "PT 9 — trust the window title and Completion % instead."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "pt_*.log or nets file."},
            "max_lines": {"type": "integer", "default": 200},
        },
        "required": ["path"],
    },
}

PKA_DOCTOR = {
    "name": "pka_doctor",
    "description": (
        "Check the local Packet Tracer toolchain: Twofish backend availability, "
        "EAX self-test, and Packet Tracer's install path. Run this first when a "
        "decrypt fails or Packet Tracer is not found."
    ),
    "parameters": {"type": "object", "properties": {}},
}

ALL = [PKA_DECRYPT, PKA_ENCRYPT, PKA_INSPECT, PKA_SOLVE, PKA_VERIFY,
       PKA_OPEN, PKA_LOGS, PKA_DOCTOR]

BY_NAME = {s["name"]: s for s in ALL}