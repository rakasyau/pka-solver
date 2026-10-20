"""Format-level tests that need no Packet Tracer sample file.

A real .pka is copyrighted coursework, so the suite builds a synthetic
plaintext with the same shape PT emits: three <PACKETTRACER5> blocks, a
RUNNINGCONFIG per DEVICE, and <COMPARISONS> nodes that differ only in
checkType. Synthetic input proves the plumbing; it cannot prove the key
schedule against a real file, which is what selftest.py's KAT and the optional
real-file roundtrip are for.

    python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pka_inspect as insp  # noqa: E402
from pka2xml_local import decrypt_pka, encrypt_pka, is_old_pt  # noqa: E402


def _device(name, config, dtype="Router"):
    return (
        "<DEVICE><NAME>%s</NAME><TYPE>%s</TYPE><REF_ID>1</REF_ID>"
        "<MODULE><SLOT><TYPE>eNonRemovableModule</TYPE></SLOT></MODULE>"
        "<RUNNINGCONFIG>%s</RUNNINGCONFIG></DEVICE>"
        % (name, dtype, config)
    )


def _node(label, children="", attrs=""):
    return "<NODE><NAME%s>%s</NAME>%s</NODE>" % (attrs, label, children)


def _leaf(label, check_type, value, points="4"):
    """A graded leaf: attributes live on <NAME>, siblings are ID and POINTS."""
    return (
        '<NODE><NAME variableEnabled="true" checkType="%s" nodeValue="%s">%s</NAME>'
        "<ID>%s</ID><POINTS>%s</POINTS></NODE>"
        % (check_type, value, label, label, points)
    )


STARTER = _device("R1", "hostname R1\n!\ninterface Serial0/0\n shutdown\n")
ANSWER = _device("R1", "hostname R1\n!\ninterface Serial0/0\n no shutdown\n")


# COMPARISONS must parse as ONE root element, and the grading tree nests one
# <NODE> per path segment.
COMPARISONS = (
    "<COMPARISONS>"
    + _node(
        "",  # real files have one unnamed root; an empty label drops out of the path
        _node(
            "R1",
            _node("Ports", _node("Serial0/0",
                                 _leaf("Status", "1", "up") + _leaf("IP", "2", "10.0.0.1"))),
        )
        + _node("Ignored", _leaf("node", "0", "x")),  # graded=true but checkType=0
    )
    + "</COMPARISONS>"
)

XML = (
    "<PACKETTRACER5><VERSION>9.0.1.0858</VERSION>%s%s</PACKETTRACER5>"
    "<PACKETTRACER5><VERSION>9.0.1.0858</VERSION>%s</PACKETTRACER5>"
    "<PACKETTRACER5><VERSION>9.0.1.0858</VERSION>%s</PACKETTRACER5>"
    % (STARTER, COMPARISONS, STARTER, ANSWER)
).encode("utf-8")


class Crypto(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        blob = encrypt_pka(XML)
        self.assertEqual(decrypt_pka(blob), XML)

    def test_ciphertext_differs_from_plaintext(self):
        self.assertNotIn(b"PACKETTRACER5", encrypt_pka(XML))

    def test_new_format_is_not_mistaken_for_legacy(self):
        self.assertFalse(is_old_pt(encrypt_pka(XML)))


class Readers(unittest.TestCase):
    text = XML.decode("utf-8")

    def test_three_blocks(self):
        self.assertEqual(len(insp.blocks(self.text)), 3)

    def test_version(self):
        self.assertEqual(insp.version(self.text), "9.0.1.0858")

    def test_block_two_is_the_answer_key(self):
        key = insp.devices(insp.blocks(self.text)[2])
        self.assertEqual(len(key), 1)
        self.assertIn("no shutdown", key[0]["config"])

    def test_starter_block_is_unconfigured(self):
        starter = insp.devices(insp.blocks(self.text)[0])
        self.assertIn("shutdown", starter[0]["config"])
        self.assertNotIn("no shutdown", starter[0]["config"])

    def test_nested_module_type_does_not_override_device_type(self):
        """<MODULE>/<SLOT> nest their own <TYPE>; the device must win."""
        self.assertEqual(insp.devices(insp.blocks(self.text)[0])[0]["type"], "Router")

    def test_only_graded_comparisons_are_reported(self):
        items = insp.graded_items(self.text)
        self.assertEqual(len(items), 2, items)
        self.assertEqual({i["path"] for i in items},
                         {"R1 / Ports / Serial0/0 / Status", "R1 / Ports / Serial0/0 / IP"})

    def test_check_type_is_preserved(self):
        by_path = {i["path"]: i for i in insp.graded_items(self.text)}
        self.assertEqual(by_path["R1 / Ports / Serial0/0 / Status"]["check_type"], "1")
        self.assertEqual(by_path["R1 / Ports / Serial0/0 / IP"]["expected"], "10.0.0.1")


class Solver(unittest.TestCase):
    def test_solves_all_blocks(self):
        import pka_solve
        solved, info = pka_solve.solve(XML.decode("utf-8"))
        blocks = insp.blocks(solved)
        self.assertEqual(len(blocks), 3)
        # The answer key must land in every block: PT boots from block 0 and
        # resets the workspace from the others.
        for i, blk in enumerate(blocks):
            self.assertIn("no shutdown", blk, "block %d was not solved" % i)
        self.assertTrue(info.get("answer_key_present", True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
