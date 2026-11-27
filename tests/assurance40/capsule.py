"""Ordinary offline checks for unsigned evidence metadata."""
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("capsule", ROOT / "tools/assurance_capsule.py")
capsule = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capsule)


class CapsuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = pathlib.Path(self.tmp.name)
        self.report = json.loads((ROOT / "docs/assurance40/examples/build.json").read_bytes())

    def write(self):
        (self.directory / capsule.EVIDENCE).write_bytes(capsule.encode(self.report))

    def test_round_trip_deterministic(self):
        self.write()
        first = capsule.produce(self.directory)
        data = (self.directory / capsule.CAPSULE).read_bytes()
        self.assertEqual(first, capsule.verify(self.directory))
        capsule.produce(self.directory)
        self.assertEqual(data, (self.directory / capsule.CAPSULE).read_bytes())
        self.assertFalse(first["signed"])

    def test_difference_is_recorded(self):
        self.report["artifact"]["build_b_sha256"] = "5" * 64
        self.report["artifact"]["equal"] = False
        self.write()
        self.assertEqual(capsule.produce(self.directory)["results"],
                         {"two_build_digest_comparison": "mismatch"})
        capsule.verify(self.directory)

    def test_evidence_revision_changes(self):
        self.write()
        capsule.produce(self.directory)
        self.report["source_commit"] = "6" * 40
        self.write()
        with self.assertRaises(ValueError):
            capsule.verify(self.directory)


if __name__ == "__main__":
    unittest.main()
