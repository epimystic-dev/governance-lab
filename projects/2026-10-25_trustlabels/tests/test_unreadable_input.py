"""Unreadable input (binary or non-UTF-8 bytes) exits 2 with a message, never a traceback."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.support import run_cli

PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = {
    "latin1.json": b'{"labels": "caf\xe9"}',
    "binary.json": bytes(range(256)) * 4,
}


class UnreadableInput(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="tl_unreadable_")
        for name, data in CASES.items():
            with open(os.path.join(self.d, name), "wb") as fh:
                fh.write(data)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_in_process_rc2(self):
        for name in CASES:
            rc, out, err = run_cli([os.path.join(self.d, name)])
            self.assertEqual(rc, 2, name)
            self.assertIn("cannot read", err, name)

    def test_subprocess_no_traceback(self):
        env = dict(os.environ, PYTHONPATH=PKG_DIR)
        for name in CASES:
            p = subprocess.run([sys.executable, "-m", "trustlabels", os.path.join(self.d, name)],
                               capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(p.returncode, 2, name)
            self.assertNotIn("Traceback", p.stdout + p.stderr, name)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
