"""CLI behaviour tests (in-process)."""

from __future__ import annotations

import json
import os
import unittest

from auditledger import __version__
from tests.support import fresh_ledger_path, run_cli


class InitAndAppend(unittest.TestCase):
    def test_init_then_append(self):
        p = fresh_ledger_path()
        rc, out, err = run_cli(["init", p])
        self.assertEqual(rc, 0, (out, err))
        self.assertTrue(os.path.isfile(p))

        rc, out, err = run_cli([
            "append", p, "--kind", "boot",
            "--payload", '{"x": 1}',
            "--ts", "2026-10-18T09:00:00Z",
        ])
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("appended seq=0", out)

    def test_append_json_output(self):
        p = fresh_ledger_path()
        run_cli(["init", p])
        rc, out, _ = run_cli([
            "append", p, "--kind", "boot",
            "--payload", '{"x": 1}',
            "--ts", "2026-10-18T09:00:00Z",
            "--json",
        ])
        self.assertEqual(rc, 0)
        row = json.loads(out)
        self.assertEqual(row["seq"], 0)
        self.assertEqual(len(row["hash"]), 64)

    def test_append_invalid_json_payload_rc_two(self):
        p = fresh_ledger_path()
        run_cli(["init", p])
        rc, out, err = run_cli([
            "append", p, "--kind", "boot",
            "--payload", "{not valid json",
        ])
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", err)

    def test_init_twice_rc_two(self):
        p = fresh_ledger_path()
        run_cli(["init", p])
        run_cli([
            "append", p, "--kind", "boot",
            "--payload", "{}",
            "--ts", "2026-10-18T09:00:00Z",
        ])
        rc, out, err = run_cli(["init", p])
        self.assertEqual(rc, 2)
        self.assertIn("already exists", err)


class VerifyFlow(unittest.TestCase):
    def _two_row_clean(self):
        p = fresh_ledger_path()
        run_cli(["init", p])
        run_cli([
            "append", p, "--kind", "boot",
            "--payload", '{"x": 1}',
            "--ts", "2026-10-18T09:00:00Z",
        ])
        run_cli([
            "append", p, "--kind", "decision",
            "--payload", '{"ok": true}',
            "--ts", "2026-10-18T09:00:01Z",
        ])
        return p

    def test_verify_clean_rc_zero(self):
        p = self._two_row_clean()
        rc, out, err = run_cli(["verify", p])
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("verdict: healthy", out)

    def test_verify_tampered_rc_two(self):
        p = self._two_row_clean()
        with open(p, "r", encoding="utf-8") as f:
            lines = f.readlines()
        row = json.loads(lines[1])
        row["payload"]["ok"] = False
        lines[1] = json.dumps(row, sort_keys=True,
                              separators=(",", ":")) + "\n"
        with open(p, "w", encoding="utf-8") as f:
            f.writelines(lines)

        rc, out, err = run_cli(["verify", p])
        self.assertEqual(rc, 2)
        self.assertIn("AL-006", out)

    def test_verify_json_output_parses(self):
        p = self._two_row_clean()
        rc, out, _ = run_cli(["verify", p, "--json"])
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(report["verdict"], "healthy")
        self.assertEqual(report["entries_checked"], 2)
        self.assertEqual(len(report["head_hash"]), 64)
        self.assertEqual(report["findings"], [])

    def test_verify_disable_rule(self):
        p = self._two_row_clean()
        # Introduce an AL-007 (MEDIUM, non-blocking) by rewriting ts
        # AND recomputing hash so no AL-006 fires.
        import hashlib
        from auditledger import canonical_bytes
        with open(p, "r", encoding="utf-8") as f:
            lines = f.readlines()
        row = json.loads(lines[0])
        row["ts"] = "yesterday afternoon"
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        lines[0] = json.dumps(row, sort_keys=True,
                              separators=(",", ":")) + "\n"
        # Also need to update row 2's prev to match row 1's new hash,
        # or AL-005 fires. Easier: just test disable on tampered row 1.
        row2 = json.loads(lines[1])
        row2["prev"] = row["hash"]
        core2 = {k: row2[k] for k in
                 ("seq", "ts", "kind", "payload", "prev")}
        row2["hash"] = hashlib.sha256(canonical_bytes(core2)).hexdigest()
        lines[1] = json.dumps(row2, sort_keys=True,
                              separators=(",", ":")) + "\n"
        with open(p, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Baseline: AL-007 fires -> rc 1.
        rc, out, _ = run_cli(["verify", p])
        self.assertEqual(rc, 1)
        self.assertIn("AL-007", out)

        # Disable: no findings -> rc 0.
        rc, out, _ = run_cli(["verify", p, "--disable", "AL-007"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("AL-007", out)


class DigestAndHead(unittest.TestCase):
    def test_digest_empty_ledger(self):
        p = fresh_ledger_path()
        run_cli(["init", p])
        rc, out, _ = run_cli(["digest", p])
        self.assertEqual(rc, 0)
        self.assertIn("empty", out)

    def test_digest_matches_head_hash(self):
        p = fresh_ledger_path()
        run_cli(["init", p])
        run_cli([
            "append", p, "--kind", "boot",
            "--payload", '{"x": 1}',
            "--ts", "2026-10-18T09:00:00Z",
        ])
        rc, dig_out, _ = run_cli(["digest", p])
        self.assertEqual(rc, 0)
        rc, head_out, _ = run_cli(["head", p])
        self.assertEqual(rc, 0)
        head_row = json.loads(head_out)
        self.assertEqual(dig_out.strip(), head_row["hash"])


class PrintRules(unittest.TestCase):
    def test_print_rules(self):
        rc, out, _ = run_cli(["--print-rules"])
        self.assertEqual(rc, 0)
        self.assertIn("AL-001", out)
        self.assertIn("AL-009", out)


class AsciiSafety(unittest.TestCase):
    def test_non_ascii_path_rendered_safe(self):
        # If a user passes a path containing a zero-width space the
        # text report must not crash on cp1252 encoding; the
        # character must appear as its codepoint escape.
        zwsp = chr(0x200B)
        p = fresh_ledger_path()
        run_cli(["init", p])
        # Move the ledger to a path containing the zwsp.
        new_p = p.replace("ledger.jsonl", "ledger" + zwsp + ".jsonl")
        os.rename(p, new_p)
        rc, out, err = run_cli(["verify", new_p])
        self.assertEqual(rc, 0)
        self.assertIn("<U+200B>", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
