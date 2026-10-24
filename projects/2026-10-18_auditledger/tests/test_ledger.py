"""Core ledger behavior tests.

Covers: init / append / head / digest round-trip, chain integrity
on a clean ledger, and that verify localises every documented
tamper to the exact seq / line.
"""

from __future__ import annotations

import json
import os
import unittest

from auditledger import (
    Ledger,
    LedgerError,
    append,
    digest,
    head,
    init,
    verify,
)
from auditledger.ledger import ZERO_HASH
from auditledger.types import Severity, Verdict
from tests.support import fresh_ledger_path, read_row, rewrite_line


# ---------------------------------------------------------------------------
# Init.
# ---------------------------------------------------------------------------

class InitTests(unittest.TestCase):
    def test_init_creates_empty_file(self):
        p = fresh_ledger_path()
        init(p)
        self.assertTrue(os.path.isfile(p))
        self.assertEqual(os.path.getsize(p), 0)

    def test_init_refuses_to_overwrite_live_ledger(self):
        p = fresh_ledger_path()
        init(p)
        append(p, "k", {"x": 1})
        self.assertRaises(LedgerError, init, p)

    def test_init_creates_parent_dir(self):
        p = fresh_ledger_path()
        nested = os.path.join(os.path.dirname(p), "a", "b", "c", "l.jsonl")
        init(nested)
        self.assertTrue(os.path.isfile(nested))


# ---------------------------------------------------------------------------
# Append + head + digest.
# ---------------------------------------------------------------------------

class AppendTests(unittest.TestCase):
    def test_first_append_sets_prev_to_zero(self):
        p = fresh_ledger_path()
        init(p)
        e = append(p, "boot", {"host": "a"},
                   ts="2026-10-18T09:00:00Z")
        self.assertEqual(e.seq, 0)
        self.assertEqual(e.prev, ZERO_HASH)
        self.assertEqual(len(e.hash), 64)

    def test_second_append_links_to_first(self):
        p = fresh_ledger_path()
        init(p)
        a = append(p, "a", {"x": 1}, ts="2026-10-18T09:00:00Z")
        b = append(p, "b", {"x": 2}, ts="2026-10-18T09:00:01Z")
        self.assertEqual(b.seq, 1)
        self.assertEqual(b.prev, a.hash)

    def test_head_matches_last_append(self):
        p = fresh_ledger_path()
        init(p)
        append(p, "a", {"x": 1}, ts="2026-10-18T09:00:00Z")
        e = append(p, "b", {"x": 2}, ts="2026-10-18T09:00:01Z")
        self.assertEqual(head(p).hash, e.hash)

    def test_digest_is_head_hash(self):
        p = fresh_ledger_path()
        init(p)
        e = append(p, "k", {"n": 1}, ts="2026-10-18T09:00:00Z")
        self.assertEqual(digest(p), e.hash)

    def test_digest_on_empty_is_none(self):
        p = fresh_ledger_path()
        init(p)
        self.assertIsNone(digest(p))

    def test_head_on_empty_is_none(self):
        p = fresh_ledger_path()
        init(p)
        self.assertIsNone(head(p))

    def test_append_rejects_empty_kind(self):
        p = fresh_ledger_path()
        init(p)
        self.assertRaises(LedgerError, append, p, "", {"x": 1})

    def test_append_rejects_nonstring_kind(self):
        p = fresh_ledger_path()
        init(p)
        self.assertRaises(LedgerError, append, p, 42, {"x": 1})

    def test_append_rejects_malformed_ts(self):
        p = fresh_ledger_path()
        init(p)
        self.assertRaises(LedgerError, append, p, "k", {"x": 1},
                          ts="yesterday afternoon")

    def test_append_rejects_nan_payload(self):
        p = fresh_ledger_path()
        init(p)
        self.assertRaises(LedgerError, append, p, "k",
                          {"x": float("nan")})


# ---------------------------------------------------------------------------
# Verify - clean path.
# ---------------------------------------------------------------------------

class VerifyCleanTests(unittest.TestCase):
    def test_empty_ledger_verifies_clean(self):
        p = fresh_ledger_path()
        init(p)
        res = verify(p)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.verdict, Verdict.HEALTHY)
        self.assertEqual(res.entries_checked, 0)
        self.assertIsNone(res.head_hash)

    def test_three_row_chain_clean(self):
        p = fresh_ledger_path()
        init(p)
        append(p, "a", {"x": 1}, ts="2026-10-18T09:00:00Z")
        append(p, "b", {"x": 2}, ts="2026-10-18T09:00:01Z")
        append(p, "c", {"x": 3}, ts="2026-10-18T09:00:02Z")
        res = verify(p)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.entries_checked, 3)
        self.assertEqual(res.head_hash, digest(p))


# ---------------------------------------------------------------------------
# Verify - defect localisation.
# ---------------------------------------------------------------------------

class VerifyTamperLocalisationTests(unittest.TestCase):

    def _three_row_ledger(self):
        p = fresh_ledger_path()
        init(p)
        append(p, "a", {"x": 1}, ts="2026-10-18T09:00:00Z")
        append(p, "b", {"x": 2}, ts="2026-10-18T09:00:01Z")
        append(p, "c", {"x": 3}, ts="2026-10-18T09:00:02Z")
        return p

    def _ids(self, result):
        return tuple(f.rule_id for f in result.findings)

    def test_AL_001_malformed_json(self):
        p = self._three_row_ledger()
        rewrite_line(p, 1, "{not valid json")
        res = verify(p)
        self.assertIn("AL-001", self._ids(res))
        # The HIGH severity localises to line 2.
        hits = [f for f in res.findings if f.rule_id == "AL-001"]
        self.assertEqual(hits[0].line_number, 2)

    def test_AL_002_row_not_object(self):
        p = self._three_row_ledger()
        rewrite_line(p, 1, '["seq", 1]')
        res = verify(p)
        self.assertIn("AL-002", self._ids(res))

    def test_AL_003_missing_required_field(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        del row["hash"]
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-003", self._ids(res))

    def test_AL_004_seq_gap(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["seq"] = 99
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-004", self._ids(res))

    def test_AL_005_prev_mismatch_localises(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["prev"] = "f" * 64  # legal shape, wrong value
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        ids = self._ids(res)
        self.assertIn("AL-005", ids)
        # Localisation: the tamper lives at seq=1.
        hit = next(f for f in res.findings if f.rule_id == "AL-005")
        self.assertEqual(hit.seq, 1)

    def test_AL_006_payload_edit_detected(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["payload"]["x"] = 999  # change payload, do not refresh hash
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-006", self._ids(res))

    def test_AL_007_bad_timestamp_shape(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["ts"] = "yesterday afternoon"
        # Recompute hash so this is a shape-only defect, not AL-006.
        from auditledger.canonical import canonical_bytes
        import hashlib
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-007", self._ids(res))

    def test_AL_008_bad_hash_shape(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["hash"] = "not-a-hex-digest"
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-008", self._ids(res))

    def test_AL_009_empty_kind(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["kind"] = ""
        # Recompute hash so this is a shape-only defect.
        from auditledger.canonical import canonical_bytes
        import hashlib
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-009", self._ids(res))

    def test_AL_010_extra_field_detected(self):
        # hash commits only to {seq, ts, kind, payload, prev}, so an
        # extra top-level field is a silent tamper surface the chain
        # alone will not catch. AL-010 closes that gap. The row's
        # existing hash is left intact: this is the exact attack it
        # defends against.
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["malicious_extra"] = "injected"
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        ids = self._ids(res)
        self.assertIn("AL-010", ids)
        self.assertNotIn("AL-006", ids)  # chain itself is intact
        hit = next(f for f in res.findings if f.rule_id == "AL-010")
        self.assertEqual(hit.seq, 1)
        self.assertEqual(hit.line_number, 2)
        self.assertIn("malicious_extra", hit.message)
        self.assertEqual(res.entries_checked, 3)  # walk continues
        self.assertEqual(res.verdict, Verdict.NEEDS_ATTENTION)

    def test_AL_010_multiple_extras_listed_sorted(self):
        p = self._three_row_ledger()
        row = read_row(p, 0)
        row["zeta"] = 1
        row["alpha"] = 2
        rewrite_line(p, 0, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        hit = next(f for f in res.findings if f.rule_id == "AL-010")
        # Field names appear in sorted order so the message is stable.
        self.assertIn("alpha, zeta", hit.message)

    def test_AL_011_string_seq_does_not_crash_walker(self):
        # Before AL-011, a row with a JSON-string seq crashed verify()
        # with TypeError on seq + 1 at the end of the row loop, taking
        # down the whole walk. The hostile ledger here recomputes the
        # row hash so the chain itself is intact; only the seq-type
        # rule can catch it.
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["seq"] = "notanint"
        from auditledger.canonical import canonical_bytes
        import hashlib
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        ids = self._ids(res)
        self.assertIn("AL-011", ids)
        self.assertNotIn("AL-004", ids)  # AL-011 subsumes AL-004 here
        hit = next(f for f in res.findings if f.rule_id == "AL-011")
        self.assertEqual(hit.line_number, 2)
        self.assertIn("notanint", hit.message)
        self.assertEqual(res.verdict, Verdict.UNHEALTHY)
        self.assertEqual(res.entries_checked, 3)  # walk continues

    def test_AL_011_null_seq_does_not_crash_walker(self):
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["seq"] = None
        from auditledger.canonical import canonical_bytes
        import hashlib
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-011", self._ids(res))
        self.assertEqual(res.entries_checked, 3)

    def test_AL_011_negative_seq(self):
        # A negative seq is syntactically an integer and would pass the
        # old guard but still breaks the +1-per-row invariant.
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["seq"] = -1
        from auditledger.canonical import canonical_bytes
        import hashlib
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-011", self._ids(res))

    def test_AL_011_bool_seq_is_rejected(self):
        # bool is an int subclass; without the explicit guard, seq=true
        # compares equal to seq=1 and slips past AL-004. The hash check
        # also fires here (canonical encoding of True is "true", not
        # "1"), but AL-011 is the rule that names the shape defect.
        p = self._three_row_ledger()
        row = read_row(p, 1)
        row["seq"] = True
        rewrite_line(p, 1, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertIn("AL-011", self._ids(res))


class LedgerFacade(unittest.TestCase):
    def test_facade_round_trip(self):
        p = fresh_ledger_path()
        L = Ledger(p)
        L.init()
        e1 = L.append("boot", {"x": 1}, ts="2026-10-18T09:00:00Z")
        e2 = L.append("decision", {"ok": True},
                      ts="2026-10-18T09:00:01Z")
        self.assertEqual(L.head().hash, e2.hash)
        self.assertEqual(L.digest(), e2.hash)
        self.assertEqual(L.verify().verdict, Verdict.HEALTHY)


class HighestSeverityIsReported(unittest.TestCase):
    def test_shape_defects_only_leads_to_needs_attention(self):
        p = fresh_ledger_path()
        init(p)
        append(p, "a", {"x": 1}, ts="2026-10-18T09:00:00Z")
        # Introduce a MEDIUM-only defect: rewrite with a bad hash
        # shape AND recompute hash to the right value? That is
        # self-defeating. So: use AL-007 (bad ts shape) with hash
        # repaired.
        row = read_row(p, 0)
        row["ts"] = "yesterday afternoon"
        from auditledger.canonical import canonical_bytes
        import hashlib
        core = {k: row[k] for k in
                ("seq", "ts", "kind", "payload", "prev")}
        row["hash"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        rewrite_line(p, 0, json.dumps(row, sort_keys=True,
                                      separators=(",", ":")))
        res = verify(p)
        self.assertEqual(res.verdict, Verdict.NEEDS_ATTENTION)
        self.assertTrue(all(f.severity != Severity.HIGH
                            for f in res.findings))


class VerifyOnMissingFile(unittest.TestCase):
    def test_raises_ledger_error(self):
        self.assertRaises(LedgerError, verify,
                          "/no/such/path/does/not/exist.jsonl")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
