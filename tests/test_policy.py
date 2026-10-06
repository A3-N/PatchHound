import contextlib
import io
import unittest

from patchhound.policy import _build_audit, _print_reused


class PolicyAuditTests(unittest.TestCase):
    def test_special_character_frequency_counts_passwords_not_occurrences(self):
        records = [
            {"name": "CORP\\alice", "sam": "ALICE", "nt": "1" * 32},
            {"name": "CORP\\bob", "sam": "BOB", "nt": "2" * 32},
        ]
        audit = _build_audit(
            records,
            {"1" * 32: "Pass!!!", "2" * 32: "Other!"},
        )
        self.assertEqual(2, audit["special_char_freq"]["!"])

    def test_single_password_is_not_duplicated_as_shortest_and_longest(self):
        records = [{"name": "CORP\\alice", "sam": "ALICE", "nt": "1" * 32}]
        audit = _build_audit(records, {"1" * 32: "OnlyPass!"})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _print_reused({"info": "[*]"}, audit)
        self.assertEqual(1, output.getvalue().count("OnlyPass!"))


if __name__ == "__main__":
    unittest.main()
