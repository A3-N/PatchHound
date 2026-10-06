import unittest

from patchhound.identity import build_target_index, match_rows


class IdentityMatchingTests(unittest.TestCase):
    def setUp(self):
        domains = [
            {"name": "CORP.EXAMPLE", "netbios": "CORP"},
            {"name": "CHILD.EXAMPLE", "netbios": "CHILD"},
        ]
        nodes = [
            {
                "labels": ["User"],
                "objectid": "S-1-5-21-1-1001",
                "name": "ALICE@CORP.EXAMPLE",
                "domain": "CORP.EXAMPLE",
                "sam": "alice",
                "upn": "alice@people.example",
            },
            {
                "labels": ["User"],
                "objectid": "S-1-5-21-2-1001",
                "name": "ALICE@CHILD.EXAMPLE",
                "domain": "CHILD.EXAMPLE",
                "sam": "alice",
                "upn": "alice@child.example",
            },
            {
                "labels": ["User"],
                "objectid": "S-1-5-21-1-1002",
                "name": "BOB@CORP.EXAMPLE",
                "domain": "CORP.EXAMPLE",
                "sam": "bob",
                "upn": "bob@people.example",
            },
            {
                "labels": ["Computer"],
                "objectid": "S-1-5-21-1-2001",
                "name": "WS01.CORP.EXAMPLE",
                "domain": "CORP.EXAMPLE",
                "sam": None,
                "upn": None,
            },
            {
                "labels": ["AZUser"],
                "objectid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                "name": "alice@people.example",
                "upn": "alice@people.example",
            },
        ]
        self.index, self.stats = build_target_index(domains, nodes)

    @staticmethod
    def row(**overrides):
        value = {
            "name": "CORP\\alice",
            "domain": "CORP",
            "sam": "ALICE",
            "upn": "",
            "nt": "a" * 32,
            "pwd": "Password1!",
        }
        value.update(overrides)
        return value

    def test_downlevel_name_is_scoped_by_netbios_domain(self):
        updates, unmatched, ambiguous = match_rows([self.row()], self.index)
        self.assertEqual(["S-1-5-21-1-1001"], [row["objectid"] for row in updates])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)

    def test_bare_duplicate_sam_is_rejected_as_ambiguous(self):
        updates, unmatched, ambiguous = match_rows([self.row(name="alice", domain="")], self.index)
        self.assertFalse(updates)
        self.assertFalse(unmatched)
        self.assertEqual("ambiguous_unscoped_sam", ambiguous[0]["match_reason"])

    def test_actual_upn_can_match_ad_user_but_never_azuser(self):
        updates, unmatched, ambiguous = match_rows(
            [self.row(name="alice@people.example", domain="", sam="", upn="alice@people.example")],
            self.index,
        )
        self.assertEqual(["User"], [row["kind"] for row in updates])
        self.assertEqual(["S-1-5-21-1-1001"], [row["objectid"] for row in updates])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)

    def test_unknown_domain_uses_globally_unique_sam_offline(self):
        updates, unmatched, ambiguous = match_rows(
            [self.row(name="MISSING\\bob", domain="MISSING", sam="bob")], self.index
        )
        self.assertEqual(["S-1-5-21-1-1002"], [row["objectid"] for row in updates])
        self.assertEqual("unique_sam_fallback", updates[0]["match_reason"])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)

    def test_unknown_domain_still_rejects_duplicate_sam(self):
        updates, unmatched, ambiguous = match_rows(
            [self.row(name="MISSING\\alice", domain="MISSING")], self.index
        )
        self.assertFalse(updates)
        self.assertFalse(unmatched)
        self.assertEqual("ambiguous_domain_sam", ambiguous[0]["match_reason"])

    def test_computer_sam_is_derived_from_bloodhound_name(self):
        updates, unmatched, ambiguous = match_rows(
            [self.row(name="CORP\\WS01$", sam="WS01$")], self.index
        )
        self.assertEqual(["Computer"], [row["kind"] for row in updates])
        self.assertEqual(["S-1-5-21-1-2001"], [row["objectid"] for row in updates])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)

    def test_node_domain_can_resolve_when_domain_node_is_missing(self):
        index, _ = build_target_index(
            [],
            [
                {
                    "labels": ["User"],
                    "objectid": "S-1-5-21-9-1001",
                    "name": "BOB@LEGACY.EXAMPLE",
                    "domain": "LEGACY.EXAMPLE",
                    "sam": "bob",
                    "upn": "bob@login.example",
                }
            ],
        )
        updates, unmatched, ambiguous = match_rows(
            [self.row(name="LEGACY\\bob", domain="LEGACY", sam="BOB")], index
        )
        self.assertEqual(["S-1-5-21-9-1001"], [row["objectid"] for row in updates])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)

    def test_dollar_suffix_does_not_guess_user_vs_computer(self):
        index, _ = build_target_index(
            [{"name": "CORP.EXAMPLE", "netbios": "CORP"}],
            [
                {
                    "labels": ["User"],
                    "objectid": "S-1-U",
                    "name": "SVC$@CORP.EXAMPLE",
                    "domain": "CORP.EXAMPLE",
                    "sam": "svc$",
                },
                {
                    "labels": ["Computer"],
                    "objectid": "S-1-C",
                    "name": "SVC.CORP.EXAMPLE",
                    "domain": "CORP.EXAMPLE",
                    "sam": "svc$",
                },
            ],
        )
        updates, unmatched, ambiguous = match_rows([self.row(name="CORP\\svc$", sam="SVC$")], index)
        self.assertFalse(updates)
        self.assertFalse(unmatched)
        self.assertEqual("ambiguous_scoped_sam", ambiguous[0]["match_reason"])

    def test_unknown_netbios_alias_is_learned_from_two_unique_sams(self):
        index, _ = build_target_index(
            [],
            [
                {
                    "labels": ["User"],
                    "objectid": "S-LEGACY-ALICE",
                    "name": "ALICE@LEGACY.EXAMPLE",
                    "domain": "LEGACY.EXAMPLE",
                    "sam": "alice",
                },
                {
                    "labels": ["User"],
                    "objectid": "S-OTHER-ALICE",
                    "name": "ALICE@OTHER.EXAMPLE",
                    "domain": "OTHER.EXAMPLE",
                    "sam": "alice",
                },
                {
                    "labels": ["User"],
                    "objectid": "S-LEGACY-BOB",
                    "name": "BOB@LEGACY.EXAMPLE",
                    "domain": "LEGACY.EXAMPLE",
                    "sam": "bob",
                },
                {
                    "labels": ["User"],
                    "objectid": "S-LEGACY-CAROL",
                    "name": "CAROL@LEGACY.EXAMPLE",
                    "domain": "LEGACY.EXAMPLE",
                    "sam": "carol",
                },
            ],
        )
        rows = [
            self.row(name="WIDGET\\bob", domain="WIDGET", sam="bob"),
            self.row(name="WIDGET\\carol", domain="WIDGET", sam="carol"),
            self.row(name="WIDGET\\alice", domain="WIDGET", sam="alice"),
        ]
        updates, unmatched, ambiguous = match_rows(rows, index)
        self.assertEqual(
            {"S-LEGACY-ALICE", "S-LEGACY-BOB", "S-LEGACY-CAROL"},
            {row["objectid"] for row in updates},
        )
        alice = next(row for row in updates if row["objectid"] == "S-LEGACY-ALICE")
        self.assertEqual("learned_domain", alice["match_reason"])
        self.assertEqual({"legacy.example"}, index["learned_domain_aliases"]["widget"])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)

    def test_conflicting_unique_sams_do_not_teach_a_domain_alias(self):
        index, _ = build_target_index(
            [],
            [
                {
                    "labels": ["User"],
                    "objectid": "S-LEGACY-ALICE",
                    "name": "ALICE@LEGACY.EXAMPLE",
                    "domain": "LEGACY.EXAMPLE",
                    "sam": "alice",
                },
                {
                    "labels": ["User"],
                    "objectid": "S-OTHER-ALICE",
                    "name": "ALICE@OTHER.EXAMPLE",
                    "domain": "OTHER.EXAMPLE",
                    "sam": "alice",
                },
                {
                    "labels": ["User"],
                    "objectid": "S-LEGACY-BOB",
                    "name": "BOB@LEGACY.EXAMPLE",
                    "domain": "LEGACY.EXAMPLE",
                    "sam": "bob",
                },
                {
                    "labels": ["User"],
                    "objectid": "S-OTHER-CAROL",
                    "name": "CAROL@OTHER.EXAMPLE",
                    "domain": "OTHER.EXAMPLE",
                    "sam": "carol",
                },
            ],
        )
        rows = [
            self.row(name="WIDGET\\bob", domain="WIDGET", sam="bob"),
            self.row(name="WIDGET\\carol", domain="WIDGET", sam="carol"),
            self.row(name="WIDGET\\alice", domain="WIDGET", sam="alice"),
        ]
        updates, unmatched, ambiguous = match_rows(rows, index)
        self.assertEqual({"S-LEGACY-BOB", "S-OTHER-CAROL"}, {row["objectid"] for row in updates})
        self.assertNotIn("widget", index["learned_domain_aliases"])
        self.assertFalse(unmatched)
        self.assertEqual("ambiguous_domain_sam", ambiguous[0]["match_reason"])

    def test_conflicting_sam_and_real_upn_are_rejected(self):
        updates, unmatched, ambiguous = match_rows(
            [
                self.row(
                    name="CORP\\alice",
                    domain="CORP",
                    sam="alice",
                    upn="alice@child.example",
                )
            ],
            self.index,
        )
        self.assertFalse(updates)
        self.assertFalse(unmatched)
        self.assertEqual("ambiguous_conflicting_identifiers", ambiguous[0]["match_reason"])

    def test_last_identifier_for_the_same_node_is_authoritative(self):
        old = self.row(nt="1" * 32, pwd="old password")
        current = self.row(
            name="alice@people.example",
            domain="",
            sam="",
            upn="alice@people.example",
            nt="2" * 32,
            pwd=None,
        )
        updates, unmatched, ambiguous = match_rows([old, current], self.index)
        self.assertEqual(1, len(updates))
        self.assertEqual("2" * 32, updates[0]["nt"])
        self.assertIsNone(updates[0]["pwd"])
        self.assertFalse(unmatched)
        self.assertFalse(ambiguous)


if __name__ == "__main__":
    unittest.main()
