import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from patchhound.credentials import analyze_ntlm_file, analyze_potfile
from patchhound.patch import (
    _append_owned_selectors,
    _apply_updates,
    _batched_selector_payload,
    _collect_owned_candidate_sids,
    _fetch_existing_owned_selectors,
    _plan_owned_selector_sync,
    _verbose_hint,
)

LM = "aad3b435b51404eeaad3b435b51404ee"
NT1 = "11111111111111111111111111111111"
NT2 = "22222222222222222222222222222222"


def selector_fixture(entries, batch_index=1):
    name, payload = _batched_selector_payload(entries, batch_index)
    return {"name": name, "payload": payload, "seed_count": len(payload["seeds"])}


class CredentialParsingTests(unittest.TestCase):
    @staticmethod
    def temporary_file(contents: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        with handle:
            handle.write(contents)
        return handle.name

    def tearDown(self):
        for path in getattr(self, "paths", []):
            Path(path).unlink(missing_ok=True)

    def remember(self, contents: str) -> str:
        path = self.temporary_file(contents)
        self.paths = getattr(self, "paths", []) + [path]
        return path

    def test_secretsdump_identity_parts_are_kept_distinct(self):
        path = self.remember(
            f"CORP\\alice:1001:{LM}:{NT1}::: alice@people.example (status=Enabled)\n"
            f"ad.example\\bob:1002:{LM}:{NT2}::: (status=Disabled)\n"
        )
        records = analyze_ntlm_file(path)["_records"]

        self.assertEqual("CORP", records[0]["domain"])
        self.assertEqual("ALICE", records[0]["sam"])
        self.assertEqual("ALICE@PEOPLE.EXAMPLE", records[0]["upn"])
        self.assertEqual("enabled", records[0]["status"])

        self.assertEqual("ad.example", records[1]["domain"])
        self.assertEqual("BOB", records[1]["sam"])
        self.assertEqual("", records[1]["upn"])
        self.assertEqual("disabled", records[1]["status"])

    def test_upn_account_is_not_treated_as_sam(self):
        path = self.remember(f"alice@people.example:1001:{LM}:{NT1}:::\n")
        record = analyze_ntlm_file(path)["_records"][0]
        self.assertEqual("", record["domain"])
        self.assertEqual("", record["sam"])
        self.assertEqual("ALICE@PEOPLE.EXAMPLE", record["upn"])

    def test_downlevel_account_preserves_spaces(self):
        path = self.remember(f"test.local\\user name:1001:{LM}:{NT1}:::\n")
        record = analyze_ntlm_file(path)["_records"][0]
        self.assertEqual("test.local\\user name", record["name"])
        self.assertEqual("test.local", record["domain"])
        self.assertEqual("USER NAME", record["sam"])

    def test_latest_hash_for_one_account_is_authoritative(self):
        path = self.remember(f"CORP\\alice:1001:{LM}:{NT1}:::\nCORP\\alice:1001:{LM}:{NT2}:::\n")
        records = analyze_ntlm_file(path)["_records"]
        self.assertEqual(1, len(records))
        self.assertEqual(NT2, records[0]["nt"])

    def test_repeated_hash_moves_account_to_its_true_latest_position(self):
        path = self.remember(
            f"CORP\\alice:1001:{LM}:{NT1}:::\n"
            f"CORP\\bob:1002:{LM}:{NT2}:::\n"
            f"CORP\\alice:1001:{LM}:{NT1}:::\n"
        )
        records = analyze_ntlm_file(path)["_records"]
        self.assertEqual(["BOB", "ALICE"], [record["sam"] for record in records])

    def test_potfile_preserves_empty_password_as_a_crack(self):
        path = self.remember(f"{NT1}:\n")
        stats = analyze_potfile(path)
        self.assertEqual("", stats["_cracked_map"][NT1])
        self.assertEqual(1, stats["valid_entries"])

    def test_potfile_preserves_password_whitespace(self):
        path = self.remember(f"{NT1}:  password with spaces  \r\n")
        stats = analyze_potfile(path)
        self.assertEqual("  password with spaces  ", stats["_cracked_map"][NT1])


class OutputFormattingTests(unittest.TestCase):
    def test_verbose_hint_colors_only_the_parenthesized_flag(self):
        self.assertEqual(" use (-v)", _verbose_hint(False, True))
        self.assertEqual(" use \x1b[33m(-v)\x1b[0m", _verbose_hint(False, False))
        self.assertEqual("", _verbose_hint(True, False))


class OwnedSelectorTests(unittest.TestCase):
    class Response:
        def __init__(self, status_code, body=None, headers=None):
            self.status_code = status_code
            self.body = body or {}
            self.headers = headers or {}

        def json(self):
            return self.body

    @patch("patchhound.patch.time.sleep", return_value=None)
    @patch("patchhound.patch.requests.request")
    @patch("patchhound.patch.requests.get")
    def test_selector_upload_deduplicates_and_retries_rate_limits(self, get, request, _sleep):
        get.return_value = self.Response(200, {"data": {"selectors": []}, "count": 0})
        request.side_effect = [
            self.Response(429, headers={"Retry-After": "0"}),
            self.Response(201),
        ]
        candidates = [
            {"sid": "S-1-5-21-1-1001", "name": "ALICE@CORP.EXAMPLE"},
            {"sid": "s-1-5-21-1-1001", "name": "duplicate"},
        ]

        result = _append_owned_selectors(
            "http://bloodhound/",
            "token",
            2,
            candidates,
            {"ok": "[+]", "info": "[*]", "warn": "[!]"},
            verbose=False,
            workers=1,
            rate_delay=0,
            seeds_per_selector=500,
            nocolor=True,
        )

        self.assertEqual(1, result["attempted"])
        self.assertEqual(1, result["added"])
        self.assertEqual(1, result["rate_limited"])
        self.assertEqual(2, request.call_count)
        payload = request.call_args.kwargs["json"]
        self.assertEqual("S-1-5-21-1-1001", payload["seeds"][0]["value"])

    @patch("patchhound.patch.requests.get")
    def test_inventory_reads_all_reported_pages(self, get):
        get.side_effect = [
            self.Response(
                200,
                {
                    "data": {"selectors": [{"seeds": [{"type": 1, "value": "S-1-1"}]}]},
                    "count": 2,
                },
            ),
            self.Response(
                200,
                {
                    "data": {"selectors": [{"seeds": [{"type": 1, "value": "S-1-2"}]}]},
                    "count": 2,
                },
            ),
        ]
        existing = _fetch_existing_owned_selectors(
            "http://bloodhound/",
            "token",
            2,
            {"ok": "[+]", "info": "[*]", "warn": "[!]"},
            False,
        )
        self.assertEqual(2, len(existing))
        self.assertEqual(
            {"S-1-1", "S-1-2"},
            {seed["value"] for selector in existing for seed in selector["seeds"]},
        )
        self.assertEqual([0, 1], [call.kwargs["params"]["skip"] for call in get.call_args_list])

    @patch("patchhound.patch.time.sleep", return_value=None)
    @patch("patchhound.patch.requests.get")
    def test_inventory_retries_rate_limits(self, get, _sleep):
        get.side_effect = [
            self.Response(429, headers={"Retry-After": "0"}),
            self.Response(200, {"data": {"selectors": []}, "count": 0}),
        ]
        existing = _fetch_existing_owned_selectors(
            "http://bloodhound/",
            "token",
            2,
            {"ok": "[+]", "info": "[*]", "warn": "[!]"},
            False,
            max_retries=2,
        )
        self.assertEqual([], existing)
        self.assertEqual(2, get.call_count)

    def test_grouped_selector_names_are_deterministic(self):
        candidates = [
            {"sid": "S-1-5-2", "name": "two"},
            {"sid": "S-1-5-1", "name": "one"},
        ]
        first = selector_fixture(candidates)
        second = selector_fixture(list(reversed(candidates)))
        self.assertEqual(first, second)
        self.assertEqual(2, first["seed_count"])
        self.assertEqual(2, len(first["payload"]["seeds"]))

    def test_changed_batch_is_patched_in_place(self):
        old = selector_fixture([{"sid": "S-1-OLD", "name": "old"}])
        existing = [{"id": 42, "name": old["name"], "seeds": old["payload"]["seeds"]}]
        upserts, deletes, unchanged = _plan_owned_selector_sync(
            "http://bloodhound/",
            2,
            [{"sid": "S-1-NEW", "name": "new"}],
            500,
            existing,
        )
        self.assertEqual("PATCH", upserts[0]["method"])
        self.assertEqual(
            "http://bloodhound/api/v2/asset-group-tags/2/selectors/42", upserts[0]["url"]
        )
        self.assertFalse(deletes)
        self.assertEqual(0, unchanged)

    def test_obsolete_managed_selector_is_deleted_but_manual_is_untouched(self):
        managed = selector_fixture([{"sid": "S-1-OLD", "name": "old"}])
        existing = [
            {"id": 42, "name": managed["name"], "seeds": managed["payload"]["seeds"]},
            {"id": 99, "name": "Manual Owner", "seeds": [{"type": 1, "value": "S-1-MANUAL"}]},
        ]
        upserts, deletes, unchanged = _plan_owned_selector_sync(
            "http://bloodhound/", 2, [], 500, existing
        )
        self.assertFalse(upserts)
        self.assertEqual([42], [int(item["url"].rsplit("/", 1)[1]) for item in deletes])
        self.assertEqual(0, unchanged)

    def test_removing_from_first_batch_does_not_reshape_later_batches(self):
        first = selector_fixture(
            [
                {"sid": "S-1-A", "name": "a"},
                {"sid": "S-1-B", "name": "b"},
            ]
        )
        # The fixture uses slot 1; model the real slot 2 separately.
        second_name, second_payload = _batched_selector_payload(
            [{"sid": "S-1-C"}, {"sid": "S-1-D"}], 2
        )
        existing = [
            {"id": 10, "name": first["name"], "seeds": first["payload"]["seeds"]},
            {"id": 20, "name": second_name, "seeds": second_payload["seeds"]},
        ]
        candidates = [
            {"sid": "S-1-B", "name": "b"},
            {"sid": "S-1-C", "name": "c"},
            {"sid": "S-1-D", "name": "d"},
        ]
        upserts, deletes, unchanged = _plan_owned_selector_sync(
            "http://bloodhound/", 2, candidates, 2, existing
        )
        self.assertEqual([10], [int(item["url"].rsplit("/", 1)[1]) for item in upserts])
        self.assertFalse(deletes)
        self.assertEqual(2, unchanged)

    def test_smaller_batch_size_splits_an_existing_oversized_selector(self):
        previous = selector_fixture(
            [
                {"sid": "S-1-A", "name": "a"},
                {"sid": "S-1-B", "name": "b"},
                {"sid": "S-1-C", "name": "c"},
                {"sid": "S-1-D", "name": "d"},
            ]
        )
        existing = [{"id": 10, "name": previous["name"], "seeds": previous["payload"]["seeds"]}]
        candidates = [
            {"sid": "S-1-A", "name": "a"},
            {"sid": "S-1-B", "name": "b"},
            {"sid": "S-1-C", "name": "c"},
            {"sid": "S-1-D", "name": "d"},
        ]

        upserts, deletes, unchanged = _plan_owned_selector_sync(
            "http://bloodhound/", 2, candidates, 2, existing
        )

        self.assertEqual(["PATCH", "POST"], [item["method"] for item in upserts])
        self.assertEqual([2, 2], [item["seed_count"] for item in upserts])
        self.assertFalse(deletes)
        self.assertEqual(0, unchanged)

    @patch("patchhound.patch.requests.request")
    @patch("patchhound.patch.requests.get")
    def test_uncracked_processed_sid_is_removed_but_unprocessed_sid_is_preserved(
        self, get, request
    ):
        previous = selector_fixture(
            [
                {"sid": "S-1-KEEP", "name": "keep"},
                {"sid": "S-1-CHANGED", "name": "changed"},
            ]
        )
        get.return_value = self.Response(
            200,
            {
                "data": {
                    "selectors": [
                        {
                            "id": 42,
                            "name": previous["name"],
                            "seeds": previous["payload"]["seeds"],
                        }
                    ]
                },
                "count": 1,
            },
        )
        request.return_value = self.Response(200)
        result = _append_owned_selectors(
            "http://bloodhound/",
            "token",
            2,
            [],
            {"ok": "[+]", "info": "[*]", "warn": "[!]"},
            verbose=False,
            workers=1,
            processed_sids={"S-1-CHANGED"},
            nocolor=True,
        )
        self.assertEqual(1, result["removed"])
        self.assertEqual(1, result["updated"])
        payload = request.call_args.kwargs["json"]
        self.assertEqual(["S-1-KEEP"], [seed["value"] for seed in payload["seeds"]])

    @patch("patchhound.patch.requests.request")
    @patch("patchhound.patch.requests.get")
    def test_unchanged_managed_batch_costs_no_write_request(self, get, request):
        desired = selector_fixture([{"sid": "S-1-5-21-1-1001", "name": "ALICE@CORP.EXAMPLE"}])
        get.return_value = self.Response(
            200,
            {
                "data": {
                    "selectors": [
                        {
                            "id": 42,
                            "name": desired["name"],
                            "seeds": desired["payload"]["seeds"],
                        }
                    ]
                },
                "count": 1,
            },
        )
        result = _append_owned_selectors(
            "http://bloodhound/",
            "token",
            2,
            [{"sid": "S-1-5-21-1-1001", "name": "ALICE@CORP.EXAMPLE"}],
            {"ok": "[+]", "info": "[*]", "warn": "[!]"},
            verbose=False,
            nocolor=True,
        )
        self.assertEqual(1, result["exists"])
        self.assertEqual(1, result["attempted"])
        self.assertEqual(0, result["selector_requests"])
        request.assert_not_called()


class GraphWriteTests(unittest.TestCase):
    class Result:
        def __init__(self, record):
            self.record = record

        def single(self):
            return self.record

    class Session:
        def __init__(self):
            self.calls = []

        def run(self, query, **kwargs):
            self.calls.append((query, kwargs))
            if "SyncedToEntraUser" in query:
                return GraphWriteTests.Result({"linked": 1})
            return GraphWriteTests.Result({"updated": len(kwargs["rows"])})

    def test_writes_use_stable_objectid_and_current_password_state(self):
        session = self.Session()
        updated = _apply_updates(
            session,
            [
                {"kind": "User", "objectid": "S-1-U", "nt": NT1, "pwd": None},
                {"kind": "Computer", "objectid": "S-1-C", "nt": NT2, "pwd": "secret"},
            ],
            False,
        )
        self.assertEqual(2, updated)
        queries = "\n".join(query for query, _ in session.calls)
        self.assertIn("{objectid:r.objectid}", queries)
        self.assertIn("Patchhound_has_pass = r.pwd IS NOT NULL", queries)
        self.assertNotIn("id(n)", queries)

    def test_owned_candidates_are_cracked_ad_users_from_this_run_only(self):
        session = self.Session()
        candidates, linked, processed = _collect_owned_candidate_sids(
            session,
            [
                {"kind": "User", "objectid": "S-1-U", "target_name": "ALICE@CORP", "pwd": "secret"},
                {"kind": "User", "objectid": "S-1-NO", "target_name": "BOB@CORP", "pwd": None},
                {
                    "kind": "Computer",
                    "objectid": "S-1-C",
                    "target_name": "WS.CORP",
                    "pwd": "secret",
                },
            ],
        )
        self.assertEqual([{"sid": "S-1-U", "name": "ALICE@CORP"}], candidates)
        self.assertEqual(1, linked)
        self.assertEqual({"S-1-U", "S-1-NO"}, processed)
        self.assertIn("SyncedToEntraUser", session.calls[0][0])


if __name__ == "__main__":
    unittest.main()
