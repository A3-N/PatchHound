import contextlib
import io
import unittest

from patchhound.cli import build_parser


class CLIParserTests(unittest.TestCase):
    def setUp(self):
        self.parser, _auth, self.patch_parser, _policy = build_parser()

    def test_global_verbose_survives_subcommand_defaults(self):
        args = self.parser.parse_args(
            [
                "--verbose",
                "patch",
                "--clears",
                "pot",
                "--ntlm",
                "ntds",
            ]
        )
        self.assertTrue(args.verbose)

    def test_subcommand_verbose_is_supported(self):
        args = self.parser.parse_args(
            [
                "patch",
                "--verbose",
                "--clears",
                "pot",
                "--ntlm",
                "ntds",
            ]
        )
        self.assertTrue(args.verbose)

    def test_temp_alias_has_been_removed(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(
                    [
                        "patch",
                        "--clears",
                        "pot",
                        "--ntlm",
                        "ntds",
                        "--temp",
                    ]
                )
        self.assertNotIn("--temp", self.patch_parser.format_help())

    def test_positive_selector_size_is_enforced(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(
                    [
                        "patch",
                        "--clears",
                        "pot",
                        "--ntlm",
                        "ntds",
                        "--owned-seeds-per-selector",
                        "0",
                    ]
                )


if __name__ == "__main__":
    unittest.main()
