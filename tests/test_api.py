import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from patchhound.api import (
    extract_error_message,
    load_session,
    normalize_base_url,
    redact_secret,
    redact_token,
    save_session,
)


class Response:
    def __init__(self, status_code=400, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body


class APIHelperTests(unittest.TestCase):
    def test_session_round_trip_is_private_and_normalizes_base_url(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "session.json")
            save_session("http://bloodhound:8080", "secret-token", path)
            self.assertEqual(
                ("http://bloodhound:8080/", "secret-token"),
                load_session(path),
            )
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))

    def test_error_extraction_supports_common_response_shapes(self):
        self.assertEqual(
            "bad request",
            extract_error_message(Response(body={"errors": [{"message": "bad request"}]})),
        )
        self.assertEqual(
            "forbidden",
            extract_error_message(Response(body={"detail": "forbidden"})),
        )
        self.assertEqual("plain failure", extract_error_message(Response(text="plain failure")))

    def test_redaction_uses_a_solid_mask_and_never_returns_fragments(self):
        self.assertEqual("████████", redact_token("short"))
        self.assertEqual("████████", redact_token("a-very-long-session-token"))
        self.assertEqual("████████", redact_secret("password"))

    def test_empty_base_url_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_base_url("  ")

    def test_non_object_session_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            path.write_text(json.dumps(["not", "a", "session"]), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "invalid"):
                load_session(str(path))


if __name__ == "__main__":
    unittest.main()
