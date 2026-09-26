"""Tests for the command-line entry point, particularly --json output."""

import io
import json
import unittest
from contextlib import redirect_stdout

from pwstrength.cli import main


def run(argv):
    out = io.StringIO()
    with redirect_stdout(out):
        exit_code = main(argv)
    return exit_code, out.getvalue()


class JsonOutputTests(unittest.TestCase):
    def test_json_output_is_a_single_parseable_object(self):
        exit_code, output = run(["--json", "correcthorsebatterystaple"])
        payload = json.loads(output)
        self.assertEqual(
            set(payload), {"password_length", "score", "label", "reasons"}
        )
        self.assertEqual(payload["password_length"], 25)
        self.assertIsInstance(payload["reasons"], list)
        self.assertEqual(exit_code, 0)

    def test_json_output_matches_plain_text_score(self):
        _, plain = run(["qwerty123"])
        _, as_json = run(["--json", "qwerty123"])
        payload = json.loads(as_json)
        self.assertIn(f"({payload['score']}/4)", plain)

    def test_weak_password_json_gives_nonzero_exit_code(self):
        exit_code, output = run(["--json", "aaaaaaaa"])
        payload = json.loads(output)
        self.assertEqual(payload["score"], 0)
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
