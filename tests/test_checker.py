"""Table-driven tests for the strength heuristics.

The interesting bugs in a scorer like this live in the edge cases, not the
happy path, so most of the table below is deliberately awkward input:
empty strings, whitespace, emoji, keyboard walks, and boundary lengths.
"""

import unittest

from pwstrength.checker import _common_passwords, _delete_leet, assess

# name, password, (score_min, score_max), reason fragments that must be
# present (case-insensitive substring match), reason fragments that must
# be absent.
CASES = [
    ("empty string", "", (0, 0), ["empty"], []),
    ("whitespace only", "    ", (0, 0), ["whitespace"], []),
    ("single char repeated 8x", "aaaaaaaa", (0, 0), ["repeated"], []),
    ("ascending letter run", "abcdefgh", (0, 1), ["sequence"], []),
    ("descending digit run", "987654321", (0, 0), ["sequence"], []),
    ("keyboard walk", "qwertyui", (0, 1), ["keyboard"], []),
    ("common breached password", "password1", (0, 0), ["breach"], []),
    (
        "leetspeak common password",
        "p4ssw0rd",
        (0, 0),
        ["resembles", "swapped"],
        [],
    ),
    (
        "leetspeak longer breached password",
        "l3tm31n",
        (0, 1),
        ["resembles", "letmein"],
        [],
    ),
    (
        "common password only in bundled wordlist, not the old inline set",
        "gorilla",
        (0, 0),
        ["breach"],
        [],
    ),
    ("repeated emoji", "\U0001F525" * 8, (0, 0), ["repeated"], []),
    ("short but all character classes", "Zz9!", (0, 1), ["characters"], []),
    (
        "long lowercase passphrase",
        "correcthorsebatterystaple",
        (3, 4),
        [],
        ["sequence", "keyboard", "repeated"],
    ),
    (
        "long mixed-class password",
        "Tq9$vB2#Xk7!Zm4^",
        (3, 4),
        ["no obvious weaknesses"],
        [],
    ),
]


class AssessTableTests(unittest.TestCase):
    def test_cases(self):
        for name, password, score_range, present, absent in CASES:
            with self.subTest(name=name):
                result = assess(password)
                lo, hi = score_range
                self.assertGreaterEqual(result.score, lo)
                self.assertLessEqual(result.score, hi)
                joined = " ".join(result.reasons).lower()
                for fragment in present:
                    self.assertIn(fragment.lower(), joined)
                for fragment in absent:
                    self.assertNotIn(fragment.lower(), joined)


class ConsistencyTests(unittest.TestCase):
    def test_unicode_normalization_is_consistent(self):
        # "e" + combining acute accent vs. the precomposed "e" should
        # score the same; a checker that only compares raw code points
        # would silently disagree with itself here.
        precomposed = "cafépass1"
        decomposed = "cafépass1"
        self.assertEqual(assess(precomposed).score, assess(decomposed).score)

    def test_never_crashes_on_odd_input(self):
        for password in ["", "x", "x" * 200, "\t\n", "P@ssw0rd!", " " * 50]:
            result = assess(password)
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 4)

    def test_longer_password_scores_at_least_as_well(self):
        # Not a guarantee in general (a longer password can still be a
        # common one), but true for these two, and a cheap regression
        # check that length isn't simply ignored.
        shorter = assess("Xk9#mQ2!").score
        longer = assess("Xk9#mQ2!Zp7$wL4^").score
        self.assertGreaterEqual(longer, shorter)


class LeetspeakTests(unittest.TestCase):
    def test_delete_leet_maps_digits_and_symbols_to_letters(self):
        self.assertEqual(_delete_leet("p4ssw0rd"), "password")
        self.assertEqual(_delete_leet("L3tM31n"), "letmein")

    def test_delete_leet_leaves_unmapped_characters_alone(self):
        # "9" and "%" have no letter they commonly stand in for, so they
        # should pass through unchanged rather than being dropped.
        self.assertEqual(_delete_leet("Xk9%"), "xk9%")

    def test_no_false_positive_when_deleeted_form_is_not_common(self):
        # "Zq4rP0lm" doesn't deleet to anything in the wordlist, so it
        # shouldn't be flagged as resembling a breached password.
        result = assess("Zq4rP0lm")
        self.assertNotIn("resembles", " ".join(result.reasons).lower())


class CommonPasswordsTests(unittest.TestCase):
    def test_wordlist_loads_and_is_nonempty(self):
        words = _common_passwords()
        self.assertIsInstance(words, frozenset)
        self.assertGreater(len(words), 20)

    def test_wordlist_entries_are_lowercase_with_no_blanks_or_comments(self):
        for word in _common_passwords():
            self.assertEqual(word, word.lower())
            self.assertTrue(word)
            self.assertFalse(word.startswith("#"))

    def test_repeated_calls_return_the_same_cached_object(self):
        self.assertIs(_common_passwords(), _common_passwords())


if __name__ == "__main__":
    unittest.main()
