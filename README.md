# password-strength-check

Most "password strength" meters you see on signup forms are either a
regex checking for one uppercase letter and one digit, or a black box
that gives no reason for its verdict. Neither helps anyone pick a better
password. This is a small command-line tool that scores a password and
tells you *why* it scored that way.

It estimates entropy from the character classes actually used (lowercase,
uppercase, digits, symbols, non-ASCII) and the length, then knocks that
estimate down for the things that make a password easier to guess than
its raw entropy suggests: repeated characters, ascending or descending
runs like `abcd` or `4321`, keyboard walks like `qwerty` or `asdf`, and a
short list of passwords that show up constantly in breach dumps -- including
leetspeak variants of them, like `p4ssw0rd` for `password`.

It does not check passwords against a network service, does not log
anything, and does not depend on anything outside the Python standard
library.

## Usage

Prompt interactively (input is hidden, like `sudo` or `ssh-add`):

```
$ python -m pwstrength.cli
password: 
fair (2/4)
  - contains a keyboard walk (e.g. qwerty, asdf)
```

Pass it as an argument (fine for testing, not for anything real -- it
ends up in your shell history):

```
$ python -m pwstrength.cli 'Tr0ub4dor&3'
strong (3/4)
  - no obvious weaknesses found
```

Pipe it in instead:

```
$ echo 'correcthorsebatterystaple' | python -m pwstrength.cli --stdin
very strong (4/4)
  - no obvious weaknesses found
```

Once installed (`pip install .`), the same tool is available as
`pwstrength` on your `PATH`.

The exit code is `0` if the score is 2 or higher ("fair" or better) and
`1` otherwise, so it can be used as a gate in a script:

```
$ python -m pwstrength.cli 'qwerty123' || echo "too weak"
```

Add `--json` to get a machine-readable result instead of the plain-text
report, for scripting or feeding into another tool:

```
$ python -m pwstrength.cli --json 'qwerty123'
{"password_length": 9, "score": 1, "label": "weak", "reasons": ["contains a keyboard walk (e.g. qwerty, asdf)"]}
```

## How scoring works

Score is 0 ("very weak") through 4 ("very strong"), based on an entropy
estimate in bits after penalties:

| bits    | score | label       |
|---------|-------|-------------|
| < 28    | 0     | very weak   |
| 28-35   | 1     | weak        |
| 36-59   | 2     | fair        |
| 60-79   | 3     | strong      |
| >= 80   | 4     | very strong |

This is a heuristic, not a cryptographic guarantee. It is meant to catch
the obviously bad passwords and give a useful nudge, not to model every
attacker's cracking dictionary.

## Development

No dependencies to install. Run the tests with:

```
python -m unittest discover -v
```

`tests/test_checker.py` is table-driven: each row is a password and the
score range plus reason text it's expected to produce, covering the
awkward cases (empty input, whitespace-only, repeated characters,
sequences, keyboard walks, emoji, unicode normalization).
