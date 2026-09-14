#!/usr/bin/env python3
"""Run the tests in `scripts/tests/`, and fail if there were none to run.

Why this exists rather than `python3 -m unittest discover` written straight into
the workflow: **discovery with nothing to discover exits 0.** `scripts/tests/`
held zero tracked files from 2026-08-27 to 2026-09-12 (`#104`) — the three test
modules were committed only on the unmerged branch `feat/8-provisioning-flow`,
and a `checkout` away from it removed them from the worktree, leaving a stale
`__pycache__` as the only evidence they had ever existed. Nothing went red:
there was no runner to go red. An empty suite and a passing suite are the same
colour, which is the failure this repo keeps paying for in other shapes.

So the count is asserted, not printed and trusted. Zero collected is exit 1 with
the reason.

Two details that are deliberate, both measured 2026-09-12:

1. **No `-t` / `--top-level-directory`.** `discover -s scripts/tests -t .` names
   the module `scripts.tests.test_*`, and `scripts/` has no `__init__.py`, so it
   dies with `ImportError: Start directory is not importable`. The tests find the
   repo root from `__file__`, never from the import path, so the bare form is the
   correct one — not a workaround.

2. **No floor above zero.** Asserting "at least 38" would go red on the first
   legitimate change to the suite, and a check that fires on correct input gets
   switched off (`~/.claude/CLAUDE.md`). Zero is the only count that cannot mean
   "someone edited the tests"; the number is printed so a drop stays visible.
"""

from __future__ import annotations

# A stale `.pyc` makes a negative control report the result of the PREVIOUS
# mutation (jgct#96: CPython accepts a cached .pyc when source mtime to the
# second AND size both match, which is exactly what a minimal edit looks like).
# Nothing here should ever write bytecode.
import sys

sys.dont_write_bytecode = True

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "scripts" / "tests"


def _cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


def collection_counts_agree(by_module: dict) -> bool:
    """Every test file must collect the same number of tests both ways.

    The failure this catches (#137): a second `unittest.main()` above some of
    the classes. `python3 scripts/tests/test_provision.py` then exits inside it,
    the classes below are never defined, and the file reports `Ran 44 OK` while
    discovery reports `Ran 56 OK`. **Both are green.** The count guard above
    does not see it either: the total is still far from zero, because only one
    file lost half of itself.

    Not a text check. `#141` asserted the `__main__` line appeared exactly once,
    and `k8scc [ef2bb8]` got past it during acceptance by writing the guard with
    single quotes. Chasing that family by spelling is unbounded — `sys.exit()`,
    `raise SystemExit`, `exit()`, another `__name__` comparison — and each new
    pattern is another round of scope. This asks the question the patterns are
    a proxy for: **do the two ways of running this file see the same tests?**
    Anything that ends the direct run early makes the two numbers differ,
    whatever it is spelled like.

    **This makes a `__main__` guard mandatory in every test file.** The direct
    side is read from its `Ran N tests` line, and a file without a guard prints
    none — it is reported as a failure here, saying so. All ten have one today
    (measured 2026-09-14), so this costs nothing now; it is written down because
    the requirement is otherwise invisible until someone adds the eleventh file.

    Cost, measured 2026-09-14 on `d8f6441` by three sessions: about 10.2s → 21.4s,
    **2.1×**. Kept deliberately (`#142`, the opener's call). The cheap version
    — patch `unittest.main` in the subprocess so the file is only collected, not
    run — would drop the added time to about a second, but it detects the
    `sys.exit()` family by *the absence of a printed count*, and an absence is
    what this whole line keeps being fooled by: `#137` hid precisely because both
    ways printed `OK` and there was no second number to compare the first with.
    **The eleven seconds buy the second number.**

    If 2.1× ever becomes a problem, reduce the bookkeeping, not the executing:
    the ten single-file discoveries can come from one whole-suite discovery split
    by module. ⚠️ **Not by sampling, and not by running this only on `main`** —
    either makes the guard miss the run that needed it.

    The discovery side is counted off the suite before it runs, so it costs
    nothing — and it has to be *before*: `TestSuite.run` drops its references
    as it goes, so walking the same object afterwards yields nothing and this
    check reports every file as empty. Measured 2026-09-14, by writing it the
    wrong way round first. The direct side has to be a real subprocess: executing the
    module top to bottom under `__main__` is the thing being measured, and no
    amount of reading the file reproduces it.
    """
    ok = True
    for path in sorted(TESTS.glob("test_*.py")):
        want = by_module.get(path.stem)
        run = subprocess.run([sys.executable, "-B", str(path)],
                             cwd=str(ROOT), capture_output=True, text=True)
        seen = re.findall(r"^Ran (\d+) tests?", run.stderr, re.M)
        rel = path.relative_to(ROOT)

        if want is None:
            print(f"FAIL  {rel} collected 0 tests under discovery.")
            print("      Either it has no tests, or discovery cannot import it.")
            ok = False
            continue
        if not seen:
            print(f"FAIL  {rel} printed no 'Ran N tests' line when run directly.")
            print(f"      Discovery collects {want}. Running the file itself has to")
            print("      report a count, or these two can never be compared.")
            print(f"      Its exit code was {run.returncode}.")
            ok = False
            continue

        direct = int(seen[-1])
        if direct != want:
            print(f"FAIL  {rel}: direct run collected {direct}, discovery {want} "
                  f"(difference {want - direct}).")
            print("      Something ends the direct run before the file finishes")
            print("      defining its tests — a `unittest.main()` or any other exit")
            print("      above the later classes. Both ways still print OK, which is")
            print("      why this is compared rather than trusted (#137, #142).")
            ok = False
        else:
            print(f"  {rel}: {direct} both ways")
    return ok


def main() -> int:
    if not TESTS.is_dir():
        print(f"FAIL  {TESTS.relative_to(ROOT)}/ does not exist.")
        print("      It held the §3 tests until 2026-08-27 and its absence was")
        print("      silent for two weeks (#104). If the tests moved, point this")
        print("      runner at them; do not delete the assertion.")
        return 1

    suite = unittest.defaultTestLoader.discover(str(TESTS))
    count = suite.countTestCases()

    if count == 0:
        print(f"FAIL  0 tests collected from {TESTS.relative_to(ROOT)}/")
        print("      This is the #104 state: the directory is there and empty,")
        print("      and `unittest discover` exits 0 on it. A suite that runs")
        print("      nothing must not report the same colour as one that passes.")
        return 1

    print(f"collected {count} tests from {TESTS.relative_to(ROOT)}/", flush=True)

    # Counted before the run, not after: see collection_counts_agree.
    by_module: dict[str, int] = {}
    for case in _cases(suite):
        by_module[type(case).__module__] = by_module.get(type(case).__module__, 0) + 1

    result = unittest.TextTestRunner(verbosity=2).run(suite)

    # Both signals always run. An earlier `return` here would mean that
    # whenever any test fails, the collection comparison never reports — and
    # the first thing that makes a test fail is often the very edit that also
    # truncates the file. Measured 2026-09-14: with a second `__main__` guard
    # spelled with double quotes, `#141`'s in-file assertion fails, and with an
    # early return that failure is the only thing printed. The two checks would
    # then look like one.
    print("collection counts, direct run vs discovery:", flush=True)
    counts_ok = collection_counts_agree(by_module)

    if not result.wasSuccessful():
        print(f"::error::{len(result.failures)} failed, {len(result.errors)} errored "
              f"out of {count} collected")
    if not counts_ok:
        print("::error::a test file does not collect the same tests both ways")
    if not result.wasSuccessful() or not counts_ok:
        return 1

    print(f"ok — {count} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
