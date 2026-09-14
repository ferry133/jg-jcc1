#!/usr/bin/env python3
"""Which of this repo's check scripts CI runs, and why the rest are not run.

Measured 2026-08-31 in a fresh checkout with no `cluster.yaml`, no `age.key`,
no rendered `kubernetes/` and no cluster: seven of the twelve `check-*` scripts
pass on their own, and five cannot see their subject from here. The five are
listed with the reason rather than dropped, because a list that silently stops
at the runnable ones reads exactly like a list that covers everything.

`--audit` fails if any guard in `scripts/` is in neither list. That is the
failure this file exists for: `#58` added a check script and nothing ran it,
which is how a repo with eleven guards ended up with no CI at all.

The inventory is deliberately not a plain `check-*` glob. It was, for one day,
and the acceptance review found the hole the same evening: a guard whose name
does not start with `check-` was invisible to the audit, **and the output was
byte-identical to full coverage** — `ok 12 check scripts` either way. That is
this file's own failure mode occurring inside this file. It was not
hypothetical: `delivery-check.py` has always been such a file.

So the inventory is "starts with `check-`, or has `check` anywhere in the name",
and the naming convention is no longer load-bearing. A guard called something
else entirely is still invisible; that residue is named here rather than left
to be rediscovered.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Exit 0 in a bare checkout. Measured, not assumed.
RUN = [
    "check-claude-config-storage-default.py",
    "check-claudecode-postgres-derive.py",
    "check-claudecode-factory-auth.py",
    "check-claude-instances-default.py",
    "check-encrypt-secrets.sh",
    "check-forwarded-header-trust.py",
    "check-handover-cells.py",
    "check-ks-position-labels.py",
    "check-lb-pool-render.py",
    "check-nas-backup.py",
    "check-private-repo-chain.py",
    "check-node-dns-path.py",
    "check-credential-expiry-pairing.py",
    "check-template-integrity.py",
]

# Cannot see their subject from a bare template checkout. The reason is the
# point: "not run" with a reason is a third outcome, and dropping these from
# the report would make the run look complete.
SKIP = {
    "check-backup-recipient.py":
        "reads the rendered cluster-secrets; exits 2 CANNOT MEASURE here",
    "check-longhorn-backup.py":
        "reads rendered kubernetes/; exits 2 COULD NOT MEASURE here",
    "check-claudecode-auth.py":
        "needs a cluster.yaml, which the template repo does not have",
    "check-lb-pool-covers-live.py":
        "needs a live cluster (kubectl) and the age key to decrypt secrets",
    "check-template-drift.py":
        "compares two repos; needs a per-user repo to compare against",
    # Not named `check-*`, and invisible to the audit until 2026-09-01. Its
    # subcommands each need something this checkout has not got — a domain, a
    # kubeconfig, an escrowed key — so SKIP is where it belongs. The defect was
    # never that it did not run; it was that nothing could tell it had not been
    # classified.
    "delivery-check.py":
        "subcommands need a domain, a kubeconfig or an escrowed key; run at delivery",
}


def scripts_present() -> set[str]:
    """Every file in `scripts/` that looks like a guard.

    Two globs, not one. `check-*` alone was the whole inventory until the
    `#59` acceptance review, and it silently excluded `delivery-check.py` while
    printing the same line it prints when nothing is missing.
    """
    d = ROOT / "scripts"
    prefixed = {p.name for p in d.glob("check-*") if p.is_file()}
    infixed = {
        p.name
        for p in d.glob("*")
        if p.is_file() and "check" in p.name and not p.name.startswith("check-")
    }
    return prefixed | infixed


def audit() -> int:
    present, known = scripts_present(), set(RUN) | set(SKIP)
    unclassified = sorted(present - known)
    missing = sorted(known - present)
    for name in unclassified:
        print(f"FAIL  scripts/{name} is in neither RUN nor SKIP")
        print("      A guard with no runner is how #59 happened. Add it to RUN,")
        print("      or to SKIP with the reason it cannot run here.")
        print("      (Counted because the name starts with `check-` or contains")
        print("      `check`. A guard named neither is still invisible — say so")
        print("      in the name, or add it to a list here by hand.)")
    for name in missing:
        print(f"FAIL  {name} is listed here but not in scripts/")
        print("      A list naming a file that no longer exists still reads as")
        print("      coverage.")
    if unclassified or missing:
        return 1
    print(f"ok    {len(present)} guards found in scripts/, {len(RUN)} run here, "
          f"{len(SKIP)} cannot see their subject from a bare checkout")
    return 0


def run() -> int:
    failed = []
    for name in RUN:
        path = ROOT / "scripts" / name
        cmd = (["bash", str(path)] if path.suffix == ".sh"
               else ["python3", str(path)])
        print(f"\n──────── {name}", flush=True)
        rc = subprocess.run(cmd, cwd=ROOT).returncode
        print(f"exit={rc}", flush=True)
        if rc != 0:
            failed.append((name, rc))

    print("\n" + "=" * 60)
    for name, reason in sorted(SKIP.items()):
        print(f"not run  {name} — {reason}")
    print("=" * 60)

    if failed:
        for name, rc in failed:
            print(f"::error::{name} exited {rc}")
        return 1
    print(f"ok — {len(RUN)} check scripts passed, {len(SKIP)} not run (above)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--run", action="store_true")
    args = ap.parse_args()
    if not (args.audit or args.run):
        ap.error("pass --audit or --run")
    # data()-based checks derive secrets from age.key (jgct#85: postgres
    # password; cookie secret). A CI checkout has none, so mint a throwaway for
    # the run and remove it after. One place, so a NEW data() check needs no
    # age.key wiring of its own -- the fragile alternative is stubbing age_key
    # in every such check and remembering to in the next one.
    if args.run:
        _age = ROOT / "age.key"
        if not _age.exists():
            subprocess.run(["age-keygen", "-o", str(_age)],
                           check=True, capture_output=True)
            import atexit
            atexit.register(lambda: _age.unlink(missing_ok=True))
    sys.exit((audit() if args.audit else 0) or (run() if args.run else 0))
