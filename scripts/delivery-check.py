#!/usr/bin/env python3
"""Executable form of the provisioning runbook's assertions — §7.1a.

`fleet-ops docs/operations/provision-customer-cluster.md` is a document made almost
entirely of checks, executed by a person, with nothing behind them. This runs
the ones a machine can run, so that 7.2 has real assertions to execute and 7.3
has something an agent can run identically.

The design rule every check here obeys
--------------------------------------
**A check that cannot discriminate reads identically to a check that passed.**
So each check below either carries a positive control, or refuses to report a
pass. Concretely, that means:

  - Absence is never reported as good on its own. `NotFound`, "no output" and
    "no rows" are also what asking the wrong question looks like, so something
    that must be present is asserted in the same breath.
  - Nothing trusts a tool's own account of itself where a checksum, a digest or
    a delegation record is available instead.
  - A check pinned to one path is treated as not having looked. `cluster.yaml`
    leaked at `config.gen/cluster.yaml` past a rule and a check both naming
    `/cluster.yaml`.

Every subcommand exits 0 on pass, 1 on fail, and 2 when it could not tell —
which is deliberately not the same as a pass.

Usage
-----
  delivery-check.py escrow       --escrowed-key PATH [--sops-yaml PATH]
  delivery-check.py repo-hygiene [--dir PATH] [--deep]
  delivery-check.py dns          --domain DOMAIN [--token-env VAR]
  delivery-check.py flux         --kubeconfig PATH --expect-sha SHA
  delivery-check.py lan          --domain DOMAIN --expect-addr ADDR
  delivery-check.py gateway      --node ADDR [--talosconfig PATH] [--routes-json PATH]
  delivery-check.py deploy-key   --repo OWNER/NAME [--pubkey PATH]
  delivery-check.py tunnel-cert  --domain DOMAIN [--cert PATH] [--token-env VAR]
  delivery-check.py handover     --domain DOMAIN [--dir PATH] [--repo OWNER/NAME]
                                 [--kubeconfig PATH] [--instance NAME]
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

PASS, FAIL, UNKNOWN = 0, 1, 2

# Reused verbatim from the runbook's history scan, and from
# delivery-ticket.py's comment guard. One list, three call sites: three
# divergent lists would mean the strictest one defines the real policy and
# nobody knows which it is.
SECRET_FIELDS = (
    "cloudflare_token",
    "claudecode_auth0_client_secret",
    "backup_r2_secret_access_key",
    "ttyd_credential",
    "claudecode_postgres_password",
)


def ok(msg: str) -> None:
    print(f"PASS  {msg}")


def bad(msg: str) -> None:
    print(f"FAIL  {msg}")


def huh(msg: str) -> None:
    print(f"?     {msg}")


# Nothing in this file may wait forever, and the reason is measured (#114):
# an unbounded `omnictl` call against an unreachable endpoint blocked
# `ci-checks.py --run` at check-handover-cells.py, and the wrapper's exit code
# still read like a completed run. **A hang and a pass are the same colour from
# outside**, and the one machine where it happens is the one that HAS the tool —
# never CI, which has neither the tool nor the network path.
#
# #115 bounded that one path. #117 enumerated the rest. Of the 18 `run([` call
# sites: 2 are already bounded by the tool itself (`curl -m` :962,
# `dig +time=` :1265) and 16 had no bound at any layer. Seven of those sixteen
# leave this machine — kubectl x3, nslookup x2, gh x2 — and the other nine do
# not: git x7 (all `git -C <dir>`, object-store reads that never contact a
# remote), plus yq and age-keygen.
#
# Do NOT re-derive 16 as "18 minus the two bounded omnictl calls". Those two are
# `_run_bounded([`, and the substring `run([` does not match them, so they were
# never in the 18. The correct subtraction is the two tool-bounded ones. That
# wrong route lands on the right number, which is why it is written down here
# (jgb-handler [20db54] and FO-openspec [8e8ef1] both walked it).
RUN_TIMEOUT = 60      # backstop for the nine local commands
REMOTE_TIMEOUT = 20   # the seven that talk to a cluster, a resolver or GitHub


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Capture a command's output, and never wait longer than RUN_TIMEOUT.

    The timeout is a default, not a policy: an explicit `timeout=` still wins,
    which is how `_run_bounded` and `--timeout` keep their own numbers.

    **It is deliberately not swallowed into a return code.** Converting a hang
    into `returncode != 0` would let each call site turn it into that site's
    particular conclusion — `git rev-parse` would report "not a git repo",
    `nslookup` would report "the name does not resolve". Those are findings, and
    a hang is not a finding: it is the absence of a measurement. It propagates
    to main(), which reports it as the third outcome.
    """
    kw.setdefault("timeout", RUN_TIMEOUT)
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------- escrow (0)

def check_escrow(args) -> int:
    """The escrowed copy IS this cluster's key, not merely a file of that name.

    A truncated copy reads exactly like a good one — same name, same rough
    size, present. Only the public half derived from the copy identifies the
    material, which is why this derives rather than compares filenames.
    """
    if not shutil.which("age-keygen"):
        huh("age-keygen not installed — cannot derive the public half")
        return UNKNOWN
    if not os.path.exists(args.escrowed_key):
        bad(f"escrowed key not found at {args.escrowed_key}")
        return FAIL

    r = run(["age-keygen", "-y", args.escrowed_key])
    if r.returncode != 0:
        bad(f"age-keygen could not read {args.escrowed_key} as a key — "
            "a truncated or partial copy does exactly this")
        return FAIL
    derived = r.stdout.strip()

    try:
        sops_text = open(args.sops_yaml).read()
    except FileNotFoundError:
        huh(f"{args.sops_yaml} not found — nothing to compare against")
        return UNKNOWN

    recipients = re.findall(r"age1[a-z0-9]{20,}", sops_text)
    if not recipients:
        huh(f"no age recipient in {args.sops_yaml}; cannot compare")
        return UNKNOWN

    if derived in recipients:
        ok(f"escrowed copy derives {derived[:16]}…, which is a recipient in "
           f"{args.sops_yaml}")
        print("      Record this as: compared, public halves match verbatim.")
        print("      Not 'escrowed' — that word is what jgt-appliance's unchecked")
        print("      age_key_escrowed: true was written on.")
        return PASS

    bad("the escrowed copy is a valid age key but NOT this cluster's")
    print(f"      derived from copy: {derived[:16]}…")
    print(f"      .sops.yaml expects: {', '.join(r[:16] + '…' for r in recipients)}")
    print("      Delete it from the escrow store — a wrong key in an escrow slot")
    print("      is worse than an empty one, because it will be trusted.")
    return FAIL


# ---------------------------------------------------- repository hygiene (3)

def check_repo_hygiene(args) -> int:
    d = args.dir
    if run(["git", "-C", d, "rev-parse", "--git-dir"]).returncode != 0:
        huh(f"{d} is not a git repository")
        return UNKNOWN

    failed = False

    # 1. Is the protection IN the repo, or only on this machine?
    #
    # This is first because it is the one that would have caught jg-jiahd, and
    # because `git check-ignore` cannot: it measures the workstation running
    # it, which is also the workstation doing the verifying. jg-jiahd has no
    # .gitignore in HEAD at all, ~/.gitignore_global ignores .gitignore itself
    # so it never reaches `git add`, and check-ignore reports .gitignore:18 and
    # looks healthy. Eleven credential-bearing blobs landed behind that.
    tracked = run(["git", "-C", d, "ls-files", "--error-unmatch", ".gitignore"])
    if tracked.returncode != 0:
        bad(".gitignore is NOT tracked — protection exists only on this machine")
        print("      A fresh clone has no ignore rule at all. `git check-ignore`")
        print("      will still say everything is fine, because it reads the")
        print("      working copy.")
        print("      Fix: git add -f .gitignore && git commit  (the global ignore")
        print("      list contains .gitignore, so a plain `git add` will not do it)")
        failed = True
    else:
        head_ignore = run(["git", "-C", d, "show", "HEAD:.gitignore"]).stdout
        if re.search(r"cluster\.yaml", head_ignore):
            ok(".gitignore is tracked and HEAD's copy names cluster.yaml")
        else:
            bad(".gitignore is tracked but HEAD's copy has no cluster.yaml rule")
            failed = True

    # 2. Any path, not just the expected one.
    hist = run(["git", "-C", d, "log", "--all", "--oneline", "--", "*cluster.yaml"])
    offenders = [l for l in hist.stdout.splitlines() if l.strip()]
    if offenders:
        bad(f"a *cluster.yaml path appears in history ({len(offenders)} commits)")
        print("      Rotate the credentials; untracking does not unpublish them.")
        failed = True
    else:
        ok("no *cluster.yaml at any path in --all history")

    # 3. Positive control for check 2.
    #
    # An empty result from `git log` is also what a wrong pathspec, an empty
    # repo or a broken invocation produces. Asserting that the same command
    # shape finds something that must exist separates "nothing there" from
    # "not looking".
    control = run(["git", "-C", d, "log", "--all", "--oneline", "--", "*.md"])
    if not control.stdout.strip():
        huh("positive control found no *.md in history either — the history "
            "query itself may not be working, so the clean result above proves "
            "nothing")
        return UNKNOWN
    ok("positive control: the same query shape does find *.md in history")

    # 4. By content, because the next leak is at a name nobody predicted.
    if args.deep:
        # Positive control first: a clean deep scan and a deep scan that cannot
        # recognise a credential produce the same empty list.
        if not _scan_blob_for_secrets(_SCAN_CONTROL):
            huh("deep scan cannot recognise a credential in its own control "
                "sample, so finding none in this history proves nothing")
            return UNKNOWN
        found = _scan_history_for_secrets(d)
        if found:
            bad(f"credential-shaped content in {len(found)} historical blob(s)")
            for path, sha in found[:10]:
                print(f"      {path}  ({sha[:12]})")
            failed = True
        else:
            ok("deep scan: control sample recognised, and no credential fields "
               "with real values in any blob")
    else:
        print("      (skipped the content scan; pass --deep. It is slow, and is")
        print("       a once-per-repo check rather than once-per-delivery.)")

    return FAIL if failed else PASS


_SECRET_LINE = re.compile(
    r"(?im)^\s*(" + "|".join(SECRET_FIELDS) + r")\s*:\s*(.+)$"
)


def _is_real_credential(value: str) -> bool:
    """Does this right-hand side look like a live secret rather than a placeholder?

    The case-insensitive field match above is deliberate: the rendered Secret
    spells the same fields in UPPER CASE, and a plaintext render is exactly the
    leak worth catching. But that breadth is what makes the SOPS exclusion
    mandatory — `kubernetes/components/sops/cluster-secrets.sops.yaml` is
    *supposed* to be committed, with every one of these fields present and
    encrypted, so without it the scan FAILs on the correct state of every
    cluster repo. Measured on jg-janncotcc 2026-08-22: five fields matched, all
    five values began `ENC[`, and the whole delivery reported a leak.

    That is the failure this file exists to prevent, pointed at itself: a guard
    that fires on the correct input gets switched off, and a switched-off guard
    reads exactly like a passing one — the same reasoning as the placeholder
    exemptions in `delivery-ticket.py`.
    """
    v = value.split("#", 1)[0].strip().strip("\"'").strip()
    if not v or len(v) < 8:
        return False
    if v.startswith(("<", "${", "$(")):          # documentation, not a value
        return False
    if v.startswith(("ENC[", "ENC(")):           # SOPS ciphertext — meant to be here
        return False
    if "change" in v.lower() or set(v.lower()) == {"x"}:
        return False
    return True


def _scan_blob_for_secrets(text: str) -> list[str]:
    """Field names in this blob whose value looks like a live credential."""
    return [f for f, value in _SECRET_LINE.findall(text) if _is_real_credential(value)]


# A blob shaped like the thing being looked for. If the scan cannot find a
# credential here, its silence on real history means nothing — see the
# positive control on the path query above.
_SCAN_CONTROL = "stringData:\n  cloudflare_token: 0123456789abcdef0123456789abcdef01234567\n"


def _scan_history_for_secrets(d: str) -> list[tuple[str, str]]:
    listing = run(["git", "-C", d, "rev-list", "--all", "--objects"]).stdout
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in listing.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        sha, path = parts
        if sha in seen or not path.endswith((".yaml", ".yml")):
            continue
        seen.add(sha)
        blob = run(["git", "-C", d, "cat-file", "blob", sha])
        if blob.returncode != 0:
            continue
        if _scan_blob_for_secrets(blob.stdout):
            hits.append((path, sha))
    return hits


# ------------------------------------------------------------------- dns (2)

def _doh(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.load(r)
    return sorted({a["data"].rstrip(".").lower() for a in data.get("Answer", [])
                   if a.get("type") == 2})


def check_dns(args) -> int:
    """Cloudflare's zone must be the zone the domain is actually delegated to.

    /user/tokens/verify says "valid and active" for a token belonging to an
    entirely different account, and GET /zones returns HTTP 200 with an empty
    result for a token pasted from the wrong field. Neither separates anything,
    so this compares nameservers as sets against the live delegation.

    DoH rather than dig on purpose: an appliance gateway transparently
    redirects all outbound UDP/53, so `dig @1.1.1.1` is answered by the cluster
    and even `dig @192.0.2.1` answers. HTTPS on 443 is immune.
    """
    try:
        cf_ns_live = _doh(f"https://cloudflare-dns.com/dns-query?name={args.domain}&type=NS")
        google_ns_live = _doh(f"https://dns.google/resolve?name={args.domain}&type=NS")
    except Exception as e:  # noqa: BLE001 — any network failure is "cannot tell"
        huh(f"could not reach a DoH resolver: {e}")
        return UNKNOWN

    if not cf_ns_live and not google_ns_live:
        bad(f"{args.domain} has no NS records at either resolver — the domain is "
            "not delegated anywhere")
        return FAIL

    if cf_ns_live != google_ns_live:
        huh("the two resolvers disagree on the delegation; retry before acting")
        print(f"      cloudflare-dns: {', '.join(cf_ns_live) or '(none)'}")
        print(f"      dns.google:     {', '.join(google_ns_live) or '(none)'}")
        return UNKNOWN
    ok(f"live delegation agrees across two resolvers: {', '.join(cf_ns_live)}")

    token = os.environ.get(args.token_env or "CLOUDFLARE_TOKEN", "")
    if not token:
        huh(f"${args.token_env or 'CLOUDFLARE_TOKEN'} not set — checked the "
            "delegation only, NOT that your token sees this zone. That is the "
            "half that catches a same-named zone in an abandoned account.")
        return UNKNOWN

    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones?name={args.domain}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = json.load(r)
    except Exception as e:  # noqa: BLE001
        huh(f"Cloudflare API call failed: {e}")
        return UNKNOWN

    results = payload.get("result") or []
    if not results:
        bad(f"the token returned HTTP 200 with an EMPTY zone list for "
            f"{args.domain}")
        print("      Not a 403 — a well-formed empty answer, which is what a")
        print("      token from another account (an R2 key, say) produces.")
        print("      external-dns filters against this list and logs nothing.")
        return FAIL

    zone = results[0]
    zone_ns = sorted(n.rstrip(".").lower() for n in zone.get("name_servers", []))
    status = zone.get("status")

    if zone_ns != cf_ns_live:
        bad("the zone your token sees is NOT the zone this domain resolves to")
        print(f"      token's zone nameservers: {', '.join(zone_ns)}")
        print(f"      live delegation:          {', '.join(cf_ns_live)}")
        print(f"      zone status: {status}")
        print("      This is the same-name-different-zone case: an abandoned")
        print("      account's copy holds complete, correct-looking records for")
        print("      hostnames that are NXDOMAIN worldwide.")
        return FAIL

    if status != "active":
        bad(f"nameservers match but zone status is {status!r}, not 'active'")
        return FAIL

    ok(f"token's zone matches the live delegation and is active")

    # ---- and: do the records in it belong to a cluster that still exists? ----
    #
    # "im.<domain> resolves" passes just as happily on records left behind by a
    # cluster that was dropped. Both cases look identical from outside: proxied
    # A records at Cloudflare's edge and HTTP 530, because a tunnel hostname
    # with no connector answers exactly like one whose cluster has not booted
    # yet. Measured on janncot.cc 2026-08-23: six external-dns records still
    # pointed at the dropped jg-appliance's tunnel while the repo held
    # credentials for a different, freshly created one.
    #
    # external-dns will usually adopt them — same owner id — but "usually" is
    # not what a delivery gate is for, and if it does not, the symptom is
    # indistinguishable from "not bootstrapped yet" forever.
    creds = pathlib.Path(args.tunnel_credentials)
    if not creds.is_file():
        huh(f"{creds} not found — checked the delegation and the token, NOT "
            "whether this zone still holds a dropped cluster's records. That "
            "is the half that stops a later DNS assertion from passing on a "
            "corpse.")
        return UNKNOWN
    try:
        local_tunnel = json.loads(creds.read_text()).get("TunnelID", "")
    except Exception as e:  # noqa: BLE001
        huh(f"could not read a TunnelID out of {creds}: {e}")
        return UNKNOWN
    if not local_tunnel:
        huh(f"{creds} has no TunnelID field")
        return UNKNOWN

    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones/{zone['id']}"
        "/dns_records?per_page=100",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            records = json.load(r).get("result") or []
    except Exception as e:  # noqa: BLE001
        huh(f"could not list the zone's DNS records: {e}")
        return UNKNOWN

    tunnel_backed = [r for r in records
                     if str(r.get("content", "")).endswith(".cfargotunnel.com")]
    if not tunnel_backed:
        ok("no tunnel-backed records in the zone: a later DNS assertion has "
           "nothing to inherit, so whatever appears will be this cluster's")
        return PASS

    foreign = [r for r in tunnel_backed
               if r["content"].split(".")[0] != local_tunnel]
    if foreign:
        bad("this zone holds tunnel records pointing at a DIFFERENT tunnel "
            "than the one this repo has credentials for")
        print(f"      this repo's tunnel: {local_tunnel[:8]}…")
        for r in foreign:
            print(f"      {r['name']} -> {r['content'][:8]}….cfargotunnel.com")
        print("      Delete them before bootstrapping. Left in place, "
              "'<host> resolves' passes")
        print("      on a dropped cluster's leftovers and cannot fail.")
        return FAIL

    ok(f"every tunnel record in the zone points at this repo's tunnel "
       f"({local_tunnel[:8]}…)")
    return PASS


# ------------------------------------------------------------------ flux (3)

def check_flux(args) -> int:
    """Flux has fetched the commit — before any absence is interpreted.

    Containment and a stalled Flux emit identical NotFound. Until the cluster
    is provably at the pushed revision, "not deployed yet" is unreadable.
    """
    if not shutil.which("kubectl"):
        huh("kubectl not installed")
        return UNKNOWN
    r, terr = _run_bounded(["kubectl", "--kubeconfig", args.kubeconfig, "get",
                            "gitrepository", "-A", "-o", "json"],
                           REMOTE_TIMEOUT, "kubectl get gitrepository")
    if r is None:
        huh(terr)
        return UNKNOWN
    if r.returncode != 0:
        huh(f"could not query the cluster: {r.stderr.strip().splitlines()[:1]}")
        return UNKNOWN

    items = json.loads(r.stdout).get("items", [])
    if not items:
        bad("no GitRepository objects at all — Flux is not installed or not "
            "reconciling; every absence you observe next would be meaningless")
        return FAIL

    matched = False
    for it in items:
        name = it["metadata"]["name"]
        conds = {c["type"]: c["status"] for c in it.get("status", {}).get("conditions", [])}
        rev = (it.get("status", {}).get("artifact") or {}).get("revision", "")
        ready = conds.get("Ready") == "True"
        has_sha = args.expect_sha in rev
        line = f"{name}: ready={conds.get('Ready')} revision={rev or '(none)'}"
        if ready and has_sha:
            ok(line)
            matched = True
        else:
            print(f"      {line}")
    if matched:
        return PASS
    bad(f"no GitRepository is Ready at a revision containing {args.expect_sha}")
    print("      Do not read any 'the resource is absent' result until this passes.")
    return FAIL


# ------------------------------------------------------------------- lan (4)

def _nslookup_answers(text: str) -> list[str]:
    """The addresses nslookup ANSWERED with — never the resolver's own.

    nslookup prints its server twice before any answer:

        Server:         10.9.1.53
        Address:        10.9.1.53#53      <- the resolver, not a result

    The previous form of this filter could not drop that line: it captured with
    `([0-9.]+)`, which stops before `#`, and then tested
    `a.endswith("#53")` — on a string from which `#53` had already been removed.
    **Dead code that read as a guard**, found 2026-09-13 by the first test ever
    written for this subcommand (#104).

    Both consequences were live, and the second is worse:

    1. A resolver whose own address happens to equal `--expect-addr` passed this
       check while resolving nothing.
    2. **The positive control could never fail.** `ctl_addrs` was non-empty for
       any resolver that replied at all, because the server line was always
       counted — so "github.com resolves, so forwarding works" was printed
       without being measured. That is this file's own doctrine breaking inside
       this file: a check that cannot fail reads exactly like one that passes.

    Capturing the whole token and rejecting anything containing `#` keeps the
    filter honest for `#53` and for a non-default port alike.

    Old vs new on the same four inputs (measured 2026-09-13; the third row is
    why the old form was worse than "it drops answers"):

        only the server line   old ['10.9.1.50']            new []
        server + IPv4 answer   old ['10.9.1.53','10.9.1.50'] new ['10.9.1.50']
        server + IPv6 answer   old ['10.9.1.53','2001']     new ['2001:db8::1']
        server on port 5353    old ['10.9.1.53','10.9.1.50'] new ['10.9.1.50']

    Row 3: the old capture stopped at the colon, so an IPv6 answer became the
    string `2001` — **an address that does not exist**, printed straight into the
    FAIL message below (`did not resolve to … (got: …)`). Whoever read that went
    looking for `2001`. A misleading diagnosis costs more than none.

    Row 4 is why the new form rejects any `#` rather than the literal `#53`: the
    old test could not have caught a resolver on a non-default port either. **The
    fix is deliberately wider than the defect — do not narrow it back for
    "precision".**
    """
    return [a for a in re.findall(r"^Address:\s*(\S+)", text, re.M) if "#" not in a]


def check_lan(args) -> int:
    """Internal names resolve, AND forwarding still works.

    The second half is the control. A cluster answering NXDOMAIN for everything
    looks like a correct configuration if you only test the one name you care
    about — and a client accepts NXDOMAIN and never asks the secondary.
    """
    if not shutil.which("nslookup"):
        huh("nslookup not installed")
        return UNKNOWN

    internal = f"internal.{args.domain}"
    # A resolver that never answers is not a name that does not resolve. The
    # FAIL below tells the operator to reconnect the client; sending them to do
    # that because the query hung would be a wrong instruction, confidently
    # given.
    r, terr = _run_bounded(["nslookup", internal], REMOTE_TIMEOUT,
                           f"nslookup {internal}")
    if r is None:
        huh(terr)
        return UNKNOWN
    got = _nslookup_answers(r.stdout)

    if args.expect_addr not in got:
        bad(f"{internal} did not resolve to {args.expect_addr} (got: "
            f"{', '.join(got) or 'nothing'})")
        print("      If nothing: the DHCP lease may not have renewed. Reconnect")
        print("      the client and retry BEFORE changing anything.")
        return FAIL
    ok(f"{internal} -> {args.expect_addr}")

    ctl, cterr = _run_bounded(["nslookup", "github.com"], REMOTE_TIMEOUT,
                              "nslookup github.com (positive control)")
    if ctl is None:
        # The control hanging proves nothing about forwarding, and the FAIL
        # below is a strong claim ("everything else on the LAN is broken").
        huh(cterr)
        return UNKNOWN
    ctl_addrs = _nslookup_answers(ctl.stdout)
    if not ctl_addrs:
        bad("positive control failed: github.com does not resolve through this "
            "resolver")
        print("      k8s-gateway is not forwarding. Internal names work and")
        print("      everything else on the LAN is broken — which is a worse")
        print("      outcome than the one this step was guarding against.")
        return FAIL
    ok("positive control: github.com resolves, so forwarding works")
    return PASS


# --------------------------------------------------- default gateway (5)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _merged_config(root: pathlib.Path):
    """cluster.yaml unified with nodes.yaml, the way `task configure` does it."""
    if not shutil.which("yq"):
        return None, "yq is not on PATH — run this under `mise exec`"
    files = [root / "cluster.yaml"]
    if (root / "nodes.yaml").is_file():
        files.append(root / "nodes.yaml")
    if not files[0].is_file():
        return None, f"{files[0]} not here — run this inside a cluster repo"
    r = run(["yq", "eval-all", "-o=json", ". as $i ireduce ({}; . * $i)",
             *[str(f) for f in files]])
    if r.returncode != 0:
        return None, f"yq could not read the config: {r.stderr.strip()[:140]}"
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError as e:
        return None, f"the merged config did not decode as JSON: {e}"


def _shipped_gateway(root: pathlib.Path):
    """(address, provenance, error). provenance is "declared" or "assumed".

    The address comes from the real `Plugin.data()`, never from a second copy
    of the `.1` rule. `#32` cost the whole fleet its ability to render because
    this file's neighbour held a copy of one value plugin.py owns, and the copy
    stayed behind when the original changed.
    """
    raw, err = _merged_config(root)
    if err:
        return None, None, err
    provenance = "declared" if "node_default_gateway" in raw else "assumed"
    loader = root / "scripts" / "check-node-dns-path.py"
    if not loader.is_file():
        return None, None, f"{loader} not here — it owns the makejinja stub"
    try:
        spec = importlib.util.spec_from_file_location("_cndp", loader)
        cndp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cndp)
        data = cndp.load_plugin().Plugin(dict(raw)).data()
    except Exception as e:  # a real repo has auth0.json; a bare one does not
        return None, provenance, f"could not render the config: {type(e).__name__}: {str(e)[:140]}"
    return data.get("node_default_gateway"), provenance, None


def _route_docs(args):
    """Whatever talosctl says, as a list of decoded JSON documents."""
    if args.routes_json:
        f = pathlib.Path(args.routes_json)
        if not f.is_file():
            return None, f"{f} not here"
        text = f.read_text()
    else:
        if not shutil.which("talosctl"):
            return None, "talosctl is not on PATH"
        cmd = ["talosctl"]
        if args.talosconfig:
            cmd += ["--talosconfig", args.talosconfig]
        cmd += ["-n", args.node, "get", "routes", "-o", "json"]
        r = run(cmd, timeout=args.timeout)
        if r.returncode != 0:
            return None, f"talosctl failed: {(r.stderr or r.stdout).strip()[:200]}"
        text = r.stdout
    docs, dec, i = [], json.JSONDecoder(), 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        try:
            doc, end = dec.raw_decode(text, i)
        except json.JSONDecodeError as e:
            return None, f"talosctl output did not decode as JSON at offset {i}: {e}"
        docs.append(doc)
        i = end
    return docs, None


def check_gateway(args) -> int:
    """The nodes' real default route, against the one this repo ships.

    `#49`: `node_default_gateway` defaults to `.1` of `node_cidr`, which is an
    assumption about someone else's LAN. It is invisible when wrong — configure
    succeeds, `cue vet` passes, the cluster boots, and nothing leaves the LAN —
    and it is invisible when right for the wrong reason, because the operator's
    own LANs are all `.1`, so the assumed string and the measured one match on
    every cluster this lab can test.

    Positive control, per this file's rule: a node always has routes. Zero
    routes back is what asking the wrong question looks like, not a node
    without a gateway, so it reports UNKNOWN rather than a missing default.

    Two default routes are not resolved by picking one — same rule as multiple
    candidate subnets for `node_cidr`.
    """
    shipped, provenance, err = _shipped_gateway(REPO_ROOT)
    if err:
        huh(f"cannot tell what this repo ships: {err}")
        return UNKNOWN

    docs, err = _route_docs(args)
    if err:
        huh(f"cannot measure the node's routes: {err}")
        print(f"      This repo would ship {shipped} ({provenance}). Unverified.")
        return UNKNOWN

    if not docs:
        huh("talosctl returned no routes at all")
        print("      Every node has routes, so this is the wrong question being")
        print("      asked — wrong node, wrong resource name, or no permission —")
        print("      not a node without a default gateway.")
        return UNKNOWN

    specs = [d.get("spec", d) for d in docs]
    if not any("gateway" in sp for sp in specs):
        keys = sorted({k for sp in specs if isinstance(sp, dict) for k in sp})
        huh(f"no route carries a `gateway` key across {len(docs)} routes")
        print(f"      Keys seen: {', '.join(keys) or 'none'}")
        print("      The selector below expects `gateway` and `dst`. If talosctl")
        print("      names them differently, fix the two names here — do not")
        print("      loosen this into picking whatever is first.")
        return UNKNOWN

    defaults = [
        sp for sp in specs
        if isinstance(sp, dict) and sp.get("gateway") and not sp.get("dst")
    ]
    # node_default_gateway is `net.IPv4` in cluster.schema.cue, so an IPv6
    # default route is not a second candidate for it — it is a different
    # question. Measured 2026-08-30 on a real 145-route capture from a jg-jiahd
    # node: 110 of them inet6, one of those with an empty dst (no gateway, so
    # it never reached this line). A node that does have an IPv6 default
    # gateway would have made the count two and this check would have refused
    # to choose — a false alarm on a healthy dual-stack node, which is the
    # failure mode that gets guards switched off.
    #
    # `family` absent is kept rather than dropped: an unknown shape should
    # widen the answer into "cannot tell", never narrow it into a confident one.
    other = sorted({sp["gateway"] for sp in defaults
                    if sp.get("family") not in (None, "", "inet4")})
    found = sorted({sp["gateway"] for sp in defaults
                    if sp.get("family") in (None, "", "inet4")})
    if other:
        print(f"      ({len(other)} non-IPv4 default route(s) not compared: "
              f"{', '.join(other)} — node_default_gateway is IPv4)")

    if not found:
        huh(f"{len(docs)} routes, none of them a default route")
        print("      A default route is one with a gateway and no destination.")
        return UNKNOWN
    if len(found) > 1:
        huh(f"{len(found)} default routes: {', '.join(found)}")
        print("      Refusing to pick. Which one the node uses depends on metric")
        print("      and interface, and guessing here would ship a number that")
        print("      looks measured. Decide on the node, then declare it.")
        return UNKNOWN

    measured = found[0]
    if measured != shipped:
        bad(f"this repo ships {shipped} ({provenance}); the node routes via {measured}")
        print("      Set node_default_gateway in cluster.yaml to the measured")
        print("      value and re-run `task configure`. Left alone, the cluster")
        print("      comes up and nothing reaches the internet.")
        return FAIL

    if provenance == "assumed":
        ok(f"default route {measured} — matches, but cluster.yaml does not say so")
        print("      Declare it anyway: it is right by coincidence today, and")
        print("      the next node_cidr change silently moves it.")
        return PASS
    ok(f"default route {measured} — declared in cluster.yaml and measured on the node")
    return PASS


# ------------------------------------------------- deploy key (6)

def check_deploy_key(args) -> int:
    """The deploy key exists locally AND GitHub has it.

    `#56`: `task init` runs `ssh-keygen` and the template renders the private
    half into a Secret, so every artefact a person would look at is present —
    and `gh api repos/<repo>/keys` was empty on jg-janncotcc. Nothing in either
    repo registers the public half, and on a PUBLIC repo nothing ever notices,
    because Flux clones anonymously. It surfaces only when the repo goes
    private, as `GitRepository READY=False` during a provisioning run.

    Registering is a runbook step (fleet-ops), not something this repo should
    do behind an operator's back — a write to someone's GitHub account is not a
    side effect of a check. Detecting it is this repo's half.

    Positive control: the local public key is compared to what GitHub returns,
    so a repo carrying somebody else's key is a finding rather than a pass.
    "The list is not empty" would accept exactly that.
    """
    pub = pathlib.Path(args.pubkey)
    if not pub.is_file():
        huh(f"{pub} is not here — run `task init` in the cluster repo first")
        return UNKNOWN
    if not shutil.which("gh"):
        huh("gh is not on PATH")
        return UNKNOWN

    # ssh-keygen writes "<type> <base64> <comment>"; GitHub returns and compares
    # the first two fields only, so the comment must not take part.
    local = " ".join(pub.read_text().split()[:2])

    r, terr = _run_bounded(["gh", "api", f"repos/{args.repo}/keys", "--jq",
                            ".[].key"], REMOTE_TIMEOUT, "gh api repos/…/keys")
    if r is None:
        huh(terr)
        print("      Same reason as below: no answer and an empty answer are")
        print("      different, and only one of them is a finding.")
        return UNKNOWN
    if r.returncode != 0:
        huh(f"could not list deploy keys: {r.stderr.strip()[:160]}")
        print("      Not reporting a missing key: no answer and an empty answer")
        print("      are different, and only one of them is a finding.")
        return UNKNOWN

    remote = [" ".join(k.split()[:2]) for k in r.stdout.splitlines() if k.strip()]
    if local in remote:
        ok(f"{args.repo} carries this repo's deploy key ({len(remote)} key(s) registered)")
        return PASS

    if not remote:
        bad(f"{args.repo} has no deploy keys at all")
    else:
        bad(f"{args.repo} has {len(remote)} deploy key(s), none of them this one")
    print("      Register it:")
    print(f"        gh api -X POST repos/{args.repo}/keys \\")
    print(f"          -f title='flux' -f key=\"$(cat {pub})\" -F read_only=true")
    print("      Until then a private repo cannot be synced: Flux authenticates")
    print("      with the matching private half and GitHub will refuse it.")
    return FAIL


# ------------------------------------------------ tunnel cert (7)

CERT_BLOCK = re.compile(
    r"-----BEGIN ARGO TUNNEL TOKEN-----(.*?)-----END ARGO TUNNEL TOKEN-----", re.S
)


def _cert_binding(cert: pathlib.Path) -> tuple[dict, str | None]:
    """The accountID/zoneID a cloudflared cert is bound to.

    The file is a base64 JSON blob with exactly three keys: `accountID`,
    `zoneID` and `apiToken`. **The third is a credential.** Only the first two
    are ever returned, and nothing here formats the parsed object as a whole —
    a check that leaks the secret it is validating is a worse trade than the
    check is worth.
    """
    try:
        text = cert.read_text()
    except OSError as e:
        return {}, f"could not read it: {e}"
    m = CERT_BLOCK.search(text)
    if not m:
        return {}, "no ARGO TUNNEL TOKEN block in it — is this a cloudflared cert?"
    try:
        payload = json.loads(base64.b64decode("".join(m.group(1).split())))
    except Exception as e:  # noqa: BLE001 — malformed is "cannot tell", not a finding
        return {}, f"the token block did not decode: {type(e).__name__}"
    if not isinstance(payload, dict):
        return {}, "the token block is not an object"
    return (
        {k: payload.get(k) for k in ("accountID", "zoneID") if payload.get(k)},
        None,
    )


def check_tunnel_cert(args) -> int:
    """Which Cloudflare account `cloudflared tunnel login` actually bound to.

    Nothing checks this today, and every downstream step passes when it is
    wrong: `cloudflared tunnel create` succeeds, `cloudflare-tunnel.json` is
    written, `task configure` renders. The cluster comes up and the tunnel
    answers **1033**.

    Measured 2026-09-02 (`#63`): re-running the runbook's Step 2 opened a
    browser already signed in as the operator, while the account being
    authorised had to be the customer's. The authorisation page even lists a
    `Moved` remnant of the old account with the right name and an `Active`
    plan. What stopped it was a person reading the screen.

    So this is the after-the-fact half. It cannot prevent clicking Authorize in
    the wrong window — nothing measured that day could — it catches it before
    the cert is used for anything.

    The filename is never evidence. `fleet-ops docs/deploy/manual.md` Stage 4
    says so, and the fixture that proves it is called `cert.pem.for.janncot`
    while being bound to the operator's own account.
    """
    cert = pathlib.Path(args.cert).expanduser()
    if not cert.is_file():
        huh(f"{cert} is not here")
        print("      That is also the state right before `cloudflared tunnel")
        print("      login` — absent and wrong are different answers, so this")
        print("      reports neither pass nor fail.")
        return UNKNOWN

    binding, err = _cert_binding(cert)
    if err:
        huh(f"{cert}: {err}")
        return UNKNOWN
    if "accountID" not in binding or "zoneID" not in binding:
        huh(f"{cert} carries {sorted(binding) or 'nothing'} — expected accountID and zoneID")
        return UNKNOWN

    token = os.environ.get(args.token_env or "CLOUDFLARE_TOKEN", "")
    if not token:
        huh(_no_token(args.token_env, args.domain))
        print(f"      The cert is bound to account {binding['accountID']},")
        print(f"      zone {binding['zoneID']}. Compare by hand, or set the token.")
        return UNKNOWN

    zone, err = _cf_zone(args.domain, args.token_env)
    if zone is None:
        huh(err)
        print("      (the same query backs handover cell 2, which compares the")
        print("      tunnel credential's AccountTag against this zone)")
        return UNKNOWN

    want_zone = zone.get("id")
    want_account = (zone.get("account") or {}).get("id")
    got_zone, got_account = binding["zoneID"], binding["accountID"]

    wrong = []
    if got_account != want_account:
        wrong.append(("account", got_account, want_account))
    if got_zone != want_zone:
        wrong.append(("zone", got_zone, want_zone))

    if not wrong:
        ok(f"{cert.name} is bound to the account and zone that own {args.domain}")
        print(f"      account {got_account}  zone {got_zone}")
        return PASS

    bad(f"{cert.name} is bound to the wrong Cloudflare account for {args.domain}")
    for what, got, want in wrong:
        print(f"      {what}: cert says {got}")
        print(f"      {' ' * len(what)}  {args.domain} belongs to {want}")
    print("      Re-run `cloudflared tunnel login` in a browser signed in as the")
    print("      account that owns this domain, and check the window before")
    print("      authorising. A tunnel built on this cert answers 1033 and")
    print("      nothing before that point complains.")
    return FAIL


# ------------------------------------------------- handover (§7.1a, jgct#102)
#
# Step 5 of the provisioning runbook is the last gate before a cluster is
# handed over, and it is 22 cells long. Five already had subcommands here, four
# can only be answered by a person, and the thirteen in between were executable
# with nothing behind them (jgct#102).
#
# One subcommand rather than thirteen, decided in that issue: eight subcommands
# means the person on site runs seven of them on a bad day, and **the one not
# run reads exactly like the one that passed**. A table loses a row visibly; a
# missing invocation loses nothing visibly.
#
# No run of this is authoritative. Cells need different vantage points and
# different tools, so what Step 5 needs is one PASS per cell from somewhere
# that could measure it. That is why every 2 below carries a KIND: "go stand
# somewhere else" and "install something here" are both 2, and their next
# actions are opposite -- collapsing them into one count is the same mistake
# as collapsing "cannot measure" into "passed" (FO-runbook [5fe39a],
# jgct#102).

# Why a cell could not answer. The point of separating these is the next
# action, which differs for each.
NEED_PLACE = "vantage"    # re-run from a place that can see it
NEED_TOOL = "tool"        # install or configure something here
NEED_HUMAN = "person"     # no machine can answer this half
NOT_YET = "phase2"        # jgct#102 phase 2
PAUSED = "ruling"         # a ruling says: do not judge this; nothing to run anywhere

WHY_TEXT = {
    NEED_PLACE: "need a different vantage point — re-run from there",
    NEED_TOOL: "need a tool or credential here — install/set it, same place",
    NEED_HUMAN: "a person must answer this half; no run of this can",
    NOT_YET: "not implemented yet (jgct#102, a later phase)",
    PAUSED: "paused by a ruling — not judged until it changes; nothing to install, nowhere to re-run from",
}


def _no_token(token_env: str, domain: str) -> str:
    """One wording for one condition. Two wordings for the same state read as
    two different states to whoever greps the output."""
    return (f"${token_env or 'CLOUDFLARE_TOKEN'} not set — cannot ask Cloudflare "
            f"which account owns {domain}")


def _is_cluster_repo(d: pathlib.Path) -> bool:
    """Is this a cluster's own directory, or somewhere else entirely?

    Same marker _merged_config already uses ("run this inside a cluster repo"),
    and it decides the meaning of a missing file: inside a cluster repo, absent
    means the thing was never created (FAIL); outside one, absent means this
    check is looking in the wrong place (UNKNOWN). Cells 2 and 3 gave opposite
    answers to that same question until FO-runbook [5fe39a] put them side by
    side on one empty directory -- and both answers were wrong, in opposite
    directions.
    """
    return (d / "cluster.yaml").is_file()


def _cf_zone(domain: str, token_env: str) -> tuple[dict | None, str | None]:
    """The one Cloudflare zone named `domain`, or a reason there is no answer.

    Shared with check_tunnel_cert rather than copied: two copies of a
    Cloudflare query would drift, and the copy that drifts is the one that
    keeps returning a comfortable answer.
    """
    token = os.environ.get(token_env or "CLOUDFLARE_TOKEN", "")
    if not token:
        return None, _no_token(token_env, domain)
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones?name={domain}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.load(r)
    except Exception as e:  # noqa: BLE001
        return None, f"could not query Cloudflare: {e}"
    zones = body.get("result") or []
    if len(zones) != 1:
        return None, (f"Cloudflare returned {len(zones)} zones named {domain} — "
                      f"zero means this token cannot see it (a finding, but not "
                      f"this one); more than one would mean picking, which "
                      f"invents an answer")
    return zones[0], None


def _curl_headers(url: str, timeout: int = 15,
                  resolve: str | None = None) -> tuple[int | None, dict, str | None]:
    """(status, headers, error) for one request, WITHOUT following redirects.

    The redirect is the assertion in cell 4, so following it would throw away
    the thing being measured.

    `resolve` pins one name to one address for this request (curl --resolve).
    Without it the name goes to the system resolver, and on a LAN that
    intercepts port 53 the reply describes *where the caller is standing*, not
    the path being handed over -- a 200 with no `cf-ray`, which reads as a
    broken cluster (jgct#131, cell 8).
    """
    if not shutil.which("curl"):
        return None, {}, "curl is not on PATH"
    cmd = ["curl", "-sS", "-o", os.devnull, "-D", "-", "-m", str(timeout),
           "--max-redirs", "0"]
    if resolve:
        cmd += ["--resolve", resolve]
    cmd.append(url)
    r = run(cmd)
    if r.returncode != 0:
        return None, {}, (r.stderr.strip()[:160] or f"curl exited {r.returncode}")
    status, hdrs = None, {}
    for line in r.stdout.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            hdrs = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, None


def cell_tunnel_account(args) -> tuple[int, str, str | None]:
    """2. The tunnel was created in the account that owns the zone.

    Not merged with `tunnel-cert`, deliberately, and each names the other in
    its output. They read files produced by different commands -- cert.pem by
    `cloudflared tunnel login`, cloudflare-tunnel.json by `tunnel create` --
    so "the two agree" is an inference, not an assertion. Merged, either
    failure would hide behind the other, and all three roads end at 1033.
    """
    d = pathlib.Path(args.dir)
    p = d / args.tunnel_credentials
    if not p.is_file():
        if not _is_cluster_repo(d):
            return UNKNOWN, (f"{d} is not a cluster repo (no cluster.yaml), so "
                             f"a missing {args.tunnel_credentials} says nothing "
                             f"— run this in the cluster's directory"), NEED_PLACE
        return FAIL, (f"{p} is not here, in a cluster repo that has a "
                      f"cluster.yaml — `cloudflared tunnel create` never "
                      f"produced a credential (sibling check: tunnel-cert)"), None
    try:
        tag = json.loads(p.read_text()).get("AccountTag") or ""
    except json.JSONDecodeError as e:
        return FAIL, f"{p} did not decode as JSON: {e}", None
    if not tag:
        return FAIL, f"{p} has no AccountTag — not a `tunnel create` credential", None
    zone, err = _cf_zone(args.domain, args.token_env)
    if zone is None:
        return UNKNOWN, f"{err} (sibling check: tunnel-cert)", NEED_TOOL
    want = (zone.get("account") or {}).get("id")
    if tag == want:
        return PASS, f"tunnel and {args.domain} are both in account {want}", None
    return FAIL, (f"tunnel was created in account {tag}, but {args.domain} "
                  f"belongs to {want} — `cloudflared tunnel create` ran while "
                  f"logged into the wrong account (tunnel-cert checks the other "
                  f"half, the login cert)"), None


def cell_factory_auth0(args) -> tuple[int, str, str | None]:
    """3. The factory Auth0 file is in the cluster directory and complete.

    Key NAMES and lengths only. The file holds a client_secret and this output
    gets pasted into handover notes.
    """
    d = pathlib.Path(args.dir)
    p = d / args.auth0_json
    if not p.is_file():
        if not _is_cluster_repo(d):
            return UNKNOWN, (f"{d} is not a cluster repo (no cluster.yaml), so "
                             f"a missing {args.auth0_json} says nothing — run "
                             f"this in the cluster's directory"), NEED_PLACE
        return FAIL, (f"{p} is not here — the base im is Auth0-gated on every "
                      f"cluster (jgct#84), so a missing factory file means no "
                      f"rescue terminal at all"), None
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        return FAIL, f"{p} did not decode as JSON: {e}", None
    missing = [k for k in ("domain", "client_id", "client_secret", "allowed_emails")
               if not data.get(k)]
    if missing:
        return FAIL, (f"{p} is missing or has empty: {', '.join(missing)} — an "
                      f"empty allowed_emails renders a gate that admits nobody, "
                      f"which looks like a broken cluster"), None
    emails = data["allowed_emails"]
    n = len(emails) if isinstance(emails, (list, tuple)) else 1
    return PASS, (f"{p.name}: domain={data['domain']}, client_id "
                  f"({len(str(data['client_id']))} chars), client_secret "
                  f"({len(str(data['client_secret']))} chars), allowed_emails "
                  f"({n} entries)"), None


def cell_im_front_door(args) -> tuple[int, str, str | None]:
    """4. im's front door redirects to the factory tenant.

    Returns UNKNOWN even when the redirect is right, on purpose. A correct 302
    proves oauth2-proxy is up and pointed at the right tenant; it does NOT
    prove the callback URL is registered in that Auth0 application, and that
    failure appears only after a human logs in. Reporting 0 would answer a
    question this cannot see (jgct#102, cell 4).
    """
    host = f"{args.instance}.{args.domain}"
    status, hdrs, err = _curl_headers(f"https://{host}/")
    if err:
        return UNKNOWN, f"could not reach https://{host}/ — {err}", NEED_TOOL
    if status == 503:
        return FAIL, (f"https://{host}/ returns 503 — oauth2-proxy is not "
                      f"running, and in OIDC mode ttyd binds to loopback, so "
                      f"there is no way in at all"), None
    if status not in (301, 302, 303, 307, 308):
        return FAIL, f"https://{host}/ returned {status}, not a redirect to Auth0", None
    loc = hdrs.get("location", "")
    tenant = ""
    ap = pathlib.Path(args.dir) / args.auth0_json
    if ap.is_file():
        try:
            tenant = json.loads(ap.read_text()).get("domain") or ""
        except json.JSONDecodeError:
            tenant = ""
    if "/authorize" not in loc:
        return FAIL, f"https://{host}/ redirects to {loc[:80]}, not an /authorize", None
    if tenant and tenant not in loc:
        return FAIL, (f"https://{host}/ redirects to {loc[:80]} — a different "
                      f"tenant from {args.auth0_json}'s {tenant}"), None
    where = f"the tenant in {args.auth0_json}" if tenant else "an /authorize endpoint"
    return UNKNOWN, (f"{host} redirects to {where}: the door is up and pointed "
                     f"right. Unverifiable from here: whether "
                     f"https://{host}/oauth2/callback is registered in that "
                     f"Auth0 application — that failure appears after login"), NEED_HUMAN


# The private per-user repo direction was paused by ferry133 on 2026-09-10
# (ferry133/fleet-ops#8 and jgct#56 closed as not planned; the runbook's Step 3
# has built --public since). While this stands, cell 5 does not judge: its FAIL
# read "make it PRIVATE, switch sync to ssh://, add the deploy key" -- the paused
# path, on every cluster, since every user repo is public (jgct#131, ruling
# 2026-09-13: "改成附裁定出處的 ?"). Set to None to put the three checks back to
# work; they are kept below, unchanged, for that day. Not deleted: a ruling that
# is reversed needs the code to still be there.
PRIVATE_REPO_PAUSED: dict | None = {
    "since": "2026-09-10",
    "by": "ferry133",
    "refs": ("ferry133/fleet-ops#8", "ferry133/jg-cluster-template#56"),
}


def cell_private_repo(args) -> tuple[int, str, str | None]:
    """5. Three things about a private per-user repo, all of which must hold.

    Since 2026-09-10 the cell does not judge at all -- see PRIVATE_REPO_PAUSED
    above; the row carries the ruling and the kind `ruling`, so the summary
    does not tell anyone to install or re-run anything.

    Phase 1 owns the two that need no cluster; the FluxInstance sync line is
    phase 2 and says so rather than reporting a bare "unchecked" -- except
    when a --kubeconfig is on hand, in which case not looking would be
    throwing away a measurement to keep a tidy phase boundary.

    The deploy-key third calls check_deploy_key rather than restating it: a
    second implementation drifts, and the copy that drifts keeps passing.
    """
    if PRIVATE_REPO_PAUSED:
        p = PRIVATE_REPO_PAUSED
        return UNKNOWN, (f"not judged: the private-repo direction was paused by "
                         f"{p['by']} on {p['since']} ({', '.join(p['refs'])} closed as "
                         f"not planned). A FAIL here would send you down the paused "
                         f"path; the three checks stay in the code for when the "
                         f"ruling changes"), PAUSED

    parts, worst, kinds = [], PASS, set()

    def worsen(rc, kind=None):
        # Every reason, not the first one. This cell can be 2 for three
        # different reasons at once, and keeping only the first hid it from the
        # phase-2 list: whoever lands phase 2 would not know half of cell 5 was
        # still missing (FO-runbook [5fe39a] on PR#103).
        nonlocal worst
        if rc == UNKNOWN and kind:
            kinds.add(kind)
        if rc == FAIL:
            worst = FAIL
        elif rc == UNKNOWN and worst != FAIL:
            worst = UNKNOWN

    if not args.repo:
        parts.append("--repo not given: GitHub visibility unchecked")
        worsen(UNKNOWN, NEED_TOOL)
    elif not shutil.which("gh"):
        parts.append("gh is not on PATH: visibility unchecked")
        worsen(UNKNOWN, NEED_TOOL)
    else:
        r, terr = _run_bounded(["gh", "repo", "view", args.repo, "--json",
                                "visibility"], REMOTE_TIMEOUT, "gh repo view")
        if r is None:
            parts.append(terr)
            worsen(UNKNOWN, NEED_PLACE)
        elif r.returncode != 0:
            parts.append(f"gh could not read {args.repo}: {r.stderr.strip()[:80]}")
            worsen(UNKNOWN, NEED_TOOL)
        else:
            vis = (json.loads(r.stdout or "{}").get("visibility") or "").upper()
            if vis == "PRIVATE":
                parts.append(f"{args.repo} is PRIVATE")
            else:
                parts.append(f"{args.repo} is {vis or 'unknown'}, not PRIVATE")
                worsen(FAIL)

    if not args.kubeconfig:
        # Implemented since phase 1 -- it runs the moment a kubeconfig is on
        # hand. Absent one, this is a vantage problem, and calling it "not
        # implemented" put it in the same list as the cells nobody has written.
        parts.append("FluxInstance sync line: needs --kubeconfig to be read")
        worsen(UNKNOWN, NEED_PLACE)
    else:
        r, terr = _run_bounded(["kubectl", "--kubeconfig", args.kubeconfig, "-n",
                                "flux-system", "get", "fluxinstance", "flux",
                                "-o", "json"],
                               REMOTE_TIMEOUT, "kubectl get fluxinstance")
        if r is None:
            parts.append(terr)
            worsen(UNKNOWN, NEED_PLACE)
        elif r.returncode != 0:
            parts.append(f"FluxInstance unreadable: {r.stderr.strip()[:80]}")
            worsen(UNKNOWN, NEED_PLACE)
        else:
            sync = (json.loads(r.stdout or "{}").get("spec") or {}).get("sync") or {}
            url, secret = sync.get("url", ""), sync.get("pullSecret", "")
            trouble = []
            if not url.startswith("ssh://"):
                trouble.append(f"sync url is {url[:40]!r}, not ssh://")
            if secret != "github-deploy-key":
                trouble.append(f"pullSecret is {secret!r}, not github-deploy-key")
            if trouble:
                parts.append("; ".join(trouble))
                worsen(FAIL)
            else:
                parts.append("FluxInstance syncs over ssh:// with github-deploy-key")

    if not args.repo:
        parts.append("deploy-key: skipped, no --repo")
        worsen(UNKNOWN, NEED_TOOL)
    else:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = check_deploy_key(args)
        first = re.sub(r"\s+", " ",
                       (buf.getvalue().splitlines() or ["(no output)"])[0]).strip()
        parts.append(f"deploy-key -> {first[:100]}")
        worsen(rc, NEED_TOOL)

    return worst, " | ".join(parts), (kinds if worst == UNKNOWN else None)


def cell_echo_ext(args) -> tuple[int, str, str | None]:
    """8. The external echo answers, and answers through Cloudflare.

    200 alone is not the assertion: the same 200 comes back when the name
    resolves to something on the LAN. `cf-ray` is what says the request
    actually crossed Cloudflare, which is the path being handed over.
    """
    host = f"echo-ext.{args.domain}"
    # Ask a resolver outside the building and pin the answer, the same line
    # cell 13 already uses. Handing the name to the system resolver measured
    # the LAN instead: a router that intercepts port 53 answers with the
    # k8s-gateway address, the request never leaves the site, and the 200 comes
    # back with no cf-ray -- reported as "answered by something other than
    # Cloudflare", which sends the reader to fix a cluster that is fine
    # (jgct#131; four such things were checked before the vantage was).
    control, cerr = _doh_a("cloudflare.com")
    if cerr or not control:
        return UNKNOWN, (f"the positive control (cloudflare.com) did not resolve "
                         f"over DoH{': ' + cerr if cerr else ''} — this box "
                         f"cannot ask a public resolver, so nothing it learns "
                         f"about {host} would mean anything"), NEED_TOOL
    addrs, aerr = _doh_a(host)
    if aerr:
        return UNKNOWN, f"DoH query for {host} failed: {aerr}", NEED_TOOL
    if not addrs:
        return FAIL, (f"{host} does not resolve from a public resolver, while "
                      f"the control does — the public name does not exist, "
                      f"whatever the LAN answers for it"), None
    public = [a for a in addrs if _is_public_v4(a)]
    if not public:
        return FAIL, (f"{host} resolves publicly to {', '.join(addrs)} — all "
                      f"private, so the public path ends inside the building"), None
    pin = public[0]
    status, hdrs, err = _curl_headers(f"https://{host}/",
                                      resolve=f"{host}:443:{pin}")
    if err:
        return UNKNOWN, f"could not reach https://{host}/ at {pin} — {err}", NEED_TOOL
    if status != 200:
        return FAIL, f"https://{host}/ at {pin} returned {status}, not 200", None
    if "cf-ray" not in hdrs:
        return FAIL, (f"https://{host}/ at {pin} returned 200 with no cf-ray "
                      f"header — that address is what a public resolver gives "
                      f"for this name, so the gap is in front of the tunnel, "
                      f"not in this LAN"), None
    return PASS, (f"{host} at {pin} (public resolver) 200 with cf-ray "
                  f"{hdrs['cf-ray'][:20]}"), None


def _doh_a(name: str) -> tuple[list[str], str | None]:
    """A records for `name` from a public resolver, never the local one.

    Cell 13 exists because the local resolver answers for the LAN: an endpoint
    of `http://10.9.1.12:9000` returned 200 from the lab bench. Asking a
    resolver outside the building is the whole point.
    """
    url = ("https://cloudflare-dns.com/dns-query?name="
           + urllib.parse.quote(name) + "&type=A")
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
    except Exception as e:  # noqa: BLE001
        return [], f"DoH query failed: {e}"
    return sorted({a["data"] for a in data.get("Answer", []) if a.get("type") == 1}), None


def _is_public_v4(addr: str) -> bool:
    try:
        parts = [int(x) for x in addr.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    a, b = parts[0], parts[1]
    if a in (10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 169 and b == 254:
        return False
    return True


def _kubectl(args, *rest: str) -> tuple[bool, str, str]:
    """(ok, stdout, reason). No --kubeconfig is a vantage problem, not a fail."""
    if not args.kubeconfig:
        return False, "", "no --kubeconfig: this run cannot see the cluster"
    if not shutil.which("kubectl"):
        return False, "", "kubectl is not on PATH"
    r, terr = _run_bounded(["kubectl", "--kubeconfig", args.kubeconfig, *rest],
                           REMOTE_TIMEOUT, f"kubectl {' '.join(rest[:2])}")
    if r is None:
        return False, "", terr
    if r.returncode != 0:
        return False, "", r.stderr.strip()[:140] or f"kubectl exited {r.returncode}"
    return True, r.stdout, ""


def _secret_values(args, ns: str, name: str) -> tuple[dict | None, str | None]:
    """Decoded keys of one Secret.

    The values come back so a check can assert their shape; NOTHING here may
    print one. Cells 11 and 13 read a capability URL and an endpoint out of
    these, and this output gets pasted into handover notes.
    """
    okc, out, err = _kubectl(args, "-n", ns, "get", "secret", name, "-o", "json")
    if not okc:
        return None, err
    try:
        raw = (json.loads(out).get("data") or {})
    except json.JSONDecodeError as e:
        return None, f"secret {ns}/{name} did not decode as JSON: {e}"
    vals = {}
    for k, v in raw.items():
        try:
            vals[k] = base64.b64decode(v).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            vals[k] = ""
    return vals, None


def _dig(resolver: str, name: str, timeout: int = 5) -> tuple[list[str], str | None]:
    if not shutil.which("dig"):
        return [], "dig is not on PATH"
    r = run(["dig", f"@{resolver}", "+short", f"+time={timeout}", "+tries=1", "A", name])
    if r.returncode != 0:
        return [], r.stderr.strip()[:120] or f"dig exited {r.returncode}"
    return [ln.strip() for ln in r.stdout.splitlines()
            if ln.strip() and not ln.strip().endswith(".")], None


def _newest_completed_job_log(args) -> tuple[str | None, str, str | None, str | None]:
    """(job name, its log, reason there is none).

    One reader for cells 7 and 12: they are asking different questions of the
    same run, and two readers would drift into asking them of two different
    runs.

    "It ran" and "you can still see what it printed" are separate facts. A
    Job object outlives its pod, so a scheduled run whose pod has been
    reclaimed leaves the first true and the second false -- and only the second
    can answer these cells. That case is UNKNOWN, never a pass.
    """
    okj, jout, jerr = _kubectl(args, "-n", "monitoring", "get", "jobs",
                              "-o", "json")
    if not okj:
        # Cannot reach the cluster at all: a vantage problem, not a "wait for
        # the schedule" problem. The two 2s have opposite next actions.
        return None, "", jerr, NEED_PLACE
    # NOT a label selector. `-l app=daily-check` matched zero Jobs on every
    # cluster, because jg-base's cronjob.yaml sets no labels anywhere -- so
    # these cells could never pass, and said "no completed daily-check Job",
    # which reads as "the schedule has not come round yet" (jgct#131).
    # The Job's owner is the fact that identifies it, and the kubelet writes
    # it; the name prefix is the fallback for a hand-made run.
    items = json.loads(jout or "{}").get("items", [])
    mine = [j for j in items
            if any(r.get("kind") == "CronJob" and r.get("name") == "daily-check"
                   for r in (j.get("metadata") or {}).get("ownerReferences") or [])
            or (j.get("metadata") or {}).get("name", "").startswith("daily-check-")]
    jobs = [j for j in mine if (j.get("status") or {}).get("succeeded", 0)]
    if not jobs:
        # Carry the denominators: "0 of 0" (nothing has run) and "0 of 3"
        # (three ran and none succeeded) need opposite next actions, and the
        # sentence without them cannot tell them apart.
        return None, "", (f"no completed Job from CronJob/daily-check "
                          f"({len(mine)} of the namespace's {len(items)} Job(s) "
                          f"come from it, none succeeded)"), NEED_TOOL
    jobs.sort(key=lambda j: (j.get("status") or {}).get("completionTime") or "")
    name = jobs[-1]["metadata"]["name"]
    okl, logs, lerr = _kubectl(args, "-n", "monitoring", "logs", f"job/{name}",
                              "--tail", "400")
    if not okl or not logs.strip():
        return name, "", (f"job/{name} completed but its log is gone "
                          f"({lerr or 'empty output'}) — the pod was reclaimed. "
                          f"That it ran and what it printed are different "
                          f"facts"), NEED_TOOL
    return name, logs, None, None


def cell_node_dns_path(args) -> tuple[int, str, str | None]:
    """6. NODE_DNS_PATH is `lan`, and the resolver answers BOTH questions.

    Unset derives to `public` in silence and turns daily-check's check 18 into
    a `➖`, which travels in the same email as a pass. And a resolver is only
    the right one if it answers a public name AND a split-horizon one: the
    cluster's own k8s-gateway address fails the first, which is why one dig is
    not enough (jgct#102, cell 6).
    """
    vals, err = _secret_values(args, "monitoring", "daily-check-config")
    if vals is None:
        return UNKNOWN, err, NEED_PLACE
    got = (vals.get("NODE_DNS_PATH") or "").strip()
    if got != "lan":
        return FAIL, (f"NODE_DNS_PATH is {got or '(empty)'!r}, not 'lan' — unset "
                      f"derives to public in silence and check 18 becomes a ➖, "
                      f"which reads like a pass in the same email"), None
    if not args.resolver:
        return UNKNOWN, ("NODE_DNS_PATH is 'lan'. The resolver itself is "
                         "unchecked: pass --resolver ADDR (the candidate from "
                         "Step 5) so both questions get asked"), NEED_TOOL
    pub, perr = _dig(args.resolver, "ghcr.io")
    if perr:
        return UNKNOWN, f"dig unavailable: {perr}", NEED_TOOL
    internal = f"internal.{args.domain}"
    priv, _ = _dig(args.resolver, internal)
    if pub and priv:
        return PASS, (f"NODE_DNS_PATH=lan and {args.resolver} answers both "
                      f"ghcr.io and {internal}"), None
    missing = []
    if not pub:
        missing.append("ghcr.io (a public name — the cluster's own k8s-gateway "
                       "address fails exactly here)")
    if not priv:
        missing.append(f"{internal} (the split-horizon name)")
    return FAIL, (f"{args.resolver} did not answer: {'; '.join(missing)}. A "
                  f"resolver that answers one of the two is the wrong one"), None


def cell_daily_check_ran(args) -> tuple[int, str, str | None]:
    """7. daily-check has actually produced THE ROW, not merely run.

    Two corrections live in this function, both from FO-runbook [5fe39a]:

    The runbook said `kubectl create job --from=cronjob/daily-check`. A gate
    that changes what it is checking is a gate nobody runs on a customer
    cluster, and a check nobody runs equals no check.

    My first read-only version then asserted `lastScheduleTime != <none>` plus
    a completed Job -- and that proves only that it RAN. A completed Job whose
    check 18 printed `➖ not measured` satisfies it exactly, which is
    jg-janncotcc's shape and the thing this cell exists to catch. The Job's
    success and what check 18 printed are independent: `lastScheduleTime` means
    the controller created a Job, `lastSuccessfulTime` means exit 0, and both
    stop short of the row.

    So the evidence is the row itself, read out of the run's log: still
    read-only, and the assertion rather than a proxy for it.
    """
    name, logs, why, kind = _newest_completed_job_log(args)
    if logs == "":
        if kind == NEED_PLACE:
            return UNKNOWN, why, NEED_PLACE
        hint = (". Wait for the schedule, or re-run with --trigger (which "
                "WRITES a Job)") if not args.trigger else ""
        if args.trigger and name is None:
            okt, _, terr = _kubectl(args, "-n", "monitoring", "create", "job",
                                   f"handover-check-{os.getpid()}",
                                   "--from=cronjob/daily-check")
            if not okt:
                return FAIL, f"{why}; --trigger could not create a Job: {terr}", None
            return UNKNOWN, (f"{why}. --trigger created a Job (this run WROTE to "
                             f"the cluster) — read this cell again once it "
                             f"finishes"), NEED_TOOL
        return UNKNOWN, f"{why}{hint}", kind or NEED_TOOL
    row = None
    for line in logs.splitlines():
        if "LAN resolves internal names" in line:
            row = line.strip()
    if row is None:
        return UNKNOWN, (f"job/{name} left a log with no 'LAN resolves internal "
                         f"names' line at all — it may have exited at the 'not "
                         f"configured' guard (cell 10), or the summary was "
                         f"truncated"), NEED_TOOL
    if row.startswith("➖"):
        return FAIL, (f"job/{name} printed: {row[:150]} — the row exists and "
                      f"measures nothing, and a ➖ travels in the same mail as "
                      f"the passes"), None
    if row.startswith("❌") or row.startswith("⚠️"):
        return FAIL, f"job/{name} printed: {row[:150]}", None
    return PASS, f"job/{name} printed: {row[:150]}", None


def cell_daily_check_configured(args) -> tuple[int, str, str | None]:
    """10. daily_check_* is configured.

    With them unset the CronJob prints "not configured" and exits 0, so
    nothing anywhere goes red -- the deliberate design (jg-base's guard), and
    the reason this cell exists at all.
    """
    vals, err = _secret_values(args, "monitoring", "daily-check-config")
    if vals is None:
        return UNKNOWN, err, NEED_PLACE
    need = ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM",
            "NOTIFY_EMAIL_TO")
    empty = [k for k in need if not (vals.get(k) or "").strip()]
    if empty:
        return FAIL, (f"empty in daily-check-config: {', '.join(empty)} — the "
                      f"Job prints 'not configured' and exits 0, so no cluster "
                      f"and no inbox will ever say so"), None
    shown = {k: ("set" if "PASSWORD" in k else vals[k]) for k in need}
    return PASS, ("daily-check-config: "
                  + ", ".join(f"{k}={shown[k]}" for k in need)), None


def cell_dead_man_switch(args) -> tuple[int, str, str | None]:
    """11. The dead-man switch actually has somewhere to ping.

    Measured on jg-janncotcc 2026-08-23: FAIL_COUNT=2 and the ping went to an
    empty string. A failing check that pings nowhere holds nothing up.

    The URL is a capability -- anyone holding it can silence the alarm -- so
    this reports set/length, never the value.
    """
    vals, err = _secret_values(args, "monitoring", "daily-check-config")
    if vals is None:
        return UNKNOWN, err, NEED_PLACE
    url = (vals.get("HEALTHCHECKS_PING_URL") or "").strip()
    if not url:
        return FAIL, ("HEALTHCHECKS_PING_URL is empty — the dead-man switch "
                      "pings nowhere, so a cluster that stops reporting looks "
                      "exactly like a cluster that is fine"), None
    if not url.startswith("https://"):
        return FAIL, (f"HEALTHCHECKS_PING_URL does not start with https:// "
                      f"({len(url)} chars, value not printed)"), None
    return PASS, f"dead-man switch URL is set ({len(url)} chars, not printed)", None


def cell_recipients_readback(args) -> tuple[int, str, str | None]:
    """12. Who the last real run actually mailed, read off that run.

    Off the run, not off the Secret: the Secret is what you think you set. This
    half is the machine's; whether those are the right people, and whether they
    would act, is a person's and is not attempted here.
    """
    name, logs, why, kind = _newest_completed_job_log(args)
    if logs == "":
        if kind == NEED_PLACE:
            return UNKNOWN, why, NEED_PLACE
        return UNKNOWN, (f"{why} — the same evidence cell 7 is missing, and for "
                         f"the same reason"), NEED_TOOL
    to = re.search(r"==> Sending email to (.+)", logs)
    sent = "Email sent successfully." in logs
    if to and sent:
        return PASS, (f"job/{name} mailed {to.group(1).strip()} and msmtp "
                      f"accepted it. Whether those are the people who would "
                      f"act is a person's question, not this one's"), NEED_HUMAN
    if to and not sent:
        return FAIL, (f"job/{name} addressed {to.group(1).strip()} but msmtp "
                      f"returned non-zero — the report was composed and not "
                      f"delivered"), None
    return UNKNOWN, (f"job/{name} logs have no 'Sending email to' line — it may "
                     f"have exited at the 'not configured' guard (cell 10)"), NEED_TOOL


def cell_r2_endpoint(args) -> tuple[int, str, str | None]:
    """13. The offsite endpoint, read OFF THE CLUSTER, is a shipping value.

    Off the cluster on purpose: read from cluster.yaml it would pass in exactly
    the situation it exists to catch -- edited locally, never applied. My first
    implementation did that, and FO-runbook [5fe39a] caught it before it
    shipped.

    Then resolved through a public resolver, never the local one, with a
    positive control in the same shape: jg-janncotcc shipped
    `http://10.9.1.12:9000`, which answered 200 from the lab bench.
    """
    vals, err = _secret_values(args, "monitoring", "offsite-backup-config")
    if vals is None:
        return UNKNOWN, err, NEED_PLACE
    ep = (vals.get("BACKUP_R2_ENDPOINT") or "").strip()
    if not ep:
        return UNKNOWN, ("BACKUP_R2_ENDPOINT is empty on the cluster — offsite "
                         "backup is not configured here, which is a decision, "
                         "not a defect this cell can judge"), NEED_HUMAN
    if not ep.startswith("https://"):
        return FAIL, (f"BACKUP_R2_ENDPOINT on the cluster is {ep[:60]!r} — not "
                      f"https://. A LAN address answers 200 from inside the "
                      f"building and nothing from anywhere else"), None
    host = ep.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    control, cerr = _doh_a("cloudflare.com")
    if cerr or not control:
        return UNKNOWN, (f"the positive control (cloudflare.com) did not resolve "
                         f"over DoH{': ' + cerr if cerr else ''} — this box "
                         f"cannot ask a public resolver, so a non-answer for "
                         f"{host} would mean nothing"), NEED_TOOL
    addrs, aerr = _doh_a(host)
    if aerr:
        return UNKNOWN, f"DoH query for {host} failed: {aerr}", NEED_TOOL
    if not addrs:
        return FAIL, (f"{host} does not resolve from a public resolver, while "
                      f"the control does — this endpoint only exists inside "
                      f"the building"), None
    private = [a for a in addrs if not _is_public_v4(a)]
    if private:
        return FAIL, (f"{host} resolves to {', '.join(private)} — a private "
                      f"address, so the offsite copy never leaves the site"), None
    return PASS, f"{host} (read off the cluster) resolves publicly", None

def _curl_status(url: str, resolve: str | None = None,
                 timeout: int = 15) -> tuple[int | None, str | None]:
    """(status, error) for one GET, optionally pinning the address.

    Separate from _curl_headers because cell 9 needs --resolve and cell 9 only;
    same subprocess shape, so the two agree about what "reachable" means.
    """
    if not shutil.which("curl"):
        return None, "curl is not on PATH"
    cmd = ["curl", "-sS", "-o", os.devnull, "-w", "%{http_code}",
           "-m", str(timeout)]
    if resolve:
        cmd += ["--resolve", resolve]
    cmd.append(url)
    r = run(cmd)
    if r.returncode != 0:
        return None, (r.stderr.strip()[:140] or f"curl exited {r.returncode}")
    try:
        return int(r.stdout.strip()[-3:]), None
    except ValueError:
        return None, f"curl printed {r.stdout.strip()[:40]!r}, not a status"


def cell_echo_int_from_lan(args) -> tuple[int, str, str | None]:
    """9. echo-int answers from a LAN client, by name AND by pinned address.

    Two requests, because they fail for different reasons and only both
    together say the handover path works:

      by name        exercises the LAN's resolver -> internal gateway
      with --resolve skips the resolver entirely and speaks to the gateway

    Same 200 from both: DNS and ingress are each fine. Only the pinned one
    works: the gateway is fine and the name does not reach it. Only the named
    one works: the name resolves to something that is NOT the address handed
    over -- which looks healthiest of all and is the one worth catching.

    This is the only cell that must run from the customer's LAN. Off it, the
    honest answer is 2 with a vantage note; a run from the office that reports
    anything else about this cell is reporting about the office.
    """
    host = f"echo-int.{args.domain}"
    if not args.expect_addr:
        return UNKNOWN, (f"--expect-addr not given: without the address this "
                         f"cluster hands over, the second request has nothing "
                         f"to pin to and the first cannot be judged"), NEED_TOOL

    by_name, e1 = _curl_status(f"https://{host}/")
    pinned, e2 = _curl_status(f"https://{host}/",
                              resolve=f"{host}:443:{args.expect_addr}")

    if e1 and e2:
        return UNKNOWN, (f"neither request reached {host} ({e1}) — if this is "
                         f"not the customer's LAN, that is the expected answer "
                         f"and not a finding"), NEED_PLACE
    if by_name == 200 and pinned == 200:
        return PASS, (f"{host} answers 200 by name and pinned to "
                      f"{args.expect_addr}: the LAN's resolver and the internal "
                      f"gateway are both on the handover path"), None
    if pinned == 200 and by_name != 200:
        return FAIL, (f"{host} answers 200 pinned to {args.expect_addr} but "
                      f"{by_name or e1} by name — the internal gateway is fine "
                      f"and the LAN does not resolve the name to it"), None
    if by_name == 200 and pinned != 200:
        return FAIL, (f"{host} answers 200 by name but {pinned or e2} when "
                      f"pinned to {args.expect_addr} — the name resolves to "
                      f"something that is NOT the address being handed over. "
                      f"This is the shape that looks healthiest from a browser "
                      f"and is wrong at handover"), None
    return FAIL, (f"{host} answered {by_name or e1} by name and "
                  f"{pinned or e2} pinned — neither path serves it"), None


def _omni_json(args, kind: str, capture: str | None,
               *cmd: str) -> tuple[object | None, str | None, str | None]:
    """Read one Omni resource, from a capture if one is given.

    A capture is a first-class input here, the way `gateway --routes-json`
    already treats one: the person who can reach Omni is often not the person
    reviewing the check, and requiring both in one place means the check is
    never run at all.
    """
    if capture:
        p = pathlib.Path(capture)
        if not p.is_file():
            return None, f"{capture} is not here", NEED_TOOL
        try:
            return json.loads(p.read_text()), None, None
        except json.JSONDecodeError as e:
            return None, f"{capture} did not decode as JSON: {e}", None
    if not shutil.which("omnictl"):
        return None, (f"no --{kind} capture and omnictl is not on PATH — this "
                      f"box cannot ask Omni"), NEED_TOOL
    r, terr = _run_bounded(["omnictl", *cmd], OMNI_TIMEOUT, "omnictl " + cmd[0])
    if r is None:
        return None, terr, NEED_PLACE
    if r.returncode != 0:
        return None, (f"omnictl could not read it: "
                      f"{r.stderr.strip()[:140]}"), NEED_PLACE
    try:
        return json.loads(r.stdout or "null"), None, None
    except json.JSONDecodeError as e:
        return None, f"omnictl output did not decode as JSON: {e}", None


# How long an Omni call may block before this reports "could not measure".
#
# There was no bound at all until jgct#114: `omnictl jointoken list` against an
# unreachable endpoint blocked forever, so `ci-checks.py --run` stopped at
# check-handover-cells.py and the wrapper's exit code still looked like a
# completed run. CI never saw it because the runner has no omnictl, and a
# machine that HAS the tool is exactly the machine someone runs this on.
OMNI_TIMEOUT = 20


def _run_bounded(cmd: list[str], timeout: int, what: str):
    """(CompletedProcess, None) or (None, reason). Never blocks past `timeout`.

    A delivery check that waits forever is not a slow check, it is a check
    nobody can finish -- and the suite it sits in stops with it.
    """
    try:
        return run(cmd, timeout=timeout), None
    except subprocess.TimeoutExpired:
        return None, (f"{what} did not answer within {timeout}s — the endpoint "
                      f"is unreachable from here, which is a vantage problem "
                      f"and not an answer about this cluster")
    except FileNotFoundError:
        return None, f"{cmd[0]} is not on PATH"


def _join_token_usecounts(args) -> tuple[dict | None, str | None]:
    """{token name: usecount} from `omnictl jointoken list`, or a capture.

    Read for context only. NEVER a pass condition -- see
    cell_arrived_on_own_identity for why the runbook's original assertion about
    this number does not hold.

    `jointoken` is not a COSI resource, which is why `omnictl get <kind>` has
    no name for it and why grepping the runbook for one found nothing.
    """
    text = None
    if args.join_token_list:
        p = pathlib.Path(args.join_token_list)
        if not p.is_file():
            return None, f"{args.join_token_list} is not here"
        text = p.read_text()
    elif shutil.which("omnictl"):
        r, terr = _run_bounded(["omnictl", "jointoken", "list"], OMNI_TIMEOUT,
                               "omnictl jointoken list")
        if r is None:
            return None, terr
        if r.returncode != 0:
            return None, f"omnictl jointoken list failed: {r.stderr.strip()[:120]}"
        text = r.stdout
    else:
        return None, "no --join-token-list capture and omnictl is not on PATH"

    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None, "the join token listing was empty"
    header = lines[0].split()
    try:
        col = next(i for i, h in enumerate(header) if "USE" in h.upper())
    except StopIteration:
        return None, (f"no USE* column in the listing header ({' '.join(header)[:60]}) "
                      f"— the output shape changed")
    # Key on the NAME column, not on field 0. Field 0 is the ID in
    # omnictl v1.8.1's listing, and keying on it made every count look like it
    # belonged to a token nobody names in Step -1 -- caught by this file's own
    # "usecount must not change the verdict" case, which compares names.
    name_col = next((i for i, h in enumerate(header) if h.upper() == "NAME"), 0)
    out = {}
    for ln in lines[1:]:
        f = ln.split()
        if len(f) > max(col, name_col) and f[col].isdigit():
            out[f[name_col]] = int(f[col])
    return (out, None) if out else (None, "no rows parsed out of the listing")


def cell_arrived_on_own_identity(args) -> tuple[int, str, str | None]:
    """1. The machine came back as itself, not as a new registration.

    The runbook called an unchanged join-token `usecount` "the row that
    matters". **It does not carry that weight**, and the measurement that
    refutes it was already in fleet-ops
    (`openspec/changes/zero-it-onboarding/5.2-shipping-shape-run.md`,
    2026-09-03): a real maintenance-mode re-registration, a machine returning
    on a different token, and all three tokens' usecounts unmoved (0/2/2). So
    "unchanged" looks the same whether the disk came back carrying what was
    shipped or came back as somebody else -- the two things this cell exists to
    tell apart. In the same run a REVOKED token's usecount stayed 1 and the
    machine still came back: what authorised it was the unique token.

    So the assertion is the node unique token being PERSISTENT, and usecount is
    read for context and printed. A jump is worth chasing; unchanged proves
    nothing and must not be able to turn this cell green -- gating on it would
    make this cell pass in exactly the situation it is meant to catch.

    PERSISTENT is what makes a shipped machine independent of the join token;
    it is granted because Talos is installed, not because it is in a cluster.
    (Command, verified offline against omnictl v1.8.1: `omnictl jointoken list`
    -- `jointoken` is not a COSI resource, which is why `omnictl get <kind>`
    has no name for it. Found by FO-runbook [5fe39a]; the refutation is theirs
    too.)
    """
    if not args.machine_uuid and not args.node_token_json:
        return UNKNOWN, ("--machine-uuid (or --node-token-json capture) not "
                         "given: nothing to ask about"), NEED_TOOL
    data, err, kind = _omni_json(
        args, "node-token-json", args.node_token_json,
        "get", "nodeuniquetokenstatus", args.machine_uuid or "", "-o", "json")
    if data is None:
        return UNKNOWN, err, kind or NEED_TOOL

    spec = data.get("spec") if isinstance(data, dict) else None
    state = (spec or {}).get("state") if isinstance(spec, dict) else None
    if state is None and isinstance(data, dict):
        state = data.get("state")
    if state is None:
        return UNKNOWN, ("could not find a `state` in the nodeuniquetokenstatus "
                         "output — the shape changed, and a missing field is "
                         "not the same as a non-PERSISTENT token"), NEED_TOOL
    if state != 1:
        return FAIL, (f"node unique token state is {state!r}, not 1 "
                      f"(PERSISTENT) — this machine still depends on the join "
                      f"token, so it did not arrive on its own identity"), None
    counts, cerr = _join_token_usecounts(args)
    if counts is None:
        ctx = f"join token usecounts not read here ({cerr})"
    else:
        ctx = "join token usecounts: " + ", ".join(
            f"{k}={v}" for k, v in sorted(counts.items()))
        if args.expect_usecounts:
            want = dict(kv.split("=", 1) for kv in args.expect_usecounts.split(",")
                        if "=" in kv)
            moved = [f"{k} {want[k]}->{counts[k]}" for k in want
                     if k in counts and str(counts[k]) != want[k]]
            ctx += ("; MOVED since Step -1: " + ", ".join(moved) + " — chase it"
                    if moved else "; unchanged since Step -1")
    return UNKNOWN, (
        f"node unique token is PERSISTENT (state 1) — that is the assertion, "
        f"and it holds. {ctx}. Context only: an unchanged usecount does NOT "
        f"prove the machine arrived on its own identity (measured 2026-09-03, "
        f"fleet-ops zero-it-onboarding 5.2), so nothing here gates on it. "
        f"Whether this machine is the one that was shipped is still a person's "
        f"call"), NEED_HUMAN


def _not_implemented(cell: int, needs: str):
    """A cell nobody has written yet, which is NOT the same as one that cannot
    reach its subject from here. The phase number deliberately does not appear:
    it was "phase 2" for both of these until the phases were re-cut, and a
    label that was true when written is the exact shape this file keeps
    finding elsewhere (FO-runbook [5fe39a], twice)."""
    def f(args) -> tuple[int, str, str | None]:
        return UNKNOWN, (f"needs {needs}. Reported as 2 rather than omitted: a "
                         f"table missing rows reads like a table that passed"), NOT_YET
    f.__name__ = f"cell_{cell}_not_implemented"
    return f


# (cell number in Step 5's thirteen, one-line title, function)
#
# Cell 13 is phase 2 on FO-runbook's correction, and the reason is worth
# keeping: its assertion is "read the endpoint back OFF THE CLUSTER, not off
# the file you think you edited". Implemented against cluster.yaml it would
# pass in exactly the situation it exists to catch -- edited locally, never
# applied. The half that resolves the name from outside is vantage-independent
# and comes with it.
HANDOVER_CELLS = [
    (1, "arrived on its own identity: node token PERSISTENT", cell_arrived_on_own_identity),
    (2, "tunnel AccountTag == the zone's account", cell_tunnel_account),
    (3, "factory auth0.json present and complete", cell_factory_auth0),
    (4, "im redirects to the factory tenant's /authorize", cell_im_front_door),
    (5, "private repo: visibility, FluxInstance sync, deploy key", cell_private_repo),
    (6, "NODE_DNS_PATH=lan and the resolver answers both questions", cell_node_dns_path),
    (7, "daily-check printed check 18's row, and it measured something", cell_daily_check_ran),
    (8, "echo-ext answers 200 through Cloudflare (cf-ray)", cell_echo_ext),
    (9, "echo-int answers from the LAN, by name and pinned", cell_echo_int_from_lan),
    (10, "daily_check_* is configured", cell_daily_check_configured),
    (11, "the dead-man switch has a ping URL", cell_dead_man_switch),
    (12, "health-check recipients read back from a real run", cell_recipients_readback),
    (13, "backup_r2_endpoint read back off the cluster", cell_r2_endpoint),
]


def check_handover(args) -> int:
    results = []
    for num, title, fn in HANDOVER_CELLS:
        try:
            rc, note, why = fn(args)
        except Exception as e:  # noqa: BLE001
            rc, note, why = UNKNOWN, f"the check itself raised {type(e).__name__}: {e}", NEED_TOOL
        results.append((num, title, rc, note, why))

    order = (NEED_PLACE, NEED_TOOL, NEED_HUMAN, NOT_YET, PAUSED)

    def kinds_of(why) -> list[str]:
        """None / one kind / several. A cell blocked on more than one thing
        belongs in every list, or the list it is missing from is the one
        somebody is working through."""
        if not why:
            return []
        one = {why} if isinstance(why, str) else set(why)
        return [k for k in order if k in one]

    mark = {PASS: "PASS ", FAIL: "FAIL ", UNKNOWN: "?    "}
    for num, title, rc, note, why in results:
        # A kind on a PASS is shown too. Cell 12 passes its machine half and
        # still leaves a person's half open ("are these the people who would
        # act"), and hiding that behind a bare PASS is the same move as folding
        # "cannot measure" into "passed" -- one row later. It stays PASS,
        # because the half a machine can do was done.
        ks = kinds_of(why) if rc in (UNKNOWN, PASS) else []
        suffix = f"   [{'+'.join(ks)}]" if ks else ""
        print(f"{mark[rc]} {num:>2}. {title}{suffix}")
        print(f"          {note}")

    fails = [n for n, _, rc, _, _ in results if rc == FAIL]
    unknown = [(n, kinds_of(why)) for n, _, rc, _, why in results if rc == UNKNOWN]
    passed_human = [n for n, _, rc, _, why in results
                    if rc == PASS and NEED_HUMAN in kinds_of(why)]
    print()
    print(f"{len(results) - len(fails) - len(unknown)}/{len(results)} cells pass.")

    if unknown:
        word = "cell" if len(unknown) == 1 else "cells"
        print(f"{len(unknown)} {word} could not be answered here. That is not a pass,")
        print("and the next action differs by kind:")
        for kind in order:
            cells = [str(n) for n, ks in unknown if kind in ks]
            if cells:
                print(f"      {WHY_TEXT[kind]}")
                print(f"          cells {', '.join(cells)}")
        print("      No single run of this is authoritative. What Step 5 needs is")
        print("      one PASS per cell from somewhere that could measure it.")

    if passed_human:
        print(f"{', '.join(str(n) for n in passed_human)}: passed the half a "
              f"machine can do, and still needs a person for the other half.")

    if fails:
        word = "cell" if len(fails) == 1 else "cells"
        print(f"{len(fails)} {word} FAILED: {', '.join(str(n) for n in fails)}")
        return FAIL
    return UNKNOWN if unknown else PASS


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("escrow")
    e.add_argument("--escrowed-key", required=True)
    e.add_argument("--sops-yaml", default=".sops.yaml")
    e.set_defaults(func=check_escrow)

    h = sub.add_parser("repo-hygiene")
    h.add_argument("--dir", default=".")
    h.add_argument("--deep", action="store_true", help="scan every blob's content")
    h.set_defaults(func=check_repo_hygiene)

    d = sub.add_parser("dns")
    d.add_argument("--domain", required=True)
    d.add_argument("--token-env", default="CLOUDFLARE_TOKEN")
    d.add_argument("--tunnel-credentials", default="cloudflare-tunnel.json")
    d.set_defaults(func=check_dns)

    f = sub.add_parser("flux")
    f.add_argument("--kubeconfig", required=True)
    f.add_argument("--expect-sha", required=True)
    f.set_defaults(func=check_flux)

    l = sub.add_parser("lan")
    l.add_argument("--domain", required=True)
    l.add_argument("--expect-addr", required=True)
    l.set_defaults(func=check_lan)

    g = sub.add_parser("gateway")
    g.add_argument("--node", help="node address talosctl should ask")
    g.add_argument("--talosconfig")
    g.add_argument("--routes-json",
                   help="a captured `talosctl get routes -o json`, instead of asking a node")
    g.add_argument("--timeout", type=int, default=30)
    g.set_defaults(func=check_gateway)

    k = sub.add_parser("deploy-key")
    k.add_argument("--repo", required=True, help="OWNER/NAME on GitHub")
    k.add_argument("--pubkey", default="github-deploy.key.pub")
    k.set_defaults(func=check_deploy_key)

    hv = sub.add_parser("handover")
    hv.add_argument("--domain", required=True)
    hv.add_argument("--dir", default=".", help="the cluster repo directory")
    hv.add_argument("--instance", default="im", help="the base terminal's name")
    hv.add_argument("--repo", help="OWNER/NAME of the per-user repo")
    hv.add_argument("--pubkey", default="github-deploy.key.pub")
    hv.add_argument("--kubeconfig", help="reaches cells that need the cluster")
    hv.add_argument("--token-env", default="CLOUDFLARE_TOKEN")
    hv.add_argument("--tunnel-credentials", default="cloudflare-tunnel.json")
    hv.add_argument("--auth0-json", default="auth0.json")
    hv.add_argument("--resolver", help="the candidate LAN resolver cell 6 should ask")
    hv.add_argument("--trigger", action="store_true",
                    help="cell 7 only: WRITE a Job when nothing has run yet")
    hv.add_argument("--expect-addr", help="cell 9: the internal address handed over")
    hv.add_argument("--machine-uuid", help="cell 1: the machine Omni knows")
    hv.add_argument("--join-token-list",
                    help="cell 1: a captured `omnictl jointoken list`; read for "
                         "context, never a pass condition")
    hv.add_argument("--expect-usecounts",
                    help="cell 1: NAME=N,NAME=N from Step -1; a move is printed "
                         "to chase, not failed on")
    hv.add_argument("--node-token-json",
                    help="cell 1: a captured `omnictl get nodeuniquetokenstatus"
                         " <uuid> -o json`, instead of asking Omni here")
    hv.set_defaults(func=check_handover)

    t = sub.add_parser("tunnel-cert")
    t.add_argument("--domain", required=True)
    t.add_argument("--cert", default="~/.cloudflared/cert.pem")
    t.add_argument("--token-env", default="CLOUDFLARE_TOKEN")
    t.set_defaults(func=check_tunnel_cert)

    args = p.parse_args()
    if args.cmd == "gateway" and not args.node and not args.routes_json:
        p.error("gateway needs --node, or --routes-json to read a capture")
    # A command that never returned is the third outcome, not a failure of the
    # thing being checked. Without this, RUN_TIMEOUT would turn "the API server
    # never answered" into whichever finding that call site reports for a
    # non-zero exit — and being told the wrong thing confidently costs more than
    # being told nothing (#117, and #114 before it).
    try:
        sys.exit(args.func(args))
    except subprocess.TimeoutExpired as e:
        name = e.cmd[0] if isinstance(e.cmd, (list, tuple)) else e.cmd
        huh(f"{name} did not finish within {e.timeout:g}s — this run could not "
            f"measure that, which is not the same as a finding")
        print("      Re-run from somewhere that can reach it, or pass a longer")
        print("      --timeout where the command legitimately takes that long.")
        sys.exit(UNKNOWN)


if __name__ == "__main__":
    main()
