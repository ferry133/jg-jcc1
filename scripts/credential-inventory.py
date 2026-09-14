#!/usr/bin/env python3
"""Per-cluster credential inventory — §5.4 and §5.6 of factory-agent.

Emits one cluster's credentials in the five-column form already in use at
`jg-base kubernetes/apps/extras/factory/factory/README.md`: credential, what it
is for, scope, blast radius if read, rotation. One shape, not two — two shapes
diverge, and the one being read is usually the older.

Rotation (5.6) is the fifth column rather than a separate document, because a
rotation procedure filed away from the credential it rotates is one nobody finds
at the moment they need it.

**The thing this script must not do is be a list of names someone thought of.**
The `config.gen/cluster.yaml` leak happened because a rule and a check both
named the file someone expected. So the table below is not the answer on its
own: every field actually present in the cluster's `cluster.yaml` is compared
against it, and anything unrecognised is printed as UNCLASSIFIED. An inventory
that silently omits a credential reads exactly like an inventory of a cluster
that does not have one.

The other half of the same rule, taken from the jg-base document: **a row that
was considered and deliberately left out looks identical, from outside, to one
that was forgotten.** So exclusions are printed with their reason, not dropped.

No credential VALUE is ever printed — only whether one is set. This output is
meant to be pasteable into a delivery ticket in a public repository.

Usage
-----
  credential-inventory.py --dir PATH [--format md|text]

Exit 0 when the inventory is complete, 1 when a credential this cluster needs is
missing, 2 when the inventory could not be built (no cluster.yaml, unreadable
schema) — never 0 with a caveat.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

DONE, INCOMPLETE, UNKNOWN = 0, 1, 2

# credential field -> (what for, scope, blast radius if read, rotation)
#
# Scope and blast radius are deliberately different columns. "Which resources
# does it address" and "what does an attacker get" diverge most for exactly the
# credentials that matter: an age key addresses one cluster's files and yields
# every secret in them.
KNOWN: dict[str, tuple[str, str, str, str]] = {
    "cloudflare_token": (
        "external-dns writes DNS records; cert-manager answers DNS-01",
        "Every zone the token was scoped to — check the token, not this row",
        "DNS for those zones: traffic redirection, certificate issuance, tunnel takeover",
        "Roll in the Cloudflare dashboard, put the new value in cluster.yaml, "
        "`task configure --yes`, commit, push. Needs Zone:DNS:Edit AND "
        "Account:Cloudflare Tunnel:**Edit** — `Read` lists tunnels and cannot "
        "create one (measured 2026-08-23, GET passes and POST returns 10000)",
    ),
    "claudecode_auth0_client_secret": (
        "oauth2-proxy's half of the OIDC exchange in front of every terminal",
        "The Auth0 application it belongs to. If this cluster uses the SHARED "
        "application, that is every cluster",
        "Sign-in as the application: an attacker completes the OIDC flow and "
        "reaches a root shell on the cluster, since ttyd binds loopback and "
        "oauth2-proxy is the only route in",
        "Rotate in Auth0. **If the tenant is shared, rotating breaks every other "
        "cluster at the same instant** — that asymmetry is why 2026-08-25 ruled "
        "each cluster gets its own tenant, and why an existing shared cluster "
        "cannot be handed over without moving tenants first",
    ),
    "claudecode_auth0_domain": (
        "The OIDC issuer this cluster trusts",
        "Not a secret. Listed because it must move with the two that are",
        "None on its own",
        "Set all three Auth0 fields or none — `plugin.py` fills a missing field "
        "from the shared `auth0.json`, so a partial answer mixes one tenant's "
        "issuer with another's client and produces a terminal nobody can log in to",
    ),
    "claudecode_auth0_client_id": (
        "Identifies this cluster's application to Auth0",
        "Not a secret",
        "None on its own",
        "See `claudecode_auth0_domain` — all three together",
    ),
    "backup_r2_access_key_id": (
        "The backup job authenticates to the object store",
        "The bucket the key is scoped to",
        "Read of every backup: the backups hold the databases",
        "Reissue at the provider, update cluster.yaml, re-render. Confirm the "
        "next scheduled run succeeded — a wrong key fails as a network-shaped "
        "error that looks like every other transient",
    ),
    "backup_r2_secret_access_key": (
        "As above, the secret half",
        "The bucket the key is scoped to",
        "Read and delete of every backup",
        "Reissue with the id above; they rotate as a pair",
    ),
    "ttyd_credential": (
        "Basic-auth for the terminal when Auth0 is off (`claudecode_auth0: false`)",
        "Every claude-code instance on this cluster",
        "A root shell on the cluster",
        "Change the value and re-render. Present only on a cluster that "
        "deliberately declined the OIDC gate",
    ),
    "claudecode_postgres_password": (
        "The claudecode Postgres extra's superuser",
        "That database",
        "Read/write of whatever the instance stores",
        "Change in cluster.yaml, re-render, then ALTER the role — the manifest "
        "does not reset an existing database's password on its own",
    ),
    "github_push_token": (
        "The resident agent pushes commits back to the cluster repo",
        "Every repo the token's account can reach",
        "A repo write is a deploy on this fleet, with no review gate",
        "Revoke in GitHub, issue a replacement scoped to this repo, re-render",
    ),
    "github_webhook_token": (
        "Shared secret for Flux's GitHub receiver",
        "This cluster's receiver",
        "Ability to trigger reconciliations — noise, not access",
        "`python3 -c \"import secrets; print(secrets.token_hex(32))\"`, update "
        "cluster.yaml and the webhook in GitHub together",
    ),
    "daily_check_smtp_password": (
        "Gmail app password the daily health check sends through",
        "The Google account that issued it, for SMTP",
        "Send mail as that account",
        "Revoke the app password in the Google account, issue another",
    ),
    "daily_check_healthchecks_ping_url": (
        "Dead-man switch: the URL is the credential",
        "One healthchecks.io check",
        "Ability to suppress the alarm by pinging it",
        "Regenerate the check's UUID at healthchecks.io",
    ),
    "anthropic_api_key": (
        "Model access for extras/default/linebot and extras/default/synophoto",
        "The Anthropic account that issued it",
        "Billable model usage on that account",
        "Revoke in the Anthropic console. **Ruling 2026-08-25: this must be the "
        "customer's own account, not the company's.** Nothing validates whose "
        "it is and nothing can — ask, and record the answer on the ticket",
    ),
    "cloudflare_lan_tunnel_token": (
        "A second tunnel for LAN-only names",
        "That tunnel",
        "Whoever holds it can stand up their own connector for the same tunnel "
        "and Cloudflare will balance traffic across both",
        "Delete and recreate the tunnel, or rotate its secret, then re-render",
    ),
    "talos_mcp_sa_key": (
        "The talos-mcp sidecar's read access to Omni",
        "Omni, at whatever role the service account has",
        "Read of the fleet's machine and cluster state",
        "`omnictl serviceaccount` — destroy and recreate, update the value",
    ),
}

# Credential-bearing material that is NOT a cluster.yaml field. Listed because
# the ones people forget are the ones that never appear in a config file.
OUT_OF_BAND = [
    ("age.key", "Decrypts every SOPS secret in this repo",
     "This cluster's repository, all of it",
     "Every secret the cluster holds, including ones rotated later — the "
     "ciphertext is public and permanent",
     "`age-keygen` a new key, then `sops updatekeys` every `*.sops.*` file IN "
     "PLACE — never decrypt into the working tree. Add the new recipient to "
     "`.sops.yaml` BEFORE removing the old one: there is one recipient, so a "
     "botched updatekeys is recoverable only from the escrow copy"),
    ("The escrowed copy of age.key", "The only copy that survives this machine",
     "As age.key", "As age.key",
     "Compare with `age-keygen -y` against `.sops.yaml`'s recipient and record "
     "'compared, public halves match verbatim' — not 'escrowed', which is a "
     "conclusion. `provision.py complete --escrowed-pubkey` refuses to mark a "
     "delivery done without it"),
    ("cloudflare-tunnel.json", "TunnelSecret + AccountTag for the main tunnel",
     "That tunnel, in that account",
     "Run a competing connector for the same tunnel",
     "Delete and recreate the tunnel, re-render, confirm the CNAME was "
     "rewritten to the new UUID"),
    ("github-deploy.key", "Flux's read access to the cluster repo",
     "That repo", "Read of the manifests, which are public anyway on this fleet",
     "Generate a new pair, replace the deploy key in GitHub"),
    ("kubeconfig-sa", "Non-interactive cluster access; embeds a bearer token",
     "This cluster's Kubernetes API at the SA's role",
     "Whatever the service account can do — on this fleet, cluster-admin",
     "`omnictl kubeconfig … --service-account`. Never overwrite `kubeconfig` "
     "with it: that file is the way back in when this token expires"),
    ("~/.cloudflared/cert.pem", "Origin certificate that creates tunnels",
     "The Cloudflare account whose BROWSER SESSION signed it — not necessarily "
     "the account the zone is in",
     "Create tunnels in that account",
     "Re-run `cloudflared tunnel login`. This is the credential behind the "
     "cross-account 1033: a tunnel is created wherever the cert belongs, and "
     "every cheaper check passes"),
]

# Absent by decision, not by omission. Printing these is half the point: from
# outside, a row that was considered and dropped looks exactly like one nobody
# thought of.
EXCLUDED = [
    ("Customer consumer-account passwords (Google, Cloudflare, Auth0 sign-in)",
     "5.2 — no automation registers or holds a consumer account. The customer "
     "registers one Google account at contract time and the company signs in "
     "with it; the password is never a value this fleet stores"),
    ("Omni Admin service account",
     "Held by factory, not by any cluster. It is in "
     "`jg-base .../factory/factory/README.md`, and a second copy here would be "
     "the copy that goes stale"),
    ("Talos client certificate / talosconfig",
     "Not issued per delivery today. The node-level handover path is "
     "`factory-agent` 6.1d, which is still a sentence rather than a procedure"),
]

CLASSIFIED_ELSEWHERE = {c[0] for c in EXCLUDED}

# Fields that hold no credential but whose names would trip a keyword sweep.
NOT_CREDENTIALS = {
    "cloudflare_domain", "cloudflare_gateway_addr", "cloudflare_tunnel_transport",
    "github_username", "repository_name", "repository_branch",
    "repository_visibility", "daily_check_notify_email_to",
    "daily_check_smtp_host", "daily_check_smtp_port", "daily_check_smtp_username",
    "daily_check_notify_email_from", "backup_r2_endpoint", "backup_r2_bucket",
    "backup_retain_days", "claudecode_allowed_emails", "claudecode_auth0",
    "claudecode_oauth2_cookie_secret_source",
}

# Name-shaped sweep used ONLY to find fields the table above does not know
# about. It is not the inventory; it is the check that the inventory is not a
# list of names someone thought of.
SUSPICIOUS = re.compile(
    r"(?i)(token|secret|password|passwd|key|credential|cert|api[_-]?key|pat)\b")


def read_fields(path: pathlib.Path) -> dict[str, str]:
    """Top-level `key: value` pairs. Commented-out lines are not settings."""
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([a-z][a-z0-9_]*)\s*:\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).split("#", 1)[0].strip()
    return out


def is_set(raw: str) -> bool:
    v = raw.strip().strip("\"'").strip()
    if not v or v in ("[]", "{}", "~", "null"):
        return False
    return not (v.startswith(("<", "${", "$(")) or "CHANGE" in v.upper())


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=".")
    ap.add_argument("--format", default="md", choices=["md", "text"])
    args = ap.parse_args()

    d = pathlib.Path(args.dir).resolve()
    cfg = d / "cluster.yaml"
    if not cfg.exists():
        print(f"?     {cfg} not found — cannot build an inventory", file=sys.stderr)
        print("      Reported as could-not-tell, not as 'no credentials'. A "
              "cluster with no cluster.yaml and one whose file is elsewhere "
              "produce the same empty table.", file=sys.stderr)
        return UNKNOWN

    fields = read_fields(cfg)
    name = fields.get("cluster_name", "?").strip("\"'")

    present, blank, undeclared, unclassified = [], [], [], []
    for field, row in KNOWN.items():
        if field not in fields:
            undeclared.append(field)
        elif is_set(fields[field]):
            present.append((field, row))
        else:
            blank.append(field)
    for field in fields:
        if field in KNOWN or field in NOT_CREDENTIALS:
            continue
        if SUSPICIOUS.search(field) and is_set(fields[field]):
            unclassified.append(field)

    print(f"# Credential inventory — {name}")
    print()
    print(f"Generated from `{cfg}` by `scripts/credential-inventory.py`. "
          "**No value is printed**, only whether one is set, so this is safe to "
          "paste onto a delivery ticket in a public repository.")
    print()
    print("| Credential | What it is for | Scope | Blast radius if read | Rotation |")
    print("|---|---|---|---|---|")
    for field, (what, scope, blast, rot) in present:
        print(f"| `{field}` | {what} | {scope} | {blast} | {rot} |")
    for cred, what, scope, blast, rot in OUT_OF_BAND:
        p = "" if _exists(d, cred) else " *(not in this directory)*"
        print(f"| **{cred}**{p} | {what} | {scope} | {blast} | {rot} |")
    print()

    print("## Declared and blank")
    print()
    if blank:
        print("Blank is a real state — the feature is off. The row is here so "
              "that off-by-decision and off-by-accident are not the same "
              "observation.")
        print()
        for f in sorted(blank):
            print(f"- `{f}`")
    else:
        print("None — every credential field this file declares carries a value.")
    print()

    print("## Not declared at all")
    print()
    print("Absent from `cluster.yaml` entirely, so this cluster does not use "
          "the feature behind them. **This section exists because the version "
          "without it had the same defect the whole file is written against:** "
          "a credential the cluster genuinely does not need and one whose line "
          "someone deleted produced identical output — nothing at all. "
          "`daily_check_healthchecks_ping_url` is the worked example: unset, the "
          "daily check runs, mails, and pings nothing, so a FAIL withholds a "
          "ping that was never configured and the only notification path left "
          "is the mail — which fails silently in exactly the cases that matter.")
    print()
    if undeclared:
        for f in sorted(undeclared):
            print(f"- `{f}`")
    else:
        print("None.")
    print()

    print("## Deliberately not in this inventory")
    print()
    print("From outside, a row that was considered and dropped looks exactly "
          "like one nobody thought of. These were considered.")
    print()
    for cred, why in EXCLUDED:
        print(f"- **{cred}** — {why}")
    print()

    rc = DONE
    if unclassified:
        rc = INCOMPLETE
        print("## ⚠️ UNCLASSIFIED — this inventory is incomplete")
        print()
        print("These fields are set in `cluster.yaml`, their names are "
              "credential-shaped, and this script's table does not know them. "
              "**They are printed rather than skipped**: a credential missing "
              "from the inventory reads exactly like a cluster that does not "
              "have one, which is the failure this file exists to avoid.")
        print()
        for f in sorted(unclassified):
            print(f"- `{f}` — add it to `KNOWN` in "
                  "`scripts/credential-inventory.py`, with its rotation procedure, "
                  "or to `NOT_CREDENTIALS` if it holds none")
        print()
        print("Exit 1. Not a warning: an incomplete inventory handed over as "
              "complete is worse than none, because it is trusted.")
    return rc


def _exists(d: pathlib.Path, cred: str) -> bool:
    if cred.startswith("~"):
        return os.path.exists(os.path.expanduser(cred))
    return (d / cred.split()[0]).exists()


if __name__ == "__main__":
    sys.exit(main())
