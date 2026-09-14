# jg-cluster-template

GitHub template for a Kubernetes cluster managed by ferry133. Click
**"Use this template"** to generate a per-user repo.

## Which document do you need?

| You are | Read |
|---------|------|
| A customer who received the hardware | **[`README-zero-IT.md`](README-zero-IT.md)**（繁體中文）— three physical actions, nothing else |
| Working out what a given cluster needs at each phase | **`fleet-ops docs/deploy/combinations.md`**（繁體中文）— which combination this is, and what preparation / installation / operation each dimension adds |
| Provisioning a cluster yourself, by hand | **`fleet-ops docs/deploy/manual.md`** — full step-by-step, both provisioning paths |
| Delivering an appliance to a customer | The operator runbook (see `ferry133/fleet-ops` → `openspec/changes/factory-agent`, private) |
| Changing how the template works | [`CLAUDE.md`](CLAUDE.md) — architecture, conventions, and the rules that are not obvious from the code |

This page routes; it deliberately contains no deployment steps, so there is only
one place each procedure is written down.

> **`docs/` is not in this repo.** It moved to `ferry133/fleet-ops` (private) on
> 2026-08-22, for the same reason `openspec/` did: this repo is public *and* a
> GitHub template, and a template copy takes every tracked file, so each
> customer-named repo inherited all of it.
>
> Every `fleet-ops docs/...` reference below and in `cluster.sample.yaml`,
> `templates/` and `scripts/` names a path in that repository. **They are not
> reachable from a generated cluster repo**, which is a real cost of the move
> and not an oversight — an operator without access to `fleet-ops` cannot follow
> those pointers.

## Architecture

Three repositories, none of which is useful alone:

| Repo | Role |
|------|------|
| [`ferry133/jg-base`](https://github.com/ferry133/jg-base) | Golden Kubernetes manifests, watched by every cluster via Flux |
| `ferry133/jg-cluster-template` (this repo) | CUE schema, Jinja2 templates, Taskfile — the tooling that turns `cluster.yaml` into a cluster |
| per-user repo (generated from this template) | One `cluster.yaml`, its encrypted secrets, and the Flux entry point |

## Deployment profiles

`deployment_profile` in `cluster.yaml` decides how much the person setting up
the cluster has to know. It has no default — an unmigrated config fails
validation rather than being rendered under an assumption.

| Profile | For | Customer-supplied fields |
|---------|-----|--------------------------|
| `appliance` | Operator-delivered, single node | none |
| `prosumer` | Customer has a NAS or some infrastructure | a few |
| `full` | Expert operates it directly | all of them |

`storage_backend` (`local-path` / `nfs` / `replicated`) is the second axis: it
selects what bulk media and file shares use. Databases are block-backed either
way — `replicated_storage` installs Longhorn without moving bulk onto it, which
is what a multi-node cluster with a NAS needs.

Those two are not the only axes that change what has to be done. See
`fleet-ops docs/deploy/combinations.md` for the full list,
the combinations validation rejects outright, and what each phase requires.

## Provisioning paths

| Path | Machines are found by | Node facts come from |
|------|----------------------|----------------------|
| **Omni** | SideroLink — the machine registers itself | Omni |
| **Manual Talos** | You, with `nmap` | `nodes.yaml`, filled in by hand |

`appliance` implies Omni: the manual path needs per-node IP, NIC and disk
selectors that a non-technical customer cannot supply, so the combination is
rejected at validation time.

## Common commands

```sh
task init                      # generate cluster.yaml, nodes.yaml, age.key, deploy key
task configure                 # validate → render → validate manifests → encrypt
task bootstrap:talos           # manual path only: install Talos onto the nodes
task bootstrap:apps            # install Cilium, cert-manager, Flux; hand over to GitOps
task reconcile                 # force Flux to re-sync
task template:check            # rendering-pipeline integrity (runs inside configure)
task template:validate-manifests   # kubeconform over the rendered output
```

## Planned work

Design proposals **are not in this repo.** They live in `ferry133/fleet-ops`
(private) under `openspec/`, along with the `openspec/specs/` this template is
built against.

They were moved out on 2026-08-22 for a reason that is a property of this repo
specifically: it is public *and* it is a GitHub template. Creating a repo from a
template copies every tracked file, so each customer-named public cluster repo
was inheriting 53 files of proposals, design decisions and incident write-ups
that have nothing to do with that customer. Moving the source fixes every future
copy at once.

It was a move, not a copy — there is no second version here to drift.

| Change | About |
|--------|-------|
| `deployment-profiles` | The profile and storage axes above |
| `factory-agent` | Operator-side agent that provisions a cluster end to end |
| `zero-it-onboarding` | The documentation split, and the customer-facing channel |
| `reconcile-jcom-lineage` | Bring a cluster that diverged back onto the template |
| `agent-state-portability` | Carrying an agent's accumulated state across a rebuild |

Implementation still lands here. **The design record moved; ownership of the
files did not.** A change amending this template's schema, renderer or Taskfile
is still implemented in this repo — its proposal and acceptance criteria are
just read from `fleet-ops`.
