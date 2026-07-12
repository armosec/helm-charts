---
type:    feature
status:  in-progress
owner:   ben@armosec.io
scope:   repo
---

# GKE Autopilot Allowlist Tooling & Release Drift Gate

## Overview

Running the node-agent on **GKE Autopilot** requires a Google-approved `WorkloadAllowlist` — Autopilot
blocks privileged workloads unless a matching allowlist is installed (via an `AllowlistSynchronizer`).
This repo ships two distributions, each matched against its own allowlist:

| Chart | node-agent image | Allowlist |
|-------|------------------|-----------|
| `charts/kubescape-operator` (ARMO) | `quay.io/armosec/node-agent` | `armo-private-node-agent-<minor>` |
| `charts/rapid7-operator` (Rapid7) | `quay.io/armosec/node-agent` | `armo-rapid7-node-agent-<minor>` |

This feature adds tooling to keep the charts in sync with the approved allowlists, and a **release-time
gate** that blocks shipping a chart the approved allowlist can no longer admit.

## Why a gate is needed

GKE Autopilot admission is **subset-based**: a pod is admitted only if its env vars, containers, mounts,
and capabilities are a **subset** of the matched allowlist. If a chart change adds something new to the
node-agent that the approved allowlist does not list, **customers on Autopilot can no longer install**
until a new allowlist is approved (Gerrit review + gradual rollout). The gate catches this at release
time instead of in the field.

## Components

- **`scripts/gke-allowlist/allowlist-drift.py`** — classifies a chart render vs an allowlist as
  `no-op` / `digest-only` / `spec-drift` (exit 2 on spec-drift).
- **`scripts/gke-allowlist/check-drift.sh`** — CI wrapper: renders the node-agent with all optional
  features enabled (backend server/`API_URL`, proxy, custom runtime, kernel-check skip, full malware
  scan, ClamAV, SBOM scanner, OTEL) and verifies it is a subset of the allowlist.
- **`scripts/gke-allowlist/build-allowlists.py`, `refresh-digests.py`** — allowlist-repo-side helpers.
- **`gke-allowlist/*.yaml`** — vendored copies of the approved allowlists the gate checks against.

## Release behavior

`03-helm-release.yaml` runs an `allowlist-drift-check` job (both charts) before publishing:

- **No drift** → passes, release proceeds.
- **Drift** → **fails** with the specific missing fields, blocking the release.
- **Intentional drift** → open the Gerrit allowlist update, then re-run the release with
  **`BYPASS_ALLOWLIST_DRIFT: true`** ("set as pass after you opened Gerrit to allowlist"). Also update
  the vendored `gke-allowlist/` copy and the chart's `nodeAgent.gke.allowlist.name` default once the new
  allowlist is approved.

## Run locally

```bash
scripts/gke-allowlist/check-drift.sh charts/kubescape-operator gke-allowlist/armo-private-node-agent-1.40-v2.yaml --wrapper
scripts/gke-allowlist/check-drift.sh charts/rapid7-operator   gke-allowlist/armo-rapid7-node-agent-1.40-v2.yaml  --wrapper
```

## Limitation

Covers subset-matched fields (env names, containers, capabilities, mounts, hostPath volumes, image repo).
It does not see runtime-only fields such as the per-node-group `node.kubernetes.io/instance-type`
nodeSelector the autoscaler adds (needs the `autogke-node-affinity-selector-limitation` exemption) —
validate those on a live Autopilot cluster.
