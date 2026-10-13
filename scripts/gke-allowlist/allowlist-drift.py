#!/usr/bin/env python3
"""GKE Autopilot allowlist drift detector (PoC).

Renders a chart's node-agent pod spec and checks whether its privileged surface
is still COVERED by an approved WorkloadAllowlist (subset-matching rules), so a
chart-release pipeline can classify each release without a cluster:

  no-op       - workload fully covered by the allowlist (nothing to do)
  digest-only - covered, but the running image digest isn't in containerImageDigests
                (Tier-1 action: append the digest)
  spec-drift  - workload needs a capability / env / mount / container / hostPID
                NOT present in the allowlist -> a NEW allowlist version is required
                (Tier-2 gate should block the release until one is approved)

Exit code: 0 for no-op, 2 for spec-drift / missing-digests (CI-gate friendly).

Usage:
  allowlist-drift.py --chart <path> --allowlist <yaml> [--values f.yaml ...]
                     [--set k=v ...] [--wrapper] [--check-digests]
"""
import argparse, re, shutil, subprocess, sys
import yaml


def render_node_agent(chart, values, sets, wrapper):
    prefix = "kubescape-operator." if wrapper else ""
    show = ("charts/kubescape-operator/templates/node-agent/daemonset.yaml"
            if wrapper else "templates/node-agent/daemonset.yaml")
    cmd = ["helm", "template", "na", chart, "--kube-version", "1.33.0",
           "--show-only", show,
           "--set", f"{prefix}clusterName=drift",
           "--set", f"{prefix}account=00000000-0000-0000-0000-000000000000",
           "--set", f"{prefix}nodeAgent.autoscaler.enabled=false"]
    for v in values:
        cmd += ["-f", v]
    for s in sets:
        cmd += ["--set", s]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"helm template failed:\n{out.stderr}")
    return yaml.safe_load(out.stdout)


def project_container(c):
    sc = c.get("securityContext", {}) or {}
    caps = sc.get("capabilities", {}) or {}
    return {
        "image": c.get("image", ""),
        "add": set(caps.get("add", []) or []),
        "drop": set(caps.get("drop", []) or []),
        "env": {e["name"] for e in (c.get("env", []) or [])},
        "mounts": {m["mountPath"] for m in (c.get("volumeMounts", []) or [])},
        "privileged": bool(sc.get("privileged", False)),
    }


def workload_projection(ds):
    spec = ds["spec"]["template"]["spec"]
    return {
        "hostPID": bool(spec.get("hostPID", False)),
        "containers": {c["name"]: project_container(c) for c in spec["containers"]},
        "hostpaths": {v["name"]: v["hostPath"]["path"]
                      for v in spec.get("volumes", []) if "hostPath" in v},
    }


def allowlist_projection(al):
    mc = al["matchingCriteria"]
    return {
        "hostPID": bool(mc.get("hostPID", False)),
        "containers": {c["name"]: project_container(c) for c in mc.get("containers", [])},
        "hostpaths": {v["name"]: v["hostPath"]["path"]
                      for v in mc.get("volumes", []) if "hostPath" in v},
        "digests": {d["containerName"]: set(d.get("imageDigests", []))
                    for d in al.get("containerImageDigests", [])},
    }


def repo(image):
    return re.split(r"[:@]", image, maxsplit=1)[0]


def resolve_digest(image):
    if shutil.which("skopeo") is None:
        return None
    out = subprocess.run(["skopeo", "inspect", f"docker://{image}"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    import json
    return json.loads(out.stdout).get("Digest", "").replace("sha256:", "")


def extract_allowlist_tags(allowlist_path):
    """Parse comments under containerImageDigests to find known image tags per container.
    A tag comment is only recorded if it is immediately followed by a valid 64-character hex digest.
    """
    tags_by_container = {}
    current_container = None
    pending_tag = None
    in_digests = False
    digest_re = re.compile(r"^-\s+[0-9a-fA-F]{64}$")
    with open(allowlist_path) as f:
        for line in f:
            line_str = line.strip()
            if line_str.startswith("containerImageDigests:"):
                in_digests = True
                continue
            if not in_digests:
                continue
            m_c = re.match(r"^-\s+containerName:\s*(\S+)", line_str)
            if m_c:
                current_container = m_c.group(1)
                tags_by_container[current_container] = set()
                pending_tag = None
                continue
            if current_container:
                if line_str.startswith("#"):
                    comment = line_str.lstrip("#").strip()
                    if ":" in comment:
                        pending_tag = comment
                    else:
                        pending_tag = None
                elif pending_tag and digest_re.match(line_str):
                    tags_by_container[current_container].add(pending_tag)
                    pending_tag = None
                elif line_str:
                    pending_tag = None
    return tags_by_container


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chart", required=True)
    ap.add_argument("--allowlist", required=True)
    ap.add_argument("--values", action="append", default=[])
    ap.add_argument("--set", dest="sets", action="append", default=[])
    ap.add_argument("--wrapper", action="store_true")
    ap.add_argument("--check-digests", action="store_true",
                    help="resolve running image digests via skopeo (network)")
    args = ap.parse_args()

    wl = workload_projection(render_node_agent(args.chart, args.values, args.sets, args.wrapper))
    al = allowlist_projection(yaml.safe_load(open(args.allowlist)))

    drift, digests_missing = [], []

    if wl["hostPID"] and not al["hostPID"]:
        drift.append("hostPID required by workload but not in allowlist")

    for name, wc in wl["containers"].items():
        ac = al["containers"].get(name)
        if ac is None:
            drift.append(f"container '{name}' not in allowlist")
            continue
        # image repo must satisfy the allowlist regex (tag-agnostic)
        if not re.match(ac["image"], repo(wc["image"])):
            drift.append(f"container '{name}': image repo {repo(wc['image'])} "
                         f"not matched by allowlist regex {ac['image']}")
        for cap in wc["add"] - ac["add"]:
            drift.append(f"container '{name}': capability {cap} not in allowlist")
        for env in wc["env"] - ac["env"]:
            drift.append(f"container '{name}': env {env} not in allowlist")
        for mp in wc["mounts"] - ac["mounts"]:
            drift.append(f"container '{name}': mountPath {mp} not in allowlist")
        if wc["privileged"] and not ac["privileged"]:
            drift.append(f"container '{name}': privileged required but allowlist has privileged:false")

    for name, path in wl["hostpaths"].items():
        if name not in al["hostpaths"]:
            drift.append(f"hostPath volume '{name}' ({path}) not in allowlist")
        elif al["hostpaths"][name] != path:
            drift.append(f"hostPath '{name}': workload path {path} != allowlist {al['hostpaths'][name]}")

    if args.check_digests:
        al_tags = extract_allowlist_tags(args.allowlist)
        for name, wc in wl["containers"].items():
            d = resolve_digest(wc["image"])
            if d:
                if d not in al["digests"].get(name, set()):
                    digests_missing.append(f"{name}: {wc['image']} -> sha256:{d[:16]}… not in containerImageDigests")
            else:
                # If skopeo cannot resolve the digest (e.g. private image without registry auth in CI),
                # verify that the image tag is annotated in the allowlist containerImageDigests comments.
                if wc["image"] not in al_tags.get(name, set()):
                    digests_missing.append(f"{name}: {wc['image']} -> digest entry not found in containerImageDigests")

    print(f"# drift report: {args.chart}")
    print(f"#   allowlist: {args.allowlist}")
    if drift:
        print("CLASS: spec-drift  (NEW allowlist version required)")
        for d in drift:
            print(f"  - {d}")
    if digests_missing:
        print("CLASS: digest-only  (append digests to existing allowlist)")
        for d in digests_missing:
            print(f"  - {d}")
    if drift or digests_missing:
        sys.exit(2)
    print("CLASS: no-op  (workload covered by approved allowlist)")
    sys.exit(0)


if __name__ == "__main__":
    main()
