#!/usr/bin/env python3
"""Refresh containerImageDigests in approved GKE Autopilot allowlists.

`containerImageDigests` is the ONLY mutable field of an approved WorkloadAllowlist,
so when a new node-agent version ships you just append its SHA-256 digest to the
existing file (no new allowlist version). This script automates that.

It covers both registries:
  - quay.io/kubescape/node-agent
  - quay.io/armosec/node-agent

For each allowlist file it finds every `containerImageDigests[].imageDigests` block,
infers which registry the block tracks from its existing `# quay.io/<reg>/node-agent:vX`
comments, fetches the latest release digests for that registry (skopeo), and reports
any that are missing. With --apply it inserts the missing entries (newest first) at the
top of the block, preserving the file's comment+digest format.

Usage:
  refresh-digests.py [--apply] [-t TAG ...] [--max N] [FILE ...]
Default FILEs are the 1.40 allowlists. Dry-run by default (prints a report).
Exit code: 0 = up to date, 10 = missing digests found (dry-run), 0 after --apply.
"""
import argparse, glob, json, os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

# Repo root of the ARMO allowlist checkout. Override with $GKE_ALLOWLIST_REPO; falls back to the
# path used during development or vendored gke-allowlist/*.yaml in the helm-charts repo.
REPO = os.environ.get(
    "GKE_ALLOWLIST_REPO",
    os.path.expanduser("~/projects/workspace-gke-autopilot-approval/gke-allow-list/ARMO"),
)
DEFAULT_FILES = sorted(glob.glob(f"{REPO}/*/1.40/*-1.40.yaml"))
if not DEFAULT_FILES:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "../.."))
    DEFAULT_FILES = sorted(glob.glob(os.path.join(repo_root, "gke-allowlist", "*.yaml")))

TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
REG_RE = re.compile(r"quay\.io/(armosec|kubescape)/node-agent")


def _skopeo(*args):
    if shutil.which("skopeo") is None:
        sys.exit("error: skopeo is not installed (needed to resolve image digests).")
    return subprocess.run(["skopeo", *args], capture_output=True, text=True, timeout=120)


@lru_cache(maxsize=None)
def get_digest(repo, tag):
    """Resolve digest for repo:tag using skopeo with --no-tags."""
    ins = _skopeo("inspect", "--no-tags", f"docker://{repo}:{tag}")
    if ins.returncode == 0:
        d = json.loads(ins.stdout).get("Digest", "").replace("sha256:", "")
        if d:
            return d
    return None


@lru_cache(maxsize=None)
def fetch_tags(registry):
    """Fetch all release tags for quay.io/<registry>/node-agent sorted newest first."""
    repo = f"quay.io/{registry}/node-agent"
    tags = _skopeo("list-tags", f"docker://{repo}")
    if tags.returncode != 0:
        sys.exit(f"skopeo list-tags failed for {repo}:\n{tags.stderr}")
    all_tags = [t for t in json.loads(tags.stdout)["Tags"] if TAG_RE.match(t)]
    all_tags.sort(key=lambda t: [int(x) for x in t[1:].split(".")], reverse=True)
    return all_tags


def resolve_tags(registry, tags):
    """Resolve digests for a list of tags in parallel."""
    if not tags:
        return []
    repo = f"quay.io/{registry}/node-agent"
    with ThreadPoolExecutor(max_workers=min(len(tags), 8)) as pool:
        results = list(pool.map(lambda t: (t, get_digest(repo, t)), tags))
    return [(t, d) for (t, d) in results if d]


def process(path, maxn, apply, explicit_tags=None):
    lines = open(path).read().splitlines()
    # find each "imageDigests:" line and the extent of its block
    blocks = []  # (insert_after_idx, end_idx, registry, existing_digests:set, existing_tags:set)
    i = 0
    while i < len(lines):
        if re.match(r"^\s*imageDigests:\s*$", lines[i]):
            indent = len(lines[i]) - len(lines[i].lstrip())
            j = i + 1
            existing_digests, existing_tags, reg = set(), set(), None
            while j < len(lines):
                ln = lines[j]
                # block ends when indentation drops to <= the imageDigests indent on a non-blank, non-deeper line
                if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                    break
                m = re.match(r"\s*-\s+([0-9a-f]{64})\s*$", ln)
                if m:
                    existing_digests.add(m.group(1))
                rm = REG_RE.search(ln)
                if rm:
                    if reg is None:
                        reg = rm.group(1)
                    tm = re.search(r":(" + TAG_RE.pattern[1:-1] + r")", ln)
                    if tm:
                        existing_tags.add(tm.group(1))
                j += 1
            blocks.append([i, j, reg, existing_digests, existing_tags])
            i = j
        else:
            i += 1

    report, additions = [], []  # additions: (insert_idx, [new lines])
    for insert_after, _end, reg, existing_digests, existing_tags in blocks:
        if not reg:
            report.append(f"  ! could not infer registry for block at line {insert_after+1}; skipping")
            continue

        if explicit_tags:
            candidate_tags = [t for t in explicit_tags if t not in existing_tags]
            resolved = resolve_tags(reg, candidate_tags)
            missing = [(t, d) for (t, d) in resolved if d not in existing_digests]
        else:
            all_tags = fetch_tags(reg)
            candidate_tags = [t for t in all_tags[:maxn] if t not in existing_tags]
            resolved = resolve_tags(reg, candidate_tags)
            missing = [(t, d) for (t, d) in resolved if d not in existing_digests]

        missing.sort(key=lambda item: [int(x) for x in item[0][1:].split(".")], reverse=True)

        report.append(f"  block@L{insert_after+1} [{reg}/node-agent]: "
                      f"{len(existing_digests)} present, {len(missing)} new")
        for t, d in missing:
            report.append(f"      + {t}  sha256:{d[:16]}…")
        if missing:
            # build new lines (newest first), matched to the block's digest indentation
            digit_indent = " " * (len(lines[insert_after]) - len(lines[insert_after].lstrip()) + 2)
            new = []
            for t, d in missing:
                new.append(f"{digit_indent}# quay.io/{reg}/node-agent:{t}")
                new.append(f"{digit_indent}- {d}")
            additions.append((insert_after + 1, new))

    total_new = sum(len(n)//2 for _, n in additions)
    print(f"\n{os.path.relpath(path)}")
    for r in report:
        print(r)

    if apply and additions:
        # apply bottom-up so earlier insert indices stay valid
        for idx, new in sorted(additions, key=lambda x: -x[0]):
            lines[idx:idx] = new
        open(path, "w").write("\n".join(lines) + "\n")
        print(f"  -> applied: inserted {total_new} digest(s)")
    return total_new


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", default=DEFAULT_FILES)
    ap.add_argument("--apply", action="store_true", help="write changes in place")
    ap.add_argument("-t", "--tag", action="append", dest="tags",
                    help="specific tag(s) to fetch and append (skips slow list-tags, e.g. -t v0.0.572)")
    ap.add_argument("--max", type=int, default=20, help="latest N release tags per registry (discovery mode)")
    args = ap.parse_args()
    files = args.files or DEFAULT_FILES
    if not files:
        sys.exit(f"error: no allowlist files given and none found under {REPO} "
                 f"(set $GKE_ALLOWLIST_REPO or pass file paths).")
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        sys.exit("error: allowlist file(s) not found: " + ", ".join(missing))

    explicit_tags = None
    if args.tags:
        explicit_tags = [t if t.startswith("v") else f"v{t}" for t in args.tags]

    total = sum(process(f, args.max, args.apply, explicit_tags=explicit_tags) for f in files)
    print(f"\nTotal new digests {'applied' if args.apply else 'available'}: {total}")
    if total and not args.apply:
        print("Re-run with --apply to insert them, then commit + push to Gerrit refs/for/main.")
        sys.exit(10)


if __name__ == "__main__":
    main()
