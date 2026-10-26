#!/usr/bin/env python3
"""Deploy-time package checks, run on the host with the app venv's python.

Lets the deploy role skip reinstalls (and therefore service restarts) when
nothing changed.

    git-status
        Reads a JSON list of {"name", "url", "ref"} on stdin. Resolves each
        ref (branch, tag or commit SHA) to a commit with `git ls-remote` and
        reads the commit pip recorded for the installed distribution
        (direct_url.json). Prints the list back with "commit" and
        "installed" (null when not installed from git) added.

    check-dist NAME VERSION
        Exits 0 if distribution NAME is installed at VERSION and every file
        in its RECORD is present, 1 otherwise.
"""

import csv
import importlib.metadata
import json
import re
import subprocess
import sys
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def parse_ls_remote(output, ref):
    """Pick the commit for ref out of `git ls-remote <url> <ref>` output.

    For an annotated tag, the peeled "^{}" line is the commit; otherwise the
    first line is. Raises ValueError if ref matched nothing.
    """
    lines = [line.split("\t") for line in output.splitlines() if "\t" in line]
    if not lines:
        raise ValueError(f"ref {ref!r} not found")
    for sha, name in lines:
        if name.endswith("^{}"):
            return sha
    return lines[0][0]


def resolve_ref(url, ref):
    if SHA_RE.match(ref):
        return ref
    out = subprocess.run(
        ["git", "ls-remote", url, ref],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    try:
        return parse_ls_remote(out, ref)
    except ValueError as e:
        raise SystemExit(f"{url}: {e}")


def installed_commit(name):
    try:
        dist = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None
    raw = dist.read_text("direct_url.json")
    if not raw:
        return None
    return json.loads(raw).get("vcs_info", {}).get("commit_id")


def git_status(packages):
    return [
        dict(
            pkg,
            commit=resolve_ref(pkg["url"], pkg["ref"]),
            installed=installed_commit(pkg["name"]),
        )
        for pkg in packages
    ]


def dist_intact(name, version):
    try:
        dist = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    if dist.version != version:
        return False
    # Read RECORD directly: Distribution.files drops entries that are missing
    # on disk (Python 3.12+), which is exactly what this checks for.
    record = dist.read_text("RECORD") or ""
    paths = [row[0] for row in csv.reader(record.splitlines()) if row]
    return all(Path(dist.locate_file(p)).exists() for p in paths)


def main(argv):
    if argv[1:2] == ["git-status"]:
        json.dump(git_status(json.load(sys.stdin)), sys.stdout)
        return 0
    if argv[1:2] == ["check-dist"] and len(argv) == 4:
        return 0 if dist_intact(argv[2], argv[3]) else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
