"""Tests for the deploy role's package checks (ansible/roles/deploy/files)."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
from pathlib import Path

import pytest

_PATH = (
    Path(__file__).resolve().parent.parent
    / "ansible"
    / "roles"
    / "deploy"
    / "files"
    / "deploy_packages.py"
)
_spec = importlib.util.spec_from_file_location("deploy_packages", _PATH)
dp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dp)

SHA_A = "a" * 40
SHA_B = "b" * 40


class TestParseLsRemote:
    def test_branch(self):
        assert dp.parse_ls_remote(f"{SHA_A}\trefs/heads/main\n", "main") == SHA_A

    def test_annotated_tag_uses_peeled_commit(self):
        out = f"{SHA_A}\trefs/tags/v1\n{SHA_B}\trefs/tags/v1^{{}}\n"
        assert dp.parse_ls_remote(out, "v1") == SHA_B

    def test_missing_ref(self):
        with pytest.raises(ValueError):
            dp.parse_ls_remote("", "nope")


class TestResolveRef:
    def test_sha_is_used_as_is(self, monkeypatch):
        def fail(*a, **k):
            raise AssertionError("ls-remote should not run for a SHA")

        monkeypatch.setattr(dp.subprocess, "run", fail)
        assert dp.resolve_ref("https://example.invalid/x.git", SHA_A) == SHA_A

    def test_branch_against_real_repo(self, tmp_path):
        repo = tmp_path / "repo"
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
             "commit", "-q", "--allow-empty", "-m", "x"],
            check=True,
        )
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert dp.resolve_ref(str(repo), "main") == head

    def test_unknown_ref_fails(self, tmp_path):
        repo = tmp_path / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        with pytest.raises(SystemExit):
            dp.resolve_ref(str(repo), "no-such-branch")


class _Dist:
    def __init__(self, direct_url):
        self._direct_url = direct_url

    def read_text(self, name):
        assert name == "direct_url.json"
        return self._direct_url


class TestGitStatus:
    def _patch(self, monkeypatch, dists):
        def distribution(name):
            if name not in dists:
                raise dp.importlib.metadata.PackageNotFoundError(name)
            return dists[name]

        monkeypatch.setattr(dp.importlib.metadata, "distribution", distribution)
        monkeypatch.setattr(dp, "resolve_ref", lambda url, ref: SHA_B)

    def test_reports_installed_and_resolved_commits(self, monkeypatch):
        self._patch(monkeypatch, {
            "same": _Dist(json.dumps({"vcs_info": {"commit_id": SHA_B}})),
            "old": _Dist(json.dumps({"vcs_info": {"commit_id": SHA_A}})),
            "pypi": _Dist(None),
        })
        pkgs = [
            {"name": n, "url": "u", "ref": "main"}
            for n in ("same", "old", "pypi", "absent")
        ]
        status = {p["name"]: p for p in dp.git_status(pkgs)}
        assert all(p["commit"] == SHA_B for p in status.values())
        assert status["same"]["installed"] == SHA_B
        assert status["old"]["installed"] == SHA_A
        assert status["pypi"]["installed"] is None
        assert status["absent"]["installed"] is None

    def test_main_round_trips_json(self, monkeypatch, capsys):
        self._patch(monkeypatch, {})
        pkg = {"name": "x", "url": "u", "ref": "main", "pip_args": "--no-deps"}
        monkeypatch.setattr(dp.sys, "stdin", io.StringIO(json.dumps([pkg])))
        assert dp.main(["deploy_packages.py", "git-status"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out == [dict(pkg, commit=SHA_B, installed=None)]


class TestCheckDist:
    def test_installed_dist_is_intact(self):
        version = dp.importlib.metadata.version("pytest")
        assert dp.main(["deploy_packages.py", "check-dist", "pytest", version]) == 0

    def test_wrong_version(self):
        assert dp.main(["deploy_packages.py", "check-dist", "pytest", "0.0.0"]) == 1

    def test_missing_dist(self):
        assert dp.main(["deploy_packages.py", "check-dist", "no-such-dist", "1"]) == 1

    def _dist(self, tmp_path, version="1.0"):
        site = tmp_path / "site-packages"
        info = site / "pkg-1.0.dist-info"
        info.mkdir(parents=True)
        (site / "pkg").mkdir()
        (site / "pkg" / "__init__.py").write_text("")
        (info / "RECORD").write_text(
            "pkg/__init__.py,sha256=x,0\npkg-1.0.dist-info/RECORD,,\n"
        )
        (info / "METADATA").write_text(f"Name: pkg\nVersion: {version}\n")
        return site, dp.importlib.metadata.PathDistribution(info)

    def test_record_files_present(self, monkeypatch, tmp_path):
        site, dist = self._dist(tmp_path)
        monkeypatch.setattr(dp.importlib.metadata, "distribution", lambda n: dist)
        assert dp.dist_intact("pkg", "1.0") is True

    def test_missing_file(self, monkeypatch, tmp_path):
        """The fastmcp case: another package's upgrade deleted a shared file."""
        site, dist = self._dist(tmp_path)
        (site / "pkg" / "__init__.py").unlink()
        monkeypatch.setattr(dp.importlib.metadata, "distribution", lambda n: dist)
        assert dp.dist_intact("pkg", "1.0") is False
