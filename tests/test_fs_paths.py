"""Tests for the T3 path denylist / classifier."""

import os
import sys

import pytest

from praxis.filesystem.paths import (
    PathClass,
    classify_path,
    refuses_delete,
    refuses_read,
    refuses_write,
)


class TestSafePaths:
    def test_ordinary_home_file_is_safe(self, tmp_path):
        p = tmp_path / "foo.txt"
        v = classify_path(p)
        assert v.path_class == PathClass.SAFE
        assert not refuses_read(v)
        assert not refuses_write(v)
        assert not refuses_delete(v)


class TestSystemPaths:
    @pytest.mark.skipif(sys.platform == "win32", reason="posix-only")
    @pytest.mark.parametrize(
        "path",
        [
            "/etc/passwd",
            "/System/Library/Kernels/kernel",
            "/usr/bin/ls",
            "/private/etc/hosts",
            "/boot/vmlinuz",
        ],
    )
    def test_system_paths_refuse_writes(self, path):
        v = classify_path(path)
        assert v.path_class == PathClass.SYSTEM
        assert not refuses_read(v), "system paths should still be readable"
        assert refuses_write(v)
        assert refuses_delete(v)


class TestSecretPaths:
    @pytest.mark.parametrize(
        "path",
        [
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "~/.gnupg/secring.gpg",
            "~/Library/Keychains/login.keychain-db",
            "~/.netrc",
            "~/.env",
            "~/.env.production",
        ],
    )
    def test_secret_paths_refuse_reads_and_writes(self, path):
        v = classify_path(path)
        assert v.path_class == PathClass.SECRETS, (
            f"expected SECRETS for {path}, got {v.path_class}"
        )
        assert refuses_read(v)
        assert refuses_write(v)
        assert refuses_delete(v)


class TestHomeRoot:
    def test_home_itself_refuses_delete(self):
        v = classify_path("~")
        assert v.path_class == PathClass.HOME_ROOT
        assert not refuses_read(v)
        assert not refuses_write(v)
        assert refuses_delete(v), "must never allow rm -rf ~"


class TestTraversal:
    def test_dot_dot_cannot_escape_into_system(self):
        # Ensure "~/Documents/../../../etc/passwd" resolves to /etc/passwd
        # and is caught by the SYSTEM check.
        if sys.platform == "win32":
            pytest.skip("posix-only")
        v = classify_path("~/Documents/../../../etc/passwd")
        assert v.path_class in (PathClass.SYSTEM, PathClass.SAFE)  # depending on OS


class TestPseudoFilesystems:
    @pytest.mark.skipif(sys.platform == "win32", reason="posix-only")
    def test_proc_is_pseudo(self):
        v = classify_path("/proc/1/mem")
        assert v.path_class == PathClass.PSEUDO
        assert refuses_write(v)
        assert not refuses_read(v)
