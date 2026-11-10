"""Kernel pseudo-filesystems must stay off the managed-files read surface.

``/proc/self/environ`` is the cheapest way to lift the dashboard process's whole
environment (API keys, tokens) through ``GET /api/files/read``: the credential
denylist matches basenames, and ``environ`` is not one of them.
"""

import os

import pytest

from hermes_cli.web_routers.files import _is_pseudo_fs_path, _is_sensitive_path

needs_proc = pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="no /proc on this host")


@needs_proc
def test_proc_environ_is_blocked():
    assert _is_sensitive_path(__import__("pathlib").Path("/proc/self/environ"))


@needs_proc
def test_proc_listing_entries_are_blocked():
    from pathlib import Path

    for candidate in ("/proc/self/cmdline", "/proc/self/maps", "/proc/cpuinfo"):
        assert _is_pseudo_fs_path(Path(candidate)), candidate
        assert _is_sensitive_path(Path(candidate)), candidate


def test_sysfs_and_devfs_are_blocked():
    from pathlib import Path

    assert _is_pseudo_fs_path(Path("/sys/kernel/notes"))
    assert _is_sensitive_path(Path("/dev/zero"))


def test_regular_paths_are_not_treated_as_pseudo_fs(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("hello", encoding="utf-8")

    assert not _is_pseudo_fs_path(target)
    assert not _is_sensitive_path(target)


@needs_proc
def test_symlink_into_proc_is_blocked(tmp_path):
    link = tmp_path / "innocent.txt"
    link.symlink_to("/proc/self/environ")

    assert _is_sensitive_path(link)
