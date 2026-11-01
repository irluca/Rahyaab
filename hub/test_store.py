"""Tests for the hub Store: the connection-leak regression (bug 13)."""

import os

import pytest

from hub.store import Store


def _fd_count():
    return len(os.listdir("/proc/self/fd"))


@pytest.mark.skipif(not os.path.exists("/proc/self/fd"),
                    reason="fd counting needs /proc (Linux)")
def test_store_methods_do_not_leak_fds(tmp_path):
    """Bug 13: `with self._connect()` never closed the connection —
    sqlite3's __exit__ only commits — so a fraction of connections sat
    in reference cycles until the cyclic GC ran, and under dashboard
    polling the leak outran collection to the 1024-fd limit and wedged
    the panel. 400 calls must not grow the fd count (no gc.collect()
    here: calling it would mask the leak)."""
    store = Store(tmp_path / "hub.db")
    base = _fd_count()
    for _ in range(200):
        store.get_pair(99999)
        store.list_pairs()
    assert _fd_count() <= base + 5
