"""In-process unit tests for the dependency locker.

Covers catalog validation limits, atomic replacement with retained
revisions, the complete (non-greedy) backtracking solver, cycle tolerance,
unsat-vs-query-failure separation, digest verification and metadata
annotation stripping.  No network services are needed; the fetcher is a
local fake.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import locker  # noqa: E402


def _dep(name, *allowed):
    return {"name": name, "allowed_versions": list(allowed)}


def _ver(version, deps=None, sha=None):
    return {
        "version": version,
        "sha256": sha or ("a" * 64),
        "dependencies": deps or [],
    }


def _catalog(artifacts, catalog_id="unit"):
    return {"schema": "artifact-catalog/v1", "catalog_id": catalog_id,
            "artifacts": artifacts}


@pytest.fixture()
def store(tmp_path):
    import sqlite3

    db = tmp_path / "lock.db"

    def connect():
        conn = sqlite3.connect(str(db), isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    import contextlib

    @contextlib.contextmanager
    def write_tx():
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        finally:
            conn.close()

    s = locker.CatalogStore(connect, write_tx)
    s.init_schema()
    return s


# ----------------------------------------------------------------- validation


def test_validates_limits_and_shape():
    good = _catalog([{"name": "a", "versions": [_ver("1")]}])
    clean = locker.validate_catalog(good)
    assert clean["artifacts"][0]["versions"][0]["sha256"] == "a" * 64

    with pytest.raises(locker.CatalogError):
        locker.validate_catalog({"schema": "x"})  # no artifacts

    too_many = _catalog([
        {"name": f"a{i}", "versions": [_ver("1")]} for i in range(locker.MAX_ARTIFACTS + 1)
    ])
    with pytest.raises(locker.CatalogError, match=r"1\.\.12 artifacts"):
        locker.validate_catalog(too_many)

    too_many_versions = _catalog([{
        "name": "a",
        "versions": [_ver(str(i)) for i in range(locker.MAX_VERSIONS_PER_ARTIFACT + 1)],
    }])
    with pytest.raises(locker.CatalogError, match=r"at most 4 versions"):
        locker.validate_catalog(too_many_versions)

    bad_sha = _catalog([{"name": "a", "versions": [_ver("1", sha="nope")]}])
    with pytest.raises(locker.CatalogError, match="sha256"):
        locker.validate_catalog(bad_sha)

    dup = _catalog([
        {"name": "a", "versions": [_ver("1"), _ver("1")]},
    ])
    with pytest.raises(locker.CatalogError, match="duplicate version"):
        locker.validate_catalog(dup)

    empty_allowed = _catalog([{
        "name": "a",
        "versions": [_ver("1", [_dep("b")])],
    }])
    with pytest.raises(locker.CatalogError, match="allowed_versions"):
        locker.validate_catalog(empty_allowed)


def test_replacement_is_atomic_and_keeps_old_revisions(store):
    doc1 = _catalog([{"name": "a", "versions": [_ver("1")]}])
    rev1 = store.replace(doc1)
    assert rev1 == 1

    bad = _catalog([{"name": "a", "versions": [_ver("1", sha="bad")]}])
    with pytest.raises(locker.CatalogError):
        store.replace(bad)

    # Failed replacement must not add a revision or change the active one.
    revs = store.list_revisions()
    assert [r["id"] for r in revs] == [1]
    assert store.current_revision()["id"] == 1

    doc2 = _catalog([{"name": "a", "versions": [_ver("2", sha="b" * 64)]}])
    rev2 = store.replace(doc2)
    assert rev2 == 2
    assert store.current_revision()["id"] == 2
    old = store.get_revision(1)
    assert old["document"]["artifacts"][0]["versions"][0]["version"] == "1"
    assert store.get_revision(99) is None


def test_seed_is_idempotent(store):
    doc = _catalog([{"name": "a", "versions": [_ver("1")]}])
    assert store.seed_if_empty(doc) == 1
    assert store.seed_if_empty(doc) is None
    assert len(store.list_revisions()) == 1


def test_concurrent_first_startup_seeds_exactly_one_revision(store):
    """Two workers racing at startup must not each insert a revision."""
    import threading

    doc = _catalog([{"name": "a", "versions": [_ver("1")]}])
    outcomes: list = []
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()  # maximise the chance of entering the tx together
        outcomes.append(store.seed_if_empty(doc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    inserted = [o for o in outcomes if o is not None]
    assert inserted == [1], f"exactly one seeding expected, got {outcomes}"
    assert len(store.list_revisions()) == 1


# --------------------------------------------------------------------- solver


def _diamond_catalog():
    # Greedy first pick (http 3.1.0) dead-ends on json-codec; only http 3.0.0
    # works.  A greedy solver would wrongly report unsat; backtracking succeeds.
    return _catalog([
        {"name": "app", "versions": [_ver("1", [_dep("core", "1"), _dep("http", "3.1.0", "3.0.0")])]},
        {"name": "core", "versions": [_ver("1", [_dep("json", "1.4.0")])]},
        {"name": "http", "versions": [
            _ver("3.1.0", [_dep("json", "2.0.0")]),
            _ver("3.0.0", [_dep("json", "1.4.0")]),
        ]},
        {"name": "json", "versions": [_ver("2.0.0"), _ver("1.4.0")]},
    ])


def test_solver_backtracks_when_greedy_pick_dead_ends():
    idx = locker.build_index(_diamond_catalog())
    r = locker.solve_constraints(idx, "app", ["1"])
    assert r["status"] == "sat"
    assert r["assignment"]["http"] == "3.0.0"
    assert r["assignment"]["json"] == "1.4.0"
    assert r["stats"]["backtracks"] >= 1


def test_solver_enforces_single_version_per_name_across_diamond():
    # core wants json 1.4.0; http 3.1.0 wants json 2.0.0 -> conflict forces the
    # http 3.0.0 branch, and json appears exactly once in the assignment.
    idx = locker.build_index(_diamond_catalog())
    r = locker.solve_constraints(idx, "app", ["1"])
    names = list(r["assignment"])
    assert len(names) == len(set(names))


def test_cycle_is_not_an_error():
    cat = _catalog([
        {"name": "p", "versions": [_ver("1", [_dep("c", "1")])]},
        {"name": "c", "versions": [_ver("1", [_dep("p", "1")])]},
    ])
    idx = locker.build_index(cat)
    r = locker.solve_constraints(idx, "p", ["1"])
    assert r["status"] == "sat"
    assert r["assignment"] == {"p": "1", "c": "1"}


def test_unsat_reasons_are_reported():
    idx = locker.build_index(_diamond_catalog())
    r = locker.solve_constraints(idx, "app", ["9.9.9"])
    assert r["status"] == "unsat"
    assert r["reasons"] and r["reasons"][0]["kind"] == "no_allowed_version"

    r2 = locker.solve_constraints(idx, "ghost", ["1"])
    assert r2["status"] == "unsat"
    assert r2["reasons"][0]["kind"] == "missing_artifact"


def test_genuinely_unsat_diamond_returns_unsat_not_greedy_failure():
    # Both http versions require json 2.0.0 while core pins json 1.4.0: no
    # combination exists, and the search must exhaust every branch.
    cat = _catalog([
        {"name": "app", "versions": [_ver("1", [_dep("core", "1"), _dep("http", "3.1.0", "3.0.0")])]},
        {"name": "core", "versions": [_ver("1", [_dep("json", "1.4.0")])]},
        {"name": "http", "versions": [
            _ver("3.1.0", [_dep("json", "2.0.0")]),
            _ver("3.0.0", [_dep("json", "2.0.0")]),
        ]},
        {"name": "json", "versions": [_ver("2.0.0"), _ver("1.4.0")]},
    ])
    r = locker.solve_constraints(locker.build_index(cat), "app", ["1"])
    assert r["status"] == "unsat"
    assert any(x["kind"] == "version_conflict" for x in r["reasons"])


def test_request_validation_limits():
    with pytest.raises(locker.CatalogError):
        locker.validate_solve_request("", ["1"])
    with pytest.raises(locker.CatalogError):
        locker.validate_solve_request("a", [])
    with pytest.raises(locker.CatalogError):
        locker.validate_solve_request("a", [str(i) for i in range(5)])


# ------------------------------------------------------------- async solve()


def test_solve_manifest_verifies_digests_and_strips_annotations():
    cat = _diamond_catalog()
    # Give every version a deterministic digest matching its metadata body.
    for art in cat["artifacts"]:
        for ver in art["versions"]:
            body = {"name": art["name"], "version": ver["version"], "extra": 1}
            ver["sha256"] = locker.digest_metadata_body(body)

    async def fetcher(name, version):
        body = {"name": name, "version": version, "extra": 1,
                # transport annotations injected by the directory service
                "artifact": name, "source_file": f"{version}.json",
                "source_mtime": 12345}
        body["sha256"] = locker.digest_metadata_body(body)
        return {"ok": True, "metadata": body}

    snap = {"id": 7, "doc_digest": locker.digest_document(cat), "document": cat}
    res = asyncio.run(locker.solve(snap, "app", ["1"], fetcher))
    assert res["status"] == "sat"
    assert res["catalog_revision"] == 7
    assert all(m["digest_verified"] for m in res["manifest"])
    names = [m["artifact"] for m in res["manifest"]]
    assert names[0] == "app" and len(names) == len(set(names))


def test_query_failure_is_distinct_from_unsat():
    cat = _diamond_catalog()

    async def failing_fetcher(name, version):
        return {"ok": False, "reason": "circuit_open", "detail": "breaker open",
                "status": 503}

    snap = {"id": 1, "doc_digest": locker.digest_document(cat), "document": cat}
    res = asyncio.run(locker.solve(snap, "app", ["1"], failing_fetcher))
    assert res["status"] == "query_failed"
    assert res["assignment"] is not None  # constraints were solvable
    assert {f["reason"] for f in res["query_failures"]} == {"circuit_open"}


def test_digest_mismatch_is_a_query_failure():
    cat = _catalog([{"name": "a", "versions": [_ver("1")]}])

    async def fetcher(name, version):
        return {"ok": True, "metadata": {"name": "a", "version": "1",
                                          "sha256": "f" * 64}}

    snap = {"id": 1, "doc_digest": locker.digest_document(cat), "document": cat}
    res = asyncio.run(locker.solve(snap, "a", ["1"], fetcher))
    assert res["status"] == "query_failed"
    assert res["query_failures"][0]["reason"] == "digest_mismatch"


def test_generated_seed_catalogs_are_valid_and_limited():
    root = Path(__file__).resolve().parents[1]
    for fname in ("lock-demo.json", "lock-demo-v2.json"):
        doc = json.loads((root / "seed_catalogs" / fname).read_text())
        clean = locker.validate_catalog(doc)
        assert len(clean["artifacts"]) <= locker.MAX_ARTIFACTS
        for art in clean["artifacts"]:
            assert len(art["versions"]) <= locker.MAX_VERSIONS_PER_ARTIFACT
