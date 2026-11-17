"""End-to-end HTTP tests for the dependency locker.

Runs against a live deployment (Compose stack or locally started upstream +
gateway), exactly like ``test_breaker.py``:

    GATEWAY=http://127.0.0.1:8000 python -m pytest -q tests/test_locker_http.py

The locker shares the gateway's circuit breaker, so these tests also prove
that metadata still flows through the original breaker and that
``query_failed`` is never confused with ``unsat``.
"""

from __future__ import annotations

import json
import os
import threading
import time

import httpx
import pytest

GATEWAY = os.environ.get("GATEWAY", "http://127.0.0.1:8000").rstrip("/")
CLIENT = httpx.Client(timeout=20.0)


def _post(path, payload):
    return CLIENT.post(f"{GATEWAY}{path}", json=payload)


def _get(path):
    return CLIENT.get(f"{GATEWAY}{path}")


def _set_mode(mode, delay=None):
    payload = {"mode": mode}
    if delay is not None:
        payload["delay"] = delay
    r = _post("/api/upstream-mode", payload)
    assert r.status_code == 200, r.text


@pytest.fixture(autouse=True)
def _normal_upstream():
    _set_mode("normal")
    CLIENT.post(f"{GATEWAY}/api/reset")
    yield
    _set_mode("normal")


def test_catalog_is_seeded_and_revisions_listed():
    r = _get("/api/lock/revisions")
    assert r.status_code == 200
    data = r.json()
    assert data["current_revision"] is not None
    assert len(data["revisions"]) >= 1
    cat = _get("/api/lock/catalog").json()
    assert cat["artifact_count"] <= 12
    assert all(len(a["versions"]) <= 4 for a in cat["catalog"]["artifacts"])


def test_solve_diamond_backtracks_to_complete_manifest():
    r = _post("/api/lock/solve", {"root": "example-app", "allowed_versions": ["2.0.0"]})
    assert r.status_code == 200
    b = r.json()
    assert b["status"] == "sat", b
    # Greedy first pick (http-client 3.1.0) conflicts with core 2.0.0 on
    # json-codec; the solver must backtrack onto 3.0.0 rather than fail.
    assert b["search"]["backtracks"] >= 1
    assert b["assignment"]["http-client"] == "3.0.0"
    assert b["assignment"]["json-codec"] == "1.4.0"
    assert len(b["manifest"]) == len({m["artifact"] for m in b["manifest"]})
    assert all(m["digest_verified"] for m in b["manifest"])
    # Manifest carries version, summary and the pinned catalog revision.
    entry = b["manifest"][0]
    assert entry["version"] and entry["catalog_sha256"] and entry["summary"]
    assert entry["catalog_sha256"] == entry["metadata_sha256"]
    assert b["catalog_revision"] and b["catalog_digest"]


def test_cycle_is_solvable():
    r = _post("/api/lock/solve", {"root": "plugin-a", "allowed_versions": ["1.0.0"]})
    b = r.json()
    assert b["status"] == "sat", b
    assert b["assignment"] == {"plugin-a": "1.0.0", "legacy-config": "0.9.0"}


def test_unsat_is_reported_as_unsat_not_query_failure():
    r = _post("/api/lock/solve", {"root": "example-app", "allowed_versions": ["9.9.9"]})
    b = r.json()
    assert b["status"] == "unsat"
    assert b["reasons"] and b["query_failures"] == []
    assert b["manifest"] is None


def test_invalid_replacement_is_rejected_and_keeps_active_revision():
    before = _get("/api/lock/revisions").json()
    active_before = before["current_revision"]
    r = _post("/api/lock/catalog",
              {"schema": "artifact-catalog/v1",
               "artifacts": [{"name": "x", "versions": [
                   {"version": "1", "sha256": "broken", "dependencies": []}]}]})
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_catalog"
    assert body["active_revision_unchanged"] == active_before
    after = _get("/api/lock/revisions").json()
    assert after["current_revision"] == active_before
    assert len(after["revisions"]) == len(before["revisions"])


def test_valid_replacement_appends_revision_and_keeps_old_one():
    revs_before = len(_get("/api/lock/revisions").json()["revisions"])
    sample = _get("/api/lock/sample-catalog/v2")
    assert sample.status_code == 200
    r = _post("/api/lock/catalog", sample.json()["catalog"])
    assert r.status_code == 201, r.text
    new_id = r.json()["revision"]
    listing = _get("/api/lock/revisions").json()
    assert len(listing["revisions"]) == revs_before + 1
    assert listing["current_revision"] == new_id
    # Old revision remains readable.
    old = _get(f"/api/lock/catalog?revision={new_id - 1}")
    assert old.status_code == 200
    assert old.json()["revision"] == new_id - 1
    # Restore the original demo catalog so test order stays independent.
    original = _get(f"/api/lock/catalog?revision=1").json()["catalog"]
    _post("/api/lock/catalog", original)


def test_solve_pins_start_revision_across_mid_solve_replacement():
    # Ensure the current catalog is revision 1 content first.
    original = _get("/api/lock/catalog?revision=1").json()["catalog"]
    pinned_before = _post("/api/lock/catalog", original).json()["revision"]

    _set_mode("delay", 0.4)  # widen the in-flight window
    result: dict = {}
    t = threading.Thread(target=lambda: result.update(
        _post("/api/lock/solve",
              {"root": "example-app", "allowed_versions": ["2.0.0"]}).json()))
    t.start()
    time.sleep(0.35)
    v2 = _get("/api/lock/sample-catalog/v2").json()["catalog"]
    swap = _post("/api/lock/catalog", v2).json()
    t.join()
    _set_mode("normal")

    assert result["catalog_revision"] == pinned_before, "running solve must keep start revision"
    assert swap["revision"] == pinned_before + 1
    later = _post("/api/lock/solve",
                  {"root": "example-app", "allowed_versions": ["2.0.0"]}).json()
    assert later["catalog_revision"] == swap["revision"], "later solve must see new revision"
    # Restore.
    _post("/api/lock/catalog", original)


def test_open_breaker_causes_query_failed_not_unsat():
    # Trip the breaker for one of the manifest's artifacts.
    _set_mode("503")
    for _ in range(3):
        CLIENT.get(f"{GATEWAY}/api/meta/http-client")
    state = next(b for b in _get("/api/breakers").json()["breakers"]
                 if b["artifact"] == "http-client")
    assert state["state"] == "open"

    b = _post("/api/lock/solve",
              {"root": "example-app", "allowed_versions": ["2.0.0"]}).json()
    assert b["status"] == "query_failed"
    assert b["assignment"] is not None, "constraints were still solvable"
    reasons = {f["reason"] for f in b["query_failures"]}
    assert "circuit_open" in reasons or "upstream_failure" in reasons


def test_bad_solve_request_returns_400():
    r = _post("/api/lock/solve", {"root": "", "allowed_versions": ["1"]})
    assert r.status_code == 400
    r2 = _post("/api/lock/solve", {"root": "a", "allowed_versions": []})
    assert r2.status_code == 400


def test_legacy_meta_endpoint_unchanged():
    r = CLIENT.get(f"{GATEWAY}/api/meta/example-app.json")
    assert r.status_code == 200
    body = r.json()
    assert body["upstream"] == "success"
    assert body["metadata"]["metadata"]["name"] == "example-app"
    assert "breaker_effect" in body
