"""Two-worker circuit-breaker gateway for artifact metadata lookups.

Architecture
------------
* FastAPI/uvicorn runs two worker processes.  Each worker has its own asyncio
  event loop, so a slow upstream query never blocks another query.
* Breaker state lives in SQLite (WAL mode, ``BEGIN IMMEDIATE`` for writes), so
  it is shared by both workers and survives restarts.
* Every upstream call is bounded to ``REQUEST_TIMEOUT`` seconds end-to-end.
* A breaker failure is a connect failure, a timeout, or a 5xx response.  Any
  other completed response (2xx/3xx/4xx) resets the failure counter.

Breaker semantics (per artifact name)
-------------------------------------
* CLOSED: calls pass through.  Failures are counted in completion order.  The
  third consecutive failure opens the circuit; a healthy response resets to 0.
* OPEN: every request is answered locally with 503; the upstream is not
  contacted.  After ``COOLDOWN`` seconds the first caller atomically becomes
  the single HALF_OPEN probe; everybody else is still rejected.
* A failed/timed-out probe re-opens the breaker with a fresh cooldown.
* A probe that crashes or silently disappears releases the probe slot after a
  lease, so a new probe can eventually run.
* Results carry the epoch observed at admission.  When the breaker has tripped
  since then the result is stale: a slow success that started before the trip
  can neither reset the counter nor close the circuit.
* Probe results carry the probe generation.  A late result from an older probe
  generation is discarded, so it cannot overwrite a newer verdict.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import locker
from locker import CatalogError, CatalogStore
from seed_data import INITIAL_CATALOG

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("GATEWAY_DB", BASE_DIR / "data" / "breaker.db"))
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://upstream:9000").rstrip("/")
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "1.0"))
COOLDOWN = float(os.environ.get("COOLDOWN", "2.0"))
FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", "3"))
# A live probe is bounded by REQUEST_TIMEOUT; anything older than this lease is
# considered abandoned (e.g. its process died before writing a verdict).
PROBE_LEASE = max(2.0, REQUEST_TIMEOUT + 1.0)

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"

# Unique id of this worker process.  Used to tell our own live probe apart from
# a stale half-open record left behind by a dead process.
INSTANCE_ID = f"{os.getpid()}-{time.time_ns()}"
ACTIVE_PROBES: set[str] = set()


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS breakers (
    artifact        TEXT PRIMARY KEY,
    state           TEXT NOT NULL DEFAULT 'closed',
    failures        INTEGER NOT NULL DEFAULT 0,
    opened_at       REAL NOT NULL DEFAULT 0,
    probe_gen       INTEGER NOT NULL DEFAULT 0,
    probe_holder    TEXT,
    epoch           INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    last_transition REAL NOT NULL DEFAULT 0,
    updated_at      REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    artifact TEXT NOT NULL,
    kind     TEXT NOT NULL,
    detail   TEXT
);
CREATE TABLE IF NOT EXISTS upstream_stats (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    hits         INTEGER NOT NULL DEFAULT 0,
    hits_by_mode TEXT NOT NULL DEFAULT '{}'
);
INSERT OR IGNORE INTO upstream_stats (id, hits) VALUES (1, 0);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    last: Optional[Exception] = None
    for _ in range(50):
        try:
            conn = connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(SCHEMA)
            finally:
                conn.close()
            return
        except sqlite3.OperationalError as exc:  # two workers racing at startup
            last = exc
            time.sleep(0.1)
    raise RuntimeError(f"unable to initialise breaker database: {last}")


@contextlib.contextmanager
def write_tx():
    """Exclusive write transaction, serialising both worker processes."""
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


# Versioned catalog store.  It shares the breaker SQLite database, so
# revisions are visible to both workers and survive restarts.
CATALOG_STORE = CatalogStore(connect, write_tx)


def log_event(conn: sqlite3.Connection, artifact: str, kind: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO events (ts, artifact, kind, detail) VALUES (?, ?, ?, ?)",
        (time.time(), artifact, kind, detail[:300]),
    )
    conn.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) - 500 FROM events)")


# ---------------------------------------------------------------------------
# Breaker state machine
# ---------------------------------------------------------------------------


@dataclass
class Admission:
    allowed: bool
    role: str  # "normal" | "probe" | "none"
    epoch: int
    probe_gen: int = 0
    holder: Optional[str] = None
    state: str = CLOSED
    retry_after: float = 0.0


@dataclass
class Outcome:
    kind: str  # "success" | "failure"
    detail: str
    status: Optional[int] = None
    payload: Any = None


def _probe_is_live(row: sqlite3.Row, now: float) -> bool:
    holder = row["probe_holder"] or ""
    if not holder:
        return False
    pid_text = holder.split("|", 1)[0]
    try:
        pid = int(pid_text)
    except ValueError:
        return False
    if pid == os.getpid():
        # Only probes this process is actively running count as live; a
        # half-open row from an earlier incarnation is stale.
        return holder in ACTIVE_PROBES
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    else:
        # A SIGKILLed worker can linger as a zombie until its parent reaps it;
        # ``kill(pid, 0)`` still succeeds for zombies, so check /proc when
        # present.
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            pass
        else:
            if stat.rsplit(")", 1)[-1].split()[0] == "Z":
                return False
    # Backstop against PID reuse / a live process that abandoned its probe: a
    # probe is bounded by REQUEST_TIMEOUT, so anything older than the lease is
    # considered dead.
    return now - row["opened_at"] <= PROBE_LEASE


def effective_state(row: sqlite3.Row, now: float) -> tuple[str, float]:
    """Persisted state with crash recovery applied.

    A HALF_OPEN row whose probe owner is gone is treated as OPEN measured from
    the probe start, so the normal cooldown rules (and its 503 responses)
    still apply before another probe is elected.
    """
    if row["state"] == HALF_OPEN and not _probe_is_live(row, now):
        return OPEN, row["opened_at"]
    return row["state"], row["opened_at"]


def admit(artifact: str) -> Admission:
    """Atomically decide whether this request may call the upstream.

    Fast paths (CLOSED and rejection-while-open) are read-only, so normal
    traffic and bursts of rejections never serialise on the SQLite write lock.
    Only the probe election takes ``BEGIN IMMEDIATE``.
    """
    now = time.time()
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM breakers WHERE artifact = ?", (artifact,)).fetchone()
    finally:
        conn.close()

    if row is not None:
        fast = _fast_admission(row, now)
        if fast is not None:
            return fast

    with write_tx() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO breakers (artifact, updated_at) VALUES (?, ?)",
            (artifact, now),
        )
        row = conn.execute("SELECT * FROM breakers WHERE artifact = ?", (artifact,)).fetchone()
        now = time.time()
        state, opened_at = effective_state(row, now)

        if state == CLOSED:
            return Admission(True, "normal", row["epoch"], state=CLOSED)

        if state == HALF_OPEN:
            # A live probe is already in flight; nobody else may pass.
            return Admission(False, "none", row["epoch"], state=HALF_OPEN, retry_after=0.2)

        remaining = COOLDOWN - (now - opened_at)
        if remaining > 0:
            return Admission(False, "none", row["epoch"], state=OPEN, retry_after=remaining)

        # Cooldown elapsed: promote exactly one caller to probe.  BEGIN
        # IMMEDIATE serialises this across both worker processes.
        probe_gen = row["probe_gen"] + 1
        holder = f"{os.getpid()}|{INSTANCE_ID}|{probe_gen}"
        conn.execute(
            "UPDATE breakers SET state = ?, probe_gen = ?, probe_holder = ?, opened_at = ?, "
            "updated_at = ? WHERE artifact = ?",
            (HALF_OPEN, probe_gen, holder, now, now, artifact),
        )
        log_event(conn, artifact, "probe_started", f"generation {probe_gen}")
        ACTIVE_PROBES.add(holder)
        return Admission(
            True, "probe", row["epoch"], probe_gen, holder, HALF_OPEN, 0.0
        )


def _fast_admission(row: sqlite3.Row, now: float) -> Optional[Admission]:
    """Admission decision that needs no write, or ``None`` if a write is needed."""
    state, opened_at = effective_state(row, now)
    if state == CLOSED:
        return Admission(True, "normal", row["epoch"], state=CLOSED)
    if state == HALF_OPEN:
        return Admission(False, "none", row["epoch"], state=HALF_OPEN, retry_after=0.2)
    remaining = COOLDOWN - (now - opened_at)
    if remaining > 0:
        return Admission(False, "none", row["epoch"], state=OPEN, retry_after=remaining)
    return None  # cooldown elapsed: must take the write lock to elect the probe


def record_outcome(artifact: str, adm: Admission, outcome: Outcome, hit_role: Optional[str] = None) -> dict[str, Any]:
    """Fold one completed upstream result into the shared state.

    ``hit_role`` counts this call towards the gateway's per-mode upstream
    counters in the same transaction, so each request needs one write.
    """
    now = time.time()
    result: dict[str, Any] = {"effect": "ignored", "state": None}
    with write_tx() as conn:
        if hit_role:
            _bump_upstream_hit(conn, hit_role)
        row = conn.execute("SELECT * FROM breakers WHERE artifact = ?", (artifact,)).fetchone()
        if row is None:
            return result

        if adm.role == "probe":
            own_probe = (
                row["probe_gen"] == adm.probe_gen
                and row["state"] == HALF_OPEN
                and (row["probe_holder"] or "") == (adm.holder or "")
            )
            if not own_probe:
                # A newer probe generation (or a newer decision) already won.
                result.update(effect="stale_probe_ignored", state=row["state"])
                log_event(conn, artifact, "probe_stale", f"generation {adm.probe_gen}")
                return result
            if outcome.kind == "success":
                conn.execute(
                    "UPDATE breakers SET state = ?, failures = 0, probe_holder = NULL, "
                    "epoch = epoch + 1, last_error = NULL, last_transition = ?, updated_at = ? "
                    "WHERE artifact = ?",
                    (CLOSED, now, now, artifact),
                )
                log_event(conn, artifact, "probe_success", "circuit closed")
                result.update(effect="closed", state=CLOSED)
            else:
                conn.execute(
                    "UPDATE breakers SET state = ?, failures = ?, opened_at = ?, "
                    "probe_holder = NULL, last_error = ?, last_transition = ?, updated_at = ? "
                    "WHERE artifact = ?",
                    (OPEN, FAILURE_THRESHOLD, now, outcome.detail, now, now, artifact),
                )
                log_event(conn, artifact, "probe_failed", outcome.detail)
                result.update(effect="reopened", state=OPEN)
            return result

        # Normal (non-probe) completed attempt.
        if row["state"] != CLOSED:
            if outcome.kind == "success":
                # Slow success started before the trip: it must not recover.
                result.update(effect="stale_success_ignored", state=row["state"])
                log_event(conn, artifact, "stale_success_ignored", "late success after trip")
            else:
                result.update(effect="stale_failure_ignored", state=row["state"])
            return result

        if adm.epoch != row["epoch"]:
            # The breaker opened (and possibly closed again) while this call
            # was in flight; this attempt belongs to an older epoch.
            result.update(effect="stale_attempt_ignored", state=row["state"])
            return result

        if outcome.kind == "success":
            conn.execute(
                "UPDATE breakers SET failures = 0, last_error = NULL, updated_at = ? "
                "WHERE artifact = ?",
                (now, artifact),
            )
            result.update(effect="reset", state=CLOSED)
        else:
            failures = row["failures"] + 1
            if failures >= FAILURE_THRESHOLD:
                conn.execute(
                    "UPDATE breakers SET state = ?, failures = ?, opened_at = ?, "
                    "epoch = epoch + 1, probe_holder = NULL, last_error = ?, "
                    "last_transition = ?, updated_at = ? WHERE artifact = ?",
                    (OPEN, failures, now, outcome.detail, now, now, artifact),
                )
                log_event(conn, artifact, "opened", f"{failures} consecutive failures: {outcome.detail}")
                result.update(effect="opened", state=OPEN)
            else:
                conn.execute(
                    "UPDATE breakers SET failures = ?, last_error = ?, updated_at = ? "
                    "WHERE artifact = ?",
                    (failures, outcome.detail, now, artifact),
                )
                log_event(conn, artifact, "failure", f"{failures}/{FAILURE_THRESHOLD} {outcome.detail}")
                result.update(effect="failure_counted", state=CLOSED)
        return result


def clean_stale_probes() -> None:
    """Release HALF_OPEN rows left behind by dead processes at startup."""
    now = time.time()
    with write_tx() as conn:
        rows = conn.execute("SELECT * FROM breakers WHERE state = ?", (HALF_OPEN,)).fetchall()
        for row in rows:
            if not _probe_is_live(row, now):
                conn.execute(
                    "UPDATE breakers SET state = ?, probe_holder = NULL, updated_at = ? "
                    "WHERE artifact = ? AND state = ?",
                    (OPEN, now, row["artifact"], HALF_OPEN),
                )
                log_event(conn, row["artifact"], "probe_abandoned", "released at startup")


# ---------------------------------------------------------------------------
# Upstream call
# ---------------------------------------------------------------------------


# One pooled client per worker process: connection setup is not repeated for
# every lookup, which keeps 1s timeouts meaningful under concurrency.
_client: Optional[httpx.AsyncClient] = None


def upstream_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50)
        _client = httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT), limits=limits)
    return _client


async def close_upstream_client() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


async def _get(url: str) -> httpx.Response:
    return await upstream_client().get(url, headers={"Accept": "application/json"})


async def call_upstream(artifact: str) -> Outcome:
    """One GET bounded by REQUEST_TIMEOUT in total (not per phase)."""
    url = f"{UPSTREAM_URL}/artifacts/{quote(artifact, safe='')}"
    try:
        resp = await asyncio.wait_for(_get(url), timeout=REQUEST_TIMEOUT)
    except (asyncio.TimeoutError, httpx.TimeoutException, httpx.ConnectError,
            httpx.NetworkError, httpx.RemoteProtocolError, httpx.HTTPError) as exc:
        return Outcome("failure", f"{type(exc).__name__}: {exc}"[:300])
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # defensive: any transport oddity counts as failure
        return Outcome("failure", f"{type(exc).__name__}: {exc}"[:300])

    if resp.status_code >= 500:
        return Outcome(
            "failure",
            f"upstream {resp.status_code}: {resp.text[:200]}",
            status=resp.status_code,
        )
    try:
        payload = resp.json()
    except ValueError:
        payload = resp.text[:2000]
    return Outcome("success", f"{resp.status_code}", status=resp.status_code, payload=payload)


async def call_upstream_versioned(artifact: str, version: str) -> Outcome:
    """One versioned metadata GET through the same timeout/breaker path."""
    url = (
        f"{UPSTREAM_URL}/artifacts/{quote(artifact, safe='')}"
        f"?version={quote(version, safe='')}"
    )
    try:
        resp = await asyncio.wait_for(_get(url), timeout=REQUEST_TIMEOUT)
    except (asyncio.TimeoutError, httpx.TimeoutException, httpx.ConnectError,
            httpx.NetworkError, httpx.RemoteProtocolError, httpx.HTTPError) as exc:
        return Outcome("failure", f"{type(exc).__name__}: {exc}"[:300])
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return Outcome("failure", f"{type(exc).__name__}: {exc}"[:300])

    if resp.status_code >= 500:
        return Outcome(
            "failure",
            f"upstream {resp.status_code}: {resp.text[:200]}",
            status=resp.status_code,
        )
    try:
        payload = resp.json()
    except ValueError:
        payload = resp.text[:2000]
    return Outcome("success", f"{resp.status_code}", status=resp.status_code, payload=payload)


async def breaker_guarded_lookup(artifact: str, version: Optional[str] = None) -> dict[str, Any]:
    """Run one metadata lookup through the shared circuit breaker.

    Returns a normalised result used by both the legacy ``/api/meta`` view
    and the dependency locker's injected fetcher.  Breaker-open rejections
    and upstream failures are surfaced as ``ok=False``; a 404 from a healthy
    upstream is also ``ok=False`` (the artifact/version simply does not
    exist), but *not* a breaker failure.
    """
    try:
        adm = await asyncio.to_thread(admit, artifact)
    except sqlite3.Error as exc:
        return {"ok": False, "reason": "breaker_store_unavailable",
                "detail": str(exc)[:300], "status": 503, "admission": None}

    if not adm.allowed:
        return {
            "ok": False,
            "reason": "circuit_open",
            "detail": f"breaker {adm.state}; retry_after={adm.retry_after:.2f}s",
            "status": 503,
            "retry_after": round(adm.retry_after, 3),
            "breaker_state": adm.state,
            "admission": {"role": adm.role, "epoch": adm.epoch},
        }

    started = time.time()
    try:
        if version is None:
            outcome = await call_upstream(artifact)
        else:
            outcome = await call_upstream_versioned(artifact, version)
    except asyncio.CancelledError:
        with contextlib.suppress(Exception):
            await asyncio.shield(
                asyncio.to_thread(
                    _finish, artifact, adm, Outcome("failure", "cancelled"), None
                )
            )
        raise
    elapsed = time.time() - started
    effect = await asyncio.to_thread(_finish, artifact, adm, outcome, adm.role)

    common = {
        "role": adm.role,
        "elapsed_ms": round(elapsed * 1000, 1),
        "breaker_effect": effect["effect"],
        "breaker_state": effect["state"],
        "pid": os.getpid(),
    }
    if outcome.kind != "success":
        return {"ok": False,
                "reason": "upstream_failure",
                "detail": outcome.detail,
                "status": outcome.status or 502,
                **common}

    status = outcome.status or 200
    payload = outcome.payload if isinstance(outcome.payload, dict) else {}
    if status >= 400:
        # A healthy upstream answered (4xx) -- the breaker was reset, but the
        # requested artifact/version has no metadata.
        return {"ok": False,
                "reason": "not_found" if status == 404 else "upstream_client_error",
                "detail": f"upstream {status}: {json.dumps(payload)[:200]}",
                "status": status,
                **common}
    metadata = payload.get("metadata", payload)
    return {"ok": True, "status": status, "metadata": metadata, **common}


# ---------------------------------------------------------------------------
# Auxiliary shared counters
# ---------------------------------------------------------------------------


def _bump_upstream_hit(conn: sqlite3.Connection, role: str) -> None:
    row = conn.execute("SELECT hits, hits_by_mode FROM upstream_stats WHERE id = 1").fetchone()
    try:
        by_mode = json.loads(row["hits_by_mode"] or "{}")
    except ValueError:
        by_mode = {}
    by_mode[role] = by_mode.get(role, 0) + 1
    conn.execute(
        "UPDATE upstream_stats SET hits = ?, hits_by_mode = ? WHERE id = 1",
        (row["hits"] + 1, json.dumps(by_mode, sort_keys=True)),
    )


def get_gateway_hits() -> dict[str, Any]:
    conn = connect()
    try:
        row = conn.execute("SELECT hits, hits_by_mode FROM upstream_stats WHERE id = 1").fetchone()
        return {"hits": row["hits"], "by_mode": json.loads(row["hits_by_mode"] or "{}")}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    clean_stale_probes()
    CATALOG_STORE.init_schema()
    CATALOG_STORE.seed_if_empty(INITIAL_CATALOG)
    try:
        yield
    finally:
        await close_upstream_client()


app = FastAPI(title="Artifact Metadata Circuit-Breaker Gateway", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "pid": str(os.getpid())}


def _finish(artifact: str, adm: Admission, outcome: Outcome, hit_role: Optional[str]) -> dict[str, Any]:
    try:
        return record_outcome(artifact, adm, outcome, hit_role=hit_role)
    finally:
        if adm.holder:
            ACTIVE_PROBES.discard(adm.holder)


@app.get("/api/meta/{artifact:path}")
async def get_meta(artifact: str) -> JSONResponse:
    artifact = artifact.strip()
    if not artifact:
        raise HTTPException(status_code=400, detail="artifact name required")

    try:
        # SQLite writes serialise across processes; run them off the event loop
        # so a request waiting on the write lock never stalls other queries in
        # the same worker.
        adm = await asyncio.to_thread(admit, artifact)
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail=f"breaker store unavailable: {exc}") from exc
    if not adm.allowed:
        return JSONResponse(
            status_code=503,
            content={
                "artifact": artifact,
                "error": "circuit_open",
                "state": adm.state,
                "retry_after": round(adm.retry_after, 3),
                "pid": os.getpid(),
            },
            headers={"Retry-After": f"{max(0.0, adm.retry_after):.2f}"},
        )

    started = time.time()
    try:
        outcome = await call_upstream(artifact)
    except asyncio.CancelledError:
        # Client went away / server shutdown: release the probe slot and treat
        # it as a failed probe so recovery can be retried later.
        with contextlib.suppress(Exception):
            await asyncio.shield(
                asyncio.to_thread(
                    _finish, artifact, adm, Outcome("failure", "cancelled"), None
                )
            )
        raise
    elapsed = time.time() - started
    effect = await asyncio.to_thread(_finish, artifact, adm, outcome, adm.role)

    body: dict[str, Any] = {
        "artifact": artifact,
        "role": adm.role,
        "upstream": outcome.kind,
        "detail": outcome.detail,
        "elapsed_ms": round(elapsed * 1000, 1),
        "breaker_effect": effect["effect"],
        "breaker_state": effect["state"],
        "pid": os.getpid(),
    }
    if outcome.payload is not None:
        body["metadata"] = outcome.payload

    headers = {"X-Breaker-Role": adm.role, "X-Worker-Pid": str(os.getpid())}
    if outcome.kind == "success":
        return JSONResponse(status_code=outcome.status or 200, content=body, headers=headers)
    return JSONResponse(status_code=502, content=body, headers=headers)


@app.get("/api/breakers")
async def breakers() -> dict[str, Any]:
    return await asyncio.to_thread(_snapshot)


def _snapshot() -> dict[str, Any]:
    now = time.time()
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM breakers ORDER BY artifact").fetchall()
        items = []
        for row in rows:
            state, opened_at = effective_state(row, now)
            remaining = (
                max(0.0, COOLDOWN - (now - opened_at)) if state == OPEN else 0.0
            )
            items.append(
                {
                    "artifact": row["artifact"],
                    "state": state,
                    "failures": row["failures"],
                    "opened_at": round(row["opened_at"], 3),
                    "cooldown_remaining": round(remaining, 3),
                    "probe_gen": row["probe_gen"],
                    "probe_holder": row["probe_holder"],
                    "epoch": row["epoch"],
                    "last_error": row["last_error"],
                }
            )
        events = [
            dict(r)
            for r in conn.execute(
                "SELECT ts, artifact, kind, detail FROM events ORDER BY id DESC LIMIT 40"
            ).fetchall()
        ]
    finally:
        conn.close()
    return {
        "now": now,
        "cooldown": COOLDOWN,
        "threshold": FAILURE_THRESHOLD,
        "timeout": REQUEST_TIMEOUT,
        "breakers": items,
        "events": events,
        "gateway_upstream": get_gateway_hits(),
        "pid": os.getpid(),
    }


@app.post("/api/reset")
async def reset() -> dict[str, Any]:
    await asyncio.to_thread(_reset)
    return {"ok": True}


def _reset() -> None:
    with write_tx() as conn:
        conn.execute("DELETE FROM breakers")
        conn.execute("DELETE FROM events")
        conn.execute("UPDATE upstream_stats SET hits = 0, hits_by_mode = '{}' WHERE id = 1")
        log_event(conn, "*", "reset")


# -- control-plane proxy to the example upstream ----------------------------


async def _proxy(method: str, path: str, payload: Any = None) -> JSONResponse:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            resp = await client.request(method, f"{UPSTREAM_URL}{path}", json=payload)
        try:
            content = resp.json()
        except ValueError:
            content = {"raw": resp.text[:1000]}
        return JSONResponse(status_code=resp.status_code, content=content)
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)[:300]})


@app.get("/api/upstream-mode")
async def get_upstream_mode() -> JSONResponse:
    return await _proxy("GET", "/control/mode")


@app.post("/api/upstream-mode")
async def set_upstream_mode(request: Request) -> JSONResponse:
    payload = await request.json()
    return await _proxy(
        "POST",
        "/control/mode",
        {"mode": payload.get("mode"), "delay": payload.get("delay")},
    )


@app.get("/api/upstream-stats")
async def upstream_stats() -> JSONResponse:
    return await _proxy("GET", "/control/stats")


@app.post("/api/upstream-stats/reset")
async def reset_upstream_stats() -> JSONResponse:
    return await _proxy("POST", "/control/reset")


@app.post("/api/upstream-script")
async def set_upstream_script(request: Request) -> JSONResponse:
    """Install scripted upstream responses (used by the automated tests)."""
    payload = await request.json()
    return await _proxy("POST", "/control/script", payload)


# -- dependency locker ------------------------------------------------------


@app.get("/api/lock/catalog")
async def lock_catalog(revision: Optional[int] = None) -> JSONResponse:
    """Return one catalog revision (default: the current one)."""
    try:
        snap = (
            CATALOG_STORE.get_revision(revision)
            if revision is not None
            else CATALOG_STORE.current_revision()
        )
    except sqlite3.Error as exc:
        return JSONResponse(status_code=503,
                            content={"error": "catalog_store_unavailable", "detail": str(exc)[:200]})
    if snap is None:
        return JSONResponse(status_code=404,
                            content={"error": "revision_not_found", "revision": revision})
    return JSONResponse(content=_catalog_payload(snap))


@app.get("/api/lock/revisions")
async def lock_revisions() -> JSONResponse:
    """List every retained catalog revision (old revisions stay readable)."""
    try:
        revisions = CATALOG_STORE.list_revisions()
    except sqlite3.Error as exc:
        return JSONResponse(status_code=503,
                            content={"error": "catalog_store_unavailable", "detail": str(exc)[:200]})
    current = revisions[-1]["id"] if revisions else None
    return JSONResponse(content={"revisions": revisions, "current_revision": current})


@app.post("/api/lock/catalog")
async def lock_replace_catalog(request: Request) -> JSONResponse:
    """Atomically replace the whole catalog.

    The document is fully validated before any write and the insert is one
    transaction, so an invalid document or a failed write leaves the active
    revision untouched.  A successful replacement always appends a new
    revision; every old revision is retained.
    """
    try:
        doc = await request.json()
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "invalid_json",
                                                      "detail": "request body must be a JSON document"})
    try:
        revision_id = await asyncio.to_thread(CATALOG_STORE.replace, doc)
    except CatalogError as exc:
        current = CATALOG_STORE.current_revision()
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_catalog",
                "detail": str(exc),
                "active_revision_unchanged": current["id"] if current else None,
            },
        )
    except sqlite3.Error as exc:
        return JSONResponse(status_code=503,
                            content={"error": "catalog_store_unavailable", "detail": str(exc)[:200]})
    snap = CATALOG_STORE.get_revision(revision_id)
    return JSONResponse(status_code=201, content=_catalog_payload(snap))


@app.get("/api/lock/sample-catalog/{sample}")
async def lock_sample_catalog(sample: str) -> JSONResponse:
    """Return a bundled sample catalog document for the replace-directory demo.

    The document is only returned for editing in the browser; it is not stored
    until the user explicitly POSTs it to ``/api/lock/catalog``.
    """
    samples = {"v2": BASE_DIR / "seed_catalogs" / "lock-demo-v2.json"}
    path = samples.get(sample)
    if path is None or not path.is_file():
        return JSONResponse(status_code=404, content={"error": "sample_not_found",
                                                      "sample": sample})
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        return JSONResponse(status_code=500, content={"error": "sample_unreadable",
                                                      "detail": str(exc)[:200]})
    return JSONResponse(content={"catalog": doc, "sample": sample})


def _catalog_payload(snap: dict[str, Any]) -> dict[str, Any]:
    doc = snap["document"]
    return {
        "revision": snap["id"],
        "created_at": round(snap["created_at"], 3),
        "doc_digest": snap["doc_digest"],
        "catalog_id": doc.get("catalog_id"),
        "schema": doc.get("schema"),
        "artifact_count": len(doc.get("artifacts", [])),
        "version_count": sum(len(a.get("versions", [])) for a in doc.get("artifacts", [])),
        "catalog": doc,
    }


@app.post("/api/lock/solve")
async def lock_solve(request: Request) -> JSONResponse:
    """Pin the current catalog revision, solve, then verify metadata.

    The revision is captured before the search starts; a catalog replacement
    arriving while the solve is in flight cannot mix new versions into the
    running solve and only affects later solves.  ``query_failed`` (breaker
    open / upstream error / 404 / digest mismatch) is distinct from
    ``unsat`` (no compatible combination exists in the pinned catalog).
    """
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    root = payload.get("root")
    allowed = payload.get("allowed_versions")
    try:
        root, allowed = locker.validate_solve_request(root, allowed)
    except CatalogError as exc:
        return JSONResponse(status_code=400, content={"error": "invalid_request", "detail": str(exc)})

    try:
        snapshot = CATALOG_STORE.current_revision()
    except sqlite3.Error as exc:
        return JSONResponse(status_code=503,
                            content={"error": "catalog_store_unavailable", "detail": str(exc)[:200]})
    if snapshot is None:
        return JSONResponse(status_code=409,
                            content={"error": "catalog_unavailable",
                                     "detail": "no catalog revision has been installed yet"})

    async def fetcher(name: str, version: str) -> dict[str, Any]:
        return await breaker_guarded_lookup(name, version)

    try:
        result = await locker.solve(snapshot, root, allowed, fetcher)
    except CatalogError as exc:
        return JSONResponse(status_code=400, content={"error": "invalid_request", "detail": str(exc)})

    # All three solver statuses (sat / unsat / query_failed) are successful
    # HTTP responses: the request itself worked, the status field carries the
    # distinction.  Transport-level problems are answered above.
    return JSONResponse(status_code=200, content=result)


# -- web UI ----------------------------------------------------------------


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/lock")
async def lock_page() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "lock.html")


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
