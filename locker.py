"""Dependency locker: versioned artifact catalog + backtracking solver.

Why this module exists
----------------------
Release engineers need a *compatible* install manifest before updating an
application.  Given a root artifact and the versions it is allowed to use,
the locker must find one version for every transitive artifact such that
every dependency edge is satisfied.  A greedy first-pick can dead-end even
when a solution exists (the classic "diamond with a newer branch"), so the
solver performs full chronological backtracking and only reports
``unsat`` after the whole search space is exhausted.

Catalog semantics
-----------------
* A catalog document holds at most ``MAX_ARTIFACTS`` artifacts and
  ``MAX_VERSIONS_PER_ARTIFACT`` versions per artifact.  Every version carries
  a SHA-256 digest and, for each dependency, the set of allowed versions.
* Version matching is exact string equality -- no range/range parsing.
* Replacement is whole-document only.  The document is fully validated
  *before* any write and the insert happens in a single ``BEGIN IMMEDIATE``
  transaction, so an invalid catalog or a failed replacement never mutates
  the previously active revision.  Every old revision is retained.
* Each solve pins the catalog revision that is current when it starts.
  A replacement performed while a solve is in flight only affects later
  solves; the running solve keeps reading its pinned snapshot.

Query-failure vs. no-solution
-----------------------------
Catalog data alone decides satisfiability.  Once a complete assignment
exists, per-version metadata is fetched *through the existing circuit
breaker* (the fetcher is injected so the HTTP/breaker layer stays in
``app.py``).  A failed metadata query (breaker open, upstream 5xx/timeout,
404, digest mismatch) yields ``query_failed`` -- never ``unsat`` -- so the
two failure modes stay distinguishable.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections import deque
from typing import Any, Awaitable, Callable, Optional

MAX_ARTIFACTS = 12
MAX_VERSIONS_PER_ARTIFACT = 4
MAX_ROOT_ALLOWED = MAX_VERSIONS_PER_ARTIFACT
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEARCH_NODE_LIMIT = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS catalog_revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    doc_digest TEXT NOT NULL,
    document   TEXT NOT NULL
);
"""


class CatalogError(ValueError):
    """Raised when a replacement catalog document fails validation."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise CatalogError(message)


def validate_catalog(doc: Any) -> dict[str, Any]:
    """Validate a catalog document and return a normalised copy.

    Raises ``CatalogError`` with a human-readable reason on any problem; the
    caller must not touch the stored revision in that case.
    """
    _require(isinstance(doc, dict), "catalog must be a JSON object")
    schema = doc.get("schema")
    _require(isinstance(schema, str) and schema, "catalog.schema must be a non-empty string")
    artifacts = doc.get("artifacts")
    _require(isinstance(artifacts, list), "catalog.artifacts must be a list")
    _require(
        0 < len(artifacts) <= MAX_ARTIFACTS,
        f"catalog must contain 1..{MAX_ARTIFACTS} artifacts, got {len(artifacts) if isinstance(artifacts, list) else 0}",
    )

    seen_names: set[str] = set()
    clean_artifacts: list[dict[str, Any]] = []
    for idx, art in enumerate(artifacts):
        where = f"artifacts[{idx}]"
        _require(isinstance(art, dict), f"{where} must be an object")
        name = art.get("name")
        _require(isinstance(name, str) and name.strip(), f"{where}.name must be a non-empty string")
        name = name.strip()
        _require(name not in seen_names, f"duplicate artifact name: {name}")
        seen_names.add(name)

        versions = art.get("versions")
        _require(isinstance(versions, list) and versions, f"{where}.versions must be a non-empty list")
        _require(
            len(versions) <= MAX_VERSIONS_PER_ARTIFACT,
            f"{name}: at most {MAX_VERSIONS_PER_ARTIFACT} versions allowed, got {len(versions)}",
        )
        seen_versions: set[str] = set()
        clean_versions: list[dict[str, Any]] = []
        for v_idx, ver in enumerate(versions):
            vwhere = f"{where}.versions[{v_idx}]"
            _require(isinstance(ver, dict), f"{vwhere} must be an object")
            version = ver.get("version")
            _require(isinstance(version, str) and version.strip(), f"{vwhere}.version must be a non-empty string")
            version = version.strip()
            _require(version not in seen_versions, f"{name}: duplicate version {version}")
            seen_versions.add(version)

            sha = ver.get("sha256")
            _require(
                isinstance(sha, str) and bool(SHA256_RE.match(sha.strip().lower())),
                f"{name}:{version}: sha256 must be 64 lowercase hex characters",
            )
            sha = sha.strip().lower()

            deps = ver.get("dependencies", [])
            _require(isinstance(deps, list), f"{vwhere}.dependencies must be a list")
            seen_deps: set[str] = set()
            clean_deps: list[dict[str, Any]] = []
            for d_idx, dep in enumerate(deps):
                dwhere = f"{vwhere}.dependencies[{d_idx}]"
                _require(isinstance(dep, dict), f"{dwhere} must be an object")
                dname = dep.get("name")
                _require(isinstance(dname, str) and dname.strip(), f"{dwhere}.name must be a non-empty string")
                dname = dname.strip()
                _require(dname not in seen_deps, f"{name}:{version}: duplicate dependency {dname}")
                seen_deps.add(dname)
                allowed = dep.get("allowed_versions")
                _require(isinstance(allowed, list) and allowed, f"{dwhere}.allowed_versions must be a non-empty list")
                clean_allowed: list[str] = []
                for av in allowed:
                    _require(isinstance(av, str) and av.strip(), f"{dwhere}: every allowed version must be a non-empty string")
                    av = av.strip()
                    if av not in clean_allowed:
                        clean_allowed.append(av)
                clean_deps.append({"name": dname, "allowed_versions": clean_allowed})
            clean_versions.append({"version": version, "sha256": sha, "dependencies": clean_deps})
        clean_artifacts.append({"name": name, "versions": clean_versions})

    return {
        "schema": schema,
        "catalog_id": str(doc.get("catalog_id") or "").strip() or None,
        "artifacts": clean_artifacts,
    }


def canonical_doc(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_document(doc: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_doc(doc)).hexdigest()


# Fields the example upstream injects when serving a file; they are transport
# annotations rather than version metadata and must not enter digest checks.
SERVED_ANNOTATION_FIELDS = ("artifact", "source_file", "source_mtime")


def digest_metadata_body(metadata: dict[str, Any]) -> str:
    """SHA-256 of the served metadata excluding transport annotations.

    The digest covers the version metadata as authored (including everything
    except the self-referential ``sha256``); fields added by the directory
    service when it serves a file are stripped first.
    """
    body = {
        k: v
        for k, v in metadata.items()
        if k != "sha256" and k not in SERVED_ANNOTATION_FIELDS
    }
    return hashlib.sha256(canonical_doc(body)).hexdigest()


# ---------------------------------------------------------------------------
# Revision store
# ---------------------------------------------------------------------------


class CatalogStore:
    """Versioned catalog storage inside the gateway's SQLite database."""

    def __init__(self, connect_fn: Callable[[], sqlite3.Connection],
                 write_tx_fn: Callable[[], Any]):
        self._connect = connect_fn
        self._write_tx = write_tx_fn

    def init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    def seed_if_empty(self, initial_doc: dict[str, Any]) -> Optional[int]:
        """Install the bundled catalog as the first revision on first startup.

        The emptiness check and the insert run inside one ``BEGIN IMMEDIATE``
        transaction, so two gateway workers racing at startup cannot each
        seed their own revision.  Returns the new revision id, or ``None`` if
        a revision already existed.
        """
        clean = validate_catalog(initial_doc)
        digest = digest_document(clean)
        payload = json.dumps(clean, sort_keys=True)
        with self._write_tx() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM catalog_revisions").fetchone()
            if row["n"] > 0:
                return None
            cur = conn.execute(
                "INSERT INTO catalog_revisions (created_at, doc_digest, document) VALUES (?, ?, ?)",
                (time.time(), digest, payload),
            )
            return int(cur.lastrowid)

    def replace(self, raw_doc: Any) -> int:
        """Validate then atomically append a new revision.

        Validation happens before the write transaction; a failed call leaves
        every existing revision untouched.  Returns the new revision id.
        """
        clean = validate_catalog(raw_doc)
        digest = digest_document(clean)
        payload = json.dumps(clean, sort_keys=True)
        with self._write_tx() as conn:
            cur = conn.execute(
                "INSERT INTO catalog_revisions (created_at, doc_digest, document) VALUES (?, ?, ?)",
                (time.time(), digest, payload),
            )
            return int(cur.lastrowid)

    def list_revisions(self) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, created_at, doc_digest FROM catalog_revisions ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def current_revision(self) -> Optional[dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, created_at, doc_digest, document FROM catalog_revisions "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            return {
                "id": row["id"],
                "created_at": row["created_at"],
                "doc_digest": row["doc_digest"],
                "document": json.loads(row["document"]),
            }
        finally:
            conn.close()

    def get_revision(self, revision_id: int) -> Optional[dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, created_at, doc_digest, document FROM catalog_revisions WHERE id = ?",
                (revision_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "id": row["id"],
                "created_at": row["created_at"],
                "doc_digest": row["doc_digest"],
                "document": json.loads(row["document"]),
            }
        finally:
            conn.close()


def build_index(document: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """artifact name -> version -> version record (with sha256/dependencies)."""
    index: dict[str, dict[str, dict[str, Any]]] = {}
    for art in document["artifacts"]:
        index[art["name"]] = {v["version"]: v for v in art["versions"]}
    return index


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------


# A fetcher takes (name, version) and returns a result dict:
#   {"ok": True,  "metadata": {...}}
#   {"ok": False, "reason": "...", "detail": "...", "status": int|None}
Fetcher = Callable[[str, str], Awaitable[dict[str, Any]]]


def validate_solve_request(root: Any, allowed_versions: Any) -> tuple[str, list[str]]:
    if not isinstance(root, str) or not root.strip():
        raise CatalogError("root artifact name must be a non-empty string")
    root = root.strip()
    if not isinstance(allowed_versions, list) or not allowed_versions:
        raise CatalogError("allowed_versions must be a non-empty list of version strings")
    if len(allowed_versions) > MAX_ROOT_ALLOWED:
        raise CatalogError(f"at most {MAX_ROOT_ALLOWED} allowed versions for the root")
    clean: list[str] = []
    for av in allowed_versions:
        if not isinstance(av, str) or not av.strip():
            raise CatalogError("every allowed version must be a non-empty string")
        av = av.strip()
        if av not in clean:
            clean.append(av)
    return root, clean


def solve_constraints(
    index: dict[str, dict[str, dict[str, Any]]],
    root: str,
    root_allowed: list[str],
) -> dict[str, Any]:
    """Search every compatible assignment via chronological backtracking.

    Returns ``{"status": "sat", "assignment": {name: version}, ...}`` or an
    ``unsat`` result carrying human-readable reasons.  Dependency cycles are
    allowed: an edge pointing at an already assigned artifact is simply
    re-checked against the chosen version.
    """
    reasons: dict[tuple[str, str], int] = {}
    stats = {"nodes": 0, "backtracks": 0, "prunes": 0}

    def note_reason(kind: str, detail: str) -> None:
        key = (kind, detail)
        reasons[key] = reasons.get(key, 0) + 1

    if root not in index:
        note_reason("missing_artifact", f"root artifact '{root}' is not present in the catalog")
        return {"status": "unsat", "reasons": _reason_list(reasons), "stats": stats,
                "limit_hit": False}

    root_versions = index[root]
    root_domain = [v for v in root_allowed if v in root_versions]
    if not root_domain:
        note_reason(
            "no_allowed_version",
            f"root '{root}' has none of the requested versions {root_allowed}; "
            f"catalog offers {sorted(root_versions)}",
        )
        return {"status": "unsat", "reasons": _reason_list(reasons), "stats": stats,
                "limit_hit": False}

    # domains[name]: ordered candidate versions still worth trying.
    domains: dict[str, list[str]] = {root: root_domain}
    assignment: dict[str, str] = {}
    # Pending dependency edges (dependant -> dependency).  Edges are popped
    # when processed, so a cycle edge reaches an already-assigned target and
    # is simply re-validated against the chosen version.
    edges: deque[tuple[str, str, list[str]]] = deque()

    def backtrack() -> Optional[dict[str, str]]:
        stats["nodes"] += 1
        if stats["nodes"] > SEARCH_NODE_LIMIT:
            return None

        # Process every pending edge.  An edge to an assigned artifact is a
        # pure constraint check (handles diamonds and cycles); an edge to an
        # unassigned artifact constrains/introduces its candidate domain.
        new_domains: dict[str, list[str]] = {}
        while edges:
            parent, dep_name, allowed = edges.popleft()
            if dep_name in assignment:
                if assignment[dep_name] not in allowed:
                    stats["prunes"] += 1
                    note_reason(
                        "version_conflict",
                        f"'{dep_name}' resolved to {assignment[dep_name]} but "
                        f"'{parent}' requires one of {allowed}",
                    )
                    return None
                continue
            if dep_name not in index:
                stats["prunes"] += 1
                note_reason(
                    "missing_artifact",
                    f"dependency '{dep_name}' (required by '{parent}') is not present in the catalog",
                )
                return None
            candidates = [v for v in index[dep_name] if v in allowed]
            if not candidates:
                stats["prunes"] += 1
                note_reason(
                    "no_allowed_version",
                    f"'{dep_name}' (required by '{parent}') has none of {allowed} "
                    f"in the catalog; catalog offers {sorted(index[dep_name])}",
                )
                return None
            if dep_name in new_domains:
                # Multiple incoming constraints: intersect (diamond case).
                new_domains[dep_name] = [
                    v for v in new_domains[dep_name] if v in candidates
                ]
            else:
                new_domains[dep_name] = candidates

        for name, dom in new_domains.items():
            if not dom:
                stats["prunes"] += 1
                note_reason(
                    "empty_domain",
                    f"no catalog version of '{name}' satisfies all incoming constraints",
                )
                return None
            if name not in domains:
                domains[name] = list(dom)
            else:
                domains[name] = [v for v in domains[name] if v in dom]

        unassigned = [name for name in domains if name not in assignment]
        if not unassigned:
            return dict(assignment)

        # MRV: branch on the most constrained artifact first, surfacing
        # conflicts early instead of discovering them at the leaves.  This is
        # what makes the search complete -- every candidate version is tried,
        # so a greedy first-pick dead-end cannot cause a false "unsat".
        name = min(unassigned, key=lambda n: (len(domains[n]), n))
        candidates = list(domains[name])
        if not candidates:
            note_reason("empty_domain", f"no candidate versions left for '{name}'")
            return None

        saved_assigned = set(assignment)
        saved_domains = {k: list(v) for k, v in domains.items()}
        saved_edges = list(edges)
        for version in candidates:
            assignment[name] = version
            for dep in index[name][version]["dependencies"]:
                edges.append((name, dep["name"], list(dep["allowed_versions"])))
            found = backtrack()
            if found is not None:
                return found
            stats["backtracks"] += 1
            # Undo the whole branch: restore edges/domains and remove every
            # assignment this branch added below ``name``.
            edges.clear()
            edges.extend(saved_edges)
            domains.clear()
            domains.update({k: list(v) for k, v in saved_domains.items()})
            for assigned_name in list(assignment):
                if assigned_name not in saved_assigned:
                    del assignment[assigned_name]
        return None

    solution = backtrack()
    if solution is None:
        return {
            "status": "unsat",
            "reasons": _reason_list(reasons),
            "stats": stats,
            "limit_hit": stats["nodes"] > SEARCH_NODE_LIMIT,
        }
    return {"status": "sat", "assignment": solution, "reasons": [], "stats": stats,
            "limit_hit": False}


def _reason_list(reasons: dict[tuple[str, str], int]) -> list[dict[str, Any]]:
    return [
        {"kind": kind, "detail": detail, "occurrences": count}
        for (kind, detail), count in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def ordered_manifest_names(index: dict[str, Any], root: str,
                           assignment: dict[str, str]) -> list[str]:
    """BFS from the root over the chosen versions, de-duplicated by name."""
    order: list[str] = []
    queued: set[str] = set()
    queue: deque[str] = deque([root])
    queued.add(root)
    while queue:
        name = queue.popleft()
        order.append(name)
        if name not in index:
            continue
        version = assignment.get(name)
        record = index[name].get(version) if version else None
        if record is None:
            continue
        for dep in record["dependencies"]:
            dname = dep["name"]
            if dname in assignment and dname not in queued:
                queued.add(dname)
                queue.append(dname)
    return order


async def solve(
    snapshot: dict[str, Any],
    root: str,
    allowed_versions: list[str],
    fetcher: Fetcher,
) -> dict[str, Any]:
    """Pin ``snapshot`` (taken at solve start), search, then verify metadata.

    The pinned revision id and digest are echoed back in every result, so a
    manifest always states which catalog revision it was computed against.
    """
    document = snapshot["document"]
    index = build_index(document)
    root, allowed_versions = validate_solve_request(root, allowed_versions)

    base = {
        "root": root,
        "allowed_versions": allowed_versions,
        "catalog_revision": snapshot["id"],
        "catalog_digest": snapshot["doc_digest"],
        "catalog_id": document.get("catalog_id"),
    }

    result = solve_constraints(index, root, allowed_versions)
    if result["status"] != "sat":
        return {**base, "status": "unsat", "reasons": result["reasons"],
                "search": result["stats"], "limit_hit": result["limit_hit"],
                "assignment": None, "manifest": None, "query_failures": []}

    assignment = result["assignment"]
    names = ordered_manifest_names(index, root, assignment)

    # Metadata verification happens only after a complete compatible
    # assignment exists, and goes through the circuit breaker.  Any failure
    # here is a query failure, distinct from "no solution".
    manifest: list[dict[str, Any]] = []
    query_failures: list[dict[str, Any]] = []
    for name in names:
        version = assignment[name]
        record = index[name][version]
        fetched = await fetcher(name, version)
        if not fetched.get("ok"):
            query_failures.append({
                "artifact": name,
                "version": version,
                "reason": fetched.get("reason", "query_failed"),
                "detail": fetched.get("detail", ""),
                "status": fetched.get("status"),
            })
            continue
        metadata = fetched["metadata"]
        served_sha = metadata.get("sha256") if isinstance(metadata, dict) else None
        recomputed = digest_metadata_body(metadata) if isinstance(metadata, dict) else None
        entry = {
            "artifact": name,
            "version": version,
            "catalog_sha256": record["sha256"],
            "metadata_sha256": served_sha,
            "digest_verified": bool(
                served_sha == record["sha256"] and recomputed == record["sha256"]
            ),
            "summary": _summary(metadata, name, version),
            "depends_on": [d["name"] for d in record["dependencies"]],
        }
        if not entry["digest_verified"]:
            query_failures.append({
                "artifact": name,
                "version": version,
                "reason": "digest_mismatch",
                "detail": (
                    f"catalog sha256={record['sha256']} "
                    f"served sha256={served_sha} recomputed={recomputed}"
                ),
                "status": None,
            })
        manifest.append(entry)

    if query_failures:
        return {**base, "status": "query_failed", "assignment": assignment,
                "manifest": manifest, "query_failures": query_failures,
                "reasons": [], "search": result["stats"], "limit_hit": False}

    return {**base, "status": "sat", "assignment": assignment, "manifest": manifest,
            "query_failures": [], "reasons": [], "search": result["stats"],
            "limit_hit": False}


def _summary(metadata: Any, name: str, version: str) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {"name": name, "version": version}
    keys = ("group", "name", "version", "packaging", "size_bytes", "license")
    return {k: metadata[k] for k in keys if k in metadata}
