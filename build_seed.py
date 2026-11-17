"""Build the sample catalogs and per-version metadata tree used by the
dependency-locker demo.

Outputs (all content-addressable, deterministic):

* ``versioned_artifacts/<artifact>/<version>.json`` -- per-version metadata
  served by ``upstream.py``.  ``sha256`` is the SHA-256 of the canonical
  metadata body *excluding* the ``sha256`` field itself, so the value can be
  verified without a self-reference problem.
* ``seed_catalogs/lock-demo.json`` -- the catalog installed as revision 1 on
  first startup (diamond + greedy trap + cycle + unsatisfiable samples).
* ``seed_catalogs/lock-demo-v2.json`` -- a full-replacement catalog used by
  the "swap directory" demo; it intentionally changes several versions.
* ``seed_data.py`` -- the initial catalog embedded into the gateway image so
  the database can be seeded without mounting the JSON files.

Run:  python3 build_seed.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
# One metadata tree per catalog revision: a full-replacement catalog may
# change a version's metadata/digest, so revisions must not share files.
ART_TREES = {
    1: BASE / "versioned_artifacts" / "v1",
    2: BASE / "versioned_artifacts" / "v2",
}
CAT_DIR = BASE / "seed_catalogs"

GROUPS = {
    "example-app": "com.example",
    "web-console": "com.example",
    "core": "com.example",
    "http-client": "com.example",
    "json-codec": "com.example",
    "shared-lib": "com.example",
    "plugin-a": "com.example",
    "legacy-config": "com.example",
}

# version -> (packaging, size, license, deps[(name, allowed_versions)])
SPECS: dict[str, dict[str, tuple]] = {
    "example-app": {
        # Greedy trap: the catalog lists 3.1.0 before 3.0.0, but 3.1.0 pulls
        # json-codec 2.0.0 while core 2.0.0 (the only allowed core) requires
        # json-codec 1.4.0.  A first-pick solver dead-ends; backtracking onto
        # http-client 3.0.0 yields a complete manifest.
        "2.0.0": ("jar", 1_843_200, "Apache-2.0",
                  [("core", ["2.0.0"]), ("http-client", ["3.1.0", "3.0.0"])]),
        "1.9.0": ("jar", 1_810_000, "Apache-2.0",
                  [("core", ["1.9.0"]), ("http-client", ["2.4.0", "3.0.0"])]),
        "1.8.0": ("jar", 1_755_400, "Apache-2.0",
                  [("core", ["1.9.0"]), ("http-client", ["2.4.0"])]),
    },
    "web-console": {
        "1.2.0": ("zip", 920_000, "Apache-2.0", [("http-client", ["3.0.0", "3.1.0"])]),
        "1.1.0": ("zip", 880_000, "Apache-2.0", [("http-client", ["2.4.0", "3.0.0"])]),
    },
    "core": {
        # Pins json-codec 1.4.0, which clashes with http-client 3.1.0's
        # json-codec 2.0.0 requirement -- the conflict that forces backtracking.
        "2.0.0": ("jar", 640_000, "Apache-2.0",
                  [("json-codec", ["1.4.0"]), ("shared-lib", ["2.0.0"])]),
        "1.9.0": ("jar", 610_000, "Apache-2.0",
                  [("json-codec", ["1.4.0", "2.0.0"]), ("shared-lib", ["1.9.0", "2.0.0"])]),
    },
    "http-client": {
        "3.1.0": ("jar", 410_000, "MIT", [("json-codec", ["2.0.0"])]),
        "3.0.0": ("jar", 398_000, "MIT",
                  [("json-codec", ["1.4.0", "2.0.0"]), ("shared-lib", ["2.0.0"])]),
        "2.4.0": ("jar", 355_000, "MIT", [("json-codec", ["1.4.0"])]),
    },
    "json-codec": {
        "2.0.0": ("jar", 220_000, "MIT", []),
        "1.4.0": ("jar", 205_000, "MIT", []),
    },
    "shared-lib": {
        "2.0.0": ("jar", 528_000, "MIT", []),
        "1.9.0": ("jar", 524_288, "MIT", []),
    },
    "plugin-a": {
        "1.0.0": ("jar", 96_000, "MIT", [("legacy-config", ["0.9.0"])]),
    },
    "legacy-config": {
        "0.9.0": ("jar", 42_000, "EPL-2.0", [("plugin-a", ["1.0.0"])]),  # cycle
    },
}

# A version whose metadata file is never written, so the gateway's breaker
# query for it ends at the upstream 404 (demo for "query failure vs unsat").
MISSING_METADATA = ("legacy-config", "0.8.0")

# Second revision: several versions change; example-app keeps the same
# coordinates but its 2.0.0 deps move to allow http-client 3.1.0 only, and
# core gains 2.1.0.  Every rebuilt metadata gets a different digest.
SPECS_V2_ADDITIONS: dict[str, dict[str, tuple]] = {
    "example-app": {
        "2.0.0": ("jar", 1_844_001, "Apache-2.0",
                  [("core", ["2.1.0", "2.0.0"]), ("http-client", ["3.1.0"])]),
        "1.9.0": ("jar", 1_810_555, "Apache-2.0",
                  [("core", ["1.9.0"]), ("http-client", ["3.0.0"])]),
    },
    "core": {
        "2.1.0": ("jar", 655_000, "Apache-2.0",
                  [("json-codec", ["2.0.0"]), ("shared-lib", ["2.0.0"])]),
    },
    "http-client": {
        "3.1.0": ("jar", 412_300, "MIT", [("json-codec", ["2.0.0"]),
                                          ("shared-lib", ["2.0.0"])]),
    },
    "json-codec": {
        "2.0.0": ("jar", 224_000, "MIT", []),
    },
    "shared-lib": {
        "2.0.0": ("jar", 530_100, "MIT", []),
    },
}


def canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_of(body_without_sha: dict) -> str:
    return hashlib.sha256(canonical(body_without_sha)).hexdigest()


def build_specs(v2: bool) -> dict[str, dict[str, tuple]]:
    specs = {name: dict(vers) for name, vers in SPECS.items()}
    if v2:
        for name, vers in SPECS_V2_ADDITIONS.items():
            specs[name].update(vers)
    return specs


def write_metadata_and_catalog(v2: bool) -> dict:
    specs = build_specs(v2)
    art_tree = ART_TREES[2 if v2 else 1]
    artifacts = []
    for name in sorted(specs):
        versions = []
        for version, (packaging, size, license_, deps) in specs[name].items():
            dep_spec = [{"name": d[0], "allowed_versions": list(d[1])} for d in deps]
            body_no_sha = {
                "group": GROUPS[name],
                "name": name,
                "version": version,
                "packaging": packaging,
                "size_bytes": size,
                "license": license_,
                "dependencies": dep_spec,
            }
            sha = digest_of(body_no_sha)
            body = dict(body_no_sha)
            body["sha256"] = sha
            if (name, version) != MISSING_METADATA:
                out = art_tree / name / f"{version}.json"
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            versions.append({
                "version": version,
                "sha256": sha,
                "dependencies": dep_spec,
            })
        artifacts.append({"name": name, "versions": versions})
    catalog = {
        "schema": "artifact-catalog/v1",
        "catalog_id": "lock-demo-v2" if v2 else "lock-demo",
        "artifacts": artifacts,
    }
    return catalog


def main() -> None:
    # Fresh trees so removed versions do not linger between rebuilds.
    for tree in ART_TREES.values():
        if tree.exists():
            for p in sorted(tree.rglob("*.json"), reverse=True):
                p.unlink()
    CAT_DIR.mkdir(parents=True, exist_ok=True)

    catalog_v1 = write_metadata_and_catalog(v2=False)
    catalog_v2 = write_metadata_and_catalog(v2=True)

    for catalog, fname in ((catalog_v1, "lock-demo.json"),
                           (catalog_v2, "lock-demo-v2.json")):
        doc = canonical_catalog(catalog)
        (CAT_DIR / fname).write_text(json.dumps(doc, indent=2) + "\n")

    # Embedded initial catalog for the gateway image / first-run seeding.
    seed_module = [
        '"""Embedded initial artifact catalog (generated by build_seed.py)."""',
        "",
        "import json",
        "",
        f"INITIAL_CATALOG = json.loads({json.dumps(json.dumps(catalog_v1))})",
        "",
    ]
    (BASE / "seed_data.py").write_text("\n".join(seed_module))

    n_art = len(catalog_v1["artifacts"])
    n_ver = sum(len(a["versions"]) for a in catalog_v1["artifacts"])
    print(f"v1: {n_art} artifacts, {n_ver} versions -> {CAT_DIR/'lock-demo.json'}")
    n_ver2 = sum(len(a["versions"]) for a in catalog_v2["artifacts"])
    print(f"v2: {len(catalog_v2['artifacts'])} artifacts, {n_ver2} versions -> {CAT_DIR/'lock-demo-v2.json'}")
    print("metadata trees:", ", ".join(str(t) for t in ART_TREES.values()))


def canonical_catalog(catalog: dict) -> dict:
    """Round-trip through a stable structure so stored docs are deterministic."""
    return json.loads(json.dumps(catalog, sort_keys=True))


if __name__ == "__main__":
    main()
