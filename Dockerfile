FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py upstream.py locker.py seed_data.py build_seed.py ./
COPY static ./static
COPY artifacts ./artifacts
COPY versioned_artifacts ./versioned_artifacts
COPY seed_catalogs ./seed_catalogs

# The SQLite database lives on a named volume shared by both workers (and kept
# across container restarts).
ENV GATEWAY_DB=/data/breaker.db
# The example upstream serves per-version metadata from the revision-1 tree.
ENV ARTIFACT_TREE_ROOT=/srv/versioned_artifacts/v1
RUN mkdir -p /data

EXPOSE 8000 9000
