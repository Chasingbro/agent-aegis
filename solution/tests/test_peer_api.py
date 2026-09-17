"""P0 服务契约：状态可读、HTTP 不触发扫描、原始 peer 工件不外发。"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

SOLUTION = Path(__file__).resolve().parent.parent
OUT = SOLUTION / "out"
sys.path.insert(0, str(SOLUTION))


def test_peer_status_endpoint_is_read_only(monkeypatch):
    from fusion import peer_runner
    from server.app import app

    expected = {"status": "ready", "job_id": "fixture"}
    monkeypatch.setattr(peer_runner, "read_peer_status", lambda: expected)
    response = TestClient(app).get("/api/peer/status")
    assert response.status_code == 200
    assert response.json() == expected


def test_dashboard_and_legacy_apis_are_redacted():
    if not (OUT / "graph.json").exists() or not (OUT / "bom.json").exists():
        pytest.skip("requires generated solution/out artifacts")
    from server.app import app

    client = TestClient(app)
    for endpoint in ("/api/dashboard", "/api/graph", "/api/bom", "/api/risks", "/api/baseline"):
        response = client.get(endpoint)
        assert response.status_code == 200, endpoint
        text = response.text
        assert "change-me-weak-secret" not in text
        assert "svc-root-all-access" not in text
    judge = client.post("/api/judge", json=[{
        "trace_id": "redact", "server": "notes-sync", "tool": "sync_note",
        "args": {"note": "JWT_SECRET=change-me-weak-secret"},
    }])
    assert judge.status_code == 200
    assert "change-me-weak-secret" not in judge.text
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["meta"]["schema_version"] == "fusion-dashboard-v1"
    assert dashboard["quality"]["invariants"]["all_edge_endpoints_resolved"]


def test_artifact_archive_excludes_raw_peer_files_and_redacts_content():
    from server.app import app

    response = TestClient(app).get("/api/artifacts")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert all("peer" not in Path(name).parts for name in archive.namelist())
        content = b"\n".join(archive.read(name) for name in archive.namelist())
        assert b"change-me-weak-secret" not in content
        assert b"svc-root-all-access" not in content
