import os
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.models import User

client = TestClient(app)

def get_token_for_role(role: str) -> str:
    user = User(username=f"test_{role}", role=role, disabled=False)
    return create_access_token(user)

def test_routes_registered_without_error():
    # If backend.main imports successfully without FastAPIError, this test passes
    assert app is not None

def test_unauthenticated_requests_return_401():
    response = client.get("/api/v1/assessments/")
    assert response.status_code == 401
    
    response = client.post("/api/v1/assessments/import", json={})
    assert response.status_code == 401

def test_administrator_can_import():
    token = get_token_for_role("administrator")
    # It might return 413, 422, etc, but shouldn't return 401 or 403
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code not in (401, 403)

def test_security_analyst_can_import():
    token = get_token_for_role("security_analyst")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code not in (401, 403)

def test_incident_responder_cannot_import():
    token = get_token_for_role("incident_responder")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

def test_read_only_auditor_cannot_import():
    token = get_token_for_role("read_only_auditor")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

def test_authenticated_roles_can_read():
    for role in ["administrator", "security_analyst", "incident_responder", "read_only_auditor"]:
        token = get_token_for_role(role)
        response = client.get("/api/v1/assessments/", headers={"Authorization": f"Bearer {token}"})
        # Should succeed or return empty list
        assert response.status_code == 200

def test_existing_login_flow_works():
    # Attempting a login with invalid credentials should return 401, verifying route exists
    response = client.post("/api/v1/auth/login", data={"username": "fake", "password": "fake"})
    assert response.status_code == 401

def test_only_one_portable_workflow_remains():
    workflows_dir = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows")
    files = os.listdir(workflows_dir)
    # Check that build-portable.yml is empty or deleted, and portable-build.yml exists
    if "build-portable.yml" in files:
        with open(os.path.join(workflows_dir, "build-portable.yml")) as f:
            content = f.read().strip()
            assert content == "# Deleted per instructions to deduplicate workflows" or len(content) == 0
    assert "portable-build.yml" in files

def test_retained_workflow_uses_correct_artifact_action():
    workflow_path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "portable-build.yml")
    with open(workflow_path, "r") as f:
        content = f.read()
    
    assert "actions/upload-artifact@v4.6.2" in content
    assert "actions/upload-artifact@v3" not in content
    assert "actions/upload-artifact@v1" not in content
    assert "actions/upload-artifact@v2" not in content
