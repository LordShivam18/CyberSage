import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import User
from backend.auth import create_user, create_access_token

# Configure in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    # Create the database and tables
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    
    # Create test users
    create_user(session, "admin_user", "password1234", "administrator")
    create_user(session, "analyst_user", "password1234", "security_analyst")
    create_user(session, "responder_user", "password1234", "incident_responder")
    create_user(session, "auditor_user", "password1234", "read_only_auditor")
    session.commit()
    
    try:
        yield session
    finally:
        session.close()
        # Drop all tables after the test
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

def get_token_for_user(db_session, username: str) -> str:
    user = db_session.query(User).filter(User.username == username).first()
    return create_access_token(user)

def test_routes_registered_without_error(client):
    assert app is not None

def test_unauthenticated_requests_return_401(client):
    response = client.get("/api/v1/assessments/")
    assert response.status_code == 401
    
    response = client.post("/api/v1/assessments/import", json={})
    assert response.status_code == 401

def test_administrator_can_import(client, db_session):
    token = get_token_for_user(db_session, "admin_user")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422

def test_security_analyst_can_import(client, db_session):
    token = get_token_for_user(db_session, "analyst_user")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422

def test_incident_responder_cannot_import(client, db_session):
    token = get_token_for_user(db_session, "responder_user")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

def test_read_only_auditor_cannot_import(client, db_session):
    token = get_token_for_user(db_session, "auditor_user")
    response = client.post("/api/v1/assessments/import", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

def test_authenticated_roles_can_read(client, db_session):
    for username in ["admin_user", "analyst_user", "responder_user", "auditor_user"]:
        token = get_token_for_user(db_session, username)
        response = client.get("/api/v1/assessments/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

def test_existing_login_flow_works(client):
    # Valid credentials
    response = client.post("/api/v1/auth/login", json={"username": "admin_user", "password": "password1234"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    
    # Invalid password
    response = client.post("/api/v1/auth/login", json={"username": "admin_user", "password": "wrong_password"})
    assert response.status_code == 401

def test_only_one_portable_workflow_remains():
    workflows_dir = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows")
    files = os.listdir(workflows_dir)
    assert "build-portable.yml" not in files
    assert "portable-build.yml" in files

def test_retained_workflow_uses_correct_artifact_action():
    workflow_path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "portable-build.yml")
    with open(workflow_path, "r") as f:
        content = f.read()
    
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in content
    assert "actions/upload-artifact@v4.6.2" not in content
    assert "actions/upload-artifact@v3" not in content
    assert "actions/upload-artifact@v2" not in content
    assert "actions/upload-artifact@v1" not in content
