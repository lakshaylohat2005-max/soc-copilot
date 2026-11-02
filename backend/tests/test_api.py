import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db import Base, get_db

# Use in-memory SQLite with StaticPool so all connections share the same memory instance
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_empty_collections(client):
    assert client.get("/api/logs").json() == []
    assert client.get("/api/alerts").json() == []
    assert client.get("/api/incidents").json() == []


def test_incident_404(client):
    res = client.get("/api/incidents/99999")
    assert res.status_code == 404
    assert res.json()["detail"] == "Incident with ID 99999 not found"


def test_create_and_read_log(client):
    payload = {
        "source": "web",
        "raw": "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1 200",
        "src_ip": "203.0.113.55",
        "user": None,
        "event_type": "sql_injection",
        "status": "blocked",
        "extra": {"waf_rule": "942100"}
    }
    create_res = client.post("/api/logs", json=payload)
    assert create_res.status_code == 201
    log_id = create_res.json()["id"]

    get_res = client.get(f"/api/logs?src_ip=203.0.113.55")
    assert get_res.status_code == 200
    logs = get_res.json()
    assert len(logs) == 1
    assert logs[0]["id"] == log_id
    assert logs[0]["extra"]["waf_rule"] == "942100"


def test_incident_with_alerts_and_actions(client):
    # 1. Create Log
    log_res = client.post("/api/logs", json={
        "source": "ssh",
        "raw": "Failed password for admin from 198.51.100.22",
        "src_ip": "198.51.100.22",
        "user": "admin",
        "event_type": "login_failed",
        "status": "failed",
        "extra": {}
    })
    log_id = log_res.json()["id"]

    # 2. Create Incident
    inc_res = client.post("/api/incidents", json={
        "title": "SSH Credential Access Attempt",
        "severity": "high",
        "status": "open",
        "src_ip": "198.51.100.22",
        "affected_users": ["admin"],
        "mitre_techniques": ["T1110.001"],
        "ai_summary": "Suspicious login failure burst.",
        "ai_recommendations": [{"action": "block_ip", "target": "198.51.100.22"}]
    })
    inc_id = inc_res.json()["id"]

    # 3. Create Alert linked to Incident
    alert_res = client.post("/api/alerts", json={
        "rule_id": "RULE-SSH-001",
        "rule_name": "SSH Brute Force",
        "severity": "high",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "mitre_tactic": "Credential Access",
        "src_ip": "198.51.100.22",
        "user": "admin",
        "description": "5 failed logins in 60s",
        "log_event_ids": [log_id],
        "incident_id": inc_id
    })
    assert alert_res.status_code == 201

    # 4. Fetch Incident Details
    detail_res = client.get(f"/api/incidents/{inc_id}")
    assert detail_res.status_code == 200
    incident = detail_res.json()
    assert incident["id"] == inc_id
    assert len(incident["alerts"]) == 1
    assert incident["alerts"][0]["rule_id"] == "RULE-SSH-001"
