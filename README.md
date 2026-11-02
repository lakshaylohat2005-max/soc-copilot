# SOC Copilot

> AI-Powered Mini Security Operations Center for Real-Time Threat Ingestion, Detection, Correlation, and Autonomous Triage.

Built for cybersecurity hackathons, **SOC Copilot** ingests heterogeneous security logs, applies detection rules mapped to the MITRE ATT&CK framework, correlates alerts into multi-stage incidents, uses Google Gemini to generate incident narratives and response recommendations, and enables 1-click active response actions directly from a live dashboard.

---

## Architecture Flow

```
Logs (Simulator / Syslog)
  └─► Ingestion & Parsing (ECS Normalization)
        └─► Rule Engine (YAML Rules mapped to MITRE ATT&CK)
              └─► Alert Correlation Engine (Sliding Window & Entity Graph)
                    └─► LLM Triage (Gemini Incident Narrative & Playbooks)
                          └─► Response Actions (Block IP, Disable User, Ticket)
                                └─► Live Dashboard (React + WebSockets)
```

For complete pipeline specifications, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy 2.0, SQLite, WebSockets, Google Generative AI SDK
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons
- **Detection & Data**: YAML Detection Rules, MITRE ATT&CK Enterprise Matrix subset
- **Simulator**: Python synthetic attack log generator (SSH Brute Force, SQL Injection, Privilege Escalation)

---

## Quickstart

### 1. Backend Setup

```bash
cd backend
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
cp ../.env.example .env
# Edit .env and supply your GEMINI_API_KEY

uvicorn app.main:app --reload
```

Backend will be available at:
- **API**: http://localhost:8000
- **Health Check**: http://localhost:8000/health
- **Swagger Docs**: http://localhost:8000/docs

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend will run at http://localhost:5173.

### 3. Log Simulator

```bash
cd simulator
python generator.py --scenario brute_force --target http://localhost:8000/api/logs/ingest
```

