# MAILSENTINEL - Backend Foundation

Backend service for MAILSENTINEL — an AI-powered Email Threat Detection & Forensic Intelligence Platform.

This foundation establishes the core FastAPI application, SQLAlchemy 2.x database session layer, Pydantic v2 configuration management, and initial API routing.

---

## Architecture Overview

- **Framework**: FastAPI (REST API)
- **Database**: PostgreSQL
- **ORM**: SQLAlchemy 2.x
- **Driver**: Psycopg 3 (`psycopg`)
- **Settings & Validation**: Pydantic v2 + `pydantic-settings`
- **Frontend**: React + TypeScript + Tailwind (located in `/frontend`)

---

## Directory Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application & /health endpoint
│   ├── api/
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py
│   │       └── router.py    # Versioned v1 API router
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py        # Pydantic v2 environment settings
│   ├── db/
│   │   ├── __init__.py
│   │   ├── base.py          # SQLAlchemy 2.x DeclarativeBase
│   │   └── session.py       # Engine and sessionmaker factory
│   ├── models/
│   │   └── __init__.py      # ORM database models (placeholder)
│   ├── schemas/
│   │   └── __init__.py      # Pydantic data schemas (placeholder)
│   └── services/
│       └── __init__.py      # Business logic services (placeholder)
├── tests/
│   ├── __init__.py
│   └── test_health.py       # Minimal health check unit test
├── requirements.txt         # Core dependencies
├── .env.example             # Configuration template
└── README.md
```

---

## Setup & Getting Started

### 1. Create a Python Virtual Environment

From within the `backend/` directory:

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 2. Install Dependencies

With the virtual environment activated, install the required packages:

```bash
pip install -r requirements.txt
```

---

### 3. Create Environment File (`.env`)

Copy the `.env.example` file to `.env`:

**Windows (PowerShell):**
```powershell
Copy-Item .env.example .env
```

**macOS / Linux:**
```bash
cp .env.example .env
```

Open `.env` and configure your local PostgreSQL credentials:

```ini
APP_NAME=MAILSENTINEL
ENVIRONMENT=development
API_V1_PREFIX=/api/v1
FRONTEND_URL=http://localhost:5173
DATABASE_URL=postgresql+psycopg://your_db_user:your_db_password@localhost:5432/mailsentinel_db
```

> **Note**: Database credentials should never be committed to source control.

---

### 4. Start the FastAPI Development Server

Start the development server with live reload enabled using Uvicorn:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

### 5. Access the API & `/health` Endpoint

Once the server is running:

- **Health Check Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)
  - Returns: `{"status": "ok", "app": "MAILSENTINEL", "environment": "development"}`
- **Interactive Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

### 6. Run Tests

To execute the test suite without any external test dependencies (uses Python standard library `unittest`):

```bash
python -m unittest discover tests
```
