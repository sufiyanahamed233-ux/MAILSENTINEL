from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import get_db

app = FastAPI(
    title=settings.APP_NAME,
    description="Backend API for MAILSENTINEL - AI-Powered Email Threat Detection & Forensic Intelligence Platform",
    version="1.0.0",
)

# Configure CORS using configured frontend URL
origins = [
    settings.FRONTEND_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the versioned API router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check endpoint confirming the API is running."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health/db", tags=["Health"])
def db_health_check(db: Session = Depends(get_db)) -> dict[str, str]:
    """Database connectivity health check verifying PostgreSQL connection without touching application tables."""
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "database": "connected",
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connectivity check failed: {str(exc)}",
        )

