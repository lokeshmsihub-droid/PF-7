from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.session import engine, Base
from app.api.v1.scans import router as scans_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.security import router as security_router
from app.core.config import settings

# Create DB tables if not existing
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Enterprise Compliance Automation + Native Vulnerability Management Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(repositories_router)
app.include_router(repositories_router, prefix=settings.API_V1_STR)
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(scans_router) # also support /scans
app.include_router(security_router)
app.include_router(security_router, prefix=settings.API_V1_STR)

@app.get("/health")
def health_check():
    return {
        "status": "ok", 
        "service": "enterprise-compliance-scanner",
        "semgrep_version": "1.177.0"
    }
