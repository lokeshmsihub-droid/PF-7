from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import health, webhooks, compliance, auth_jira, jira_compliance
from app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Compliance Platform Automation Engine Backend"
)

# Enable CORS for frontend web server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers for clean API responses
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle model validation errors elegantly."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Request body validation failed", "errors": exc.errors()}
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Fallback handler to prevent raw trace leaks."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred"}
    )

# Include routers
app.include_router(health.router, tags=["System Health"])
app.include_router(webhooks.router, tags=["Webhooks"])
app.include_router(compliance.router, tags=["Compliance & Change Management"])
app.include_router(jira_compliance.router, tags=["Jira Compliance & Lineage"])
app.include_router(auth_jira.router, prefix="/api", tags=["Jira OAuth & Configuration"])

