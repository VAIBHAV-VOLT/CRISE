import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

app = FastAPI(
    title="cyber-risk-analyzer-backend",
    description="Backend API for Cyber Risk Analyzer platform",
    version="1.0.0"
)

# CORS Configuration
raw_origins = os.getenv("ALLOWED_ORIGINS", "")
env_origin = os.getenv("FRONTEND_ORIGIN", "")

allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

if env_origin and env_origin not in allowed_origins:
    allowed_origins.append(env_origin)

if raw_origins:
    for o in raw_origins.split(","):
        o_clean = o.strip()
        if o_clean and o_clean not in allowed_origins:
            allowed_origins.append(o_clean)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status": "error"}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "status": "error"}
    )


@app.get("/api/health")
async def health_check():
    """
    Backend health check endpoint.
    """
    return {
        "status": "ok",
        "service": "cyber-risk-analyzer-backend"
    }


# ------------------------------------------------------------------
# Future Endpoint Stubs (Phase 2+)
# ------------------------------------------------------------------
# POST /api/validate        -> Validation of uploaded datasets
# POST /api/analyze         -> Comprehensive risk analysis calculation
# POST /api/simulate        -> What-if scenario simulations
# POST /api/optimize        -> Investment/control optimizer
# POST /api/recommendations -> Remediation action plan generator
# ------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)
