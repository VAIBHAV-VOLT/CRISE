import io
import os
from typing import Dict, Any, Optional, Tuple
from fastapi import FastAPI, HTTPException, Request, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import pandas as pd

from services.validation import validate_all
from services.processing import process_data
from services.risk_engine import calculate_risk

# Load environment variables
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


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


async def _parse_upload_file(file: Optional[UploadFile], file_key: str) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """
    Safely validate and parse UploadFile into a pandas DataFrame.
    Returns (df, error_message).
    """
    if file is None or not file.filename:
        return None, f"Missing required file: {file_key}.csv"

    filename = file.filename.lower()
    if not filename.endswith(".csv"):
        return None, f"Unsupported file type for {file_key}. Only .csv files are allowed."

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        return None, f"File {file.filename} exceeds maximum size limit of 10MB."

    if len(content.strip()) == 0:
        return None, f"{file_key}.csv is empty."

    # Attempt parsing with multiple encodings
    for encoding in ["utf-8", "utf-8-sig", "latin-1"]:
        try:
            df = pd.read_csv(io.BytesIO(content), encoding=encoding)
            return df, None
        except Exception:
            continue

    return None, f"Malformed CSV in {file_key}.csv."


@app.post("/api/validate")
async def validate_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None)
):
    """
    Endpoint to receive and validate assets, vulnerabilities, controls, and incidents CSV files.
    """
    files_map = {
        "assets": assets,
        "vulnerabilities": vulnerabilities,
        "controls": controls,
        "incidents": incidents
    }

    parsed_dfs: Dict[str, pd.DataFrame] = {}
    missing_or_error_messages = []

    for key, file_obj in files_map.items():
        df, err = await _parse_upload_file(file_obj, key)
        if err:
            missing_or_error_messages.append(err)
        else:
            parsed_dfs[key] = df

    if missing_or_error_messages:
        return JSONResponse(
            status_code=400,
            content={
                "valid": False,
                "errors": missing_or_error_messages
            }
        )

    # Perform detailed domain validation
    validation_result = validate_all(
        assets_df=parsed_dfs["assets"],
        vulnerabilities_df=parsed_dfs["vulnerabilities"],
        controls_df=parsed_dfs["controls"],
        incidents_df=parsed_dfs["incidents"]
    )

    status_code = 200 if validation_result["valid"] else 400
    return JSONResponse(status_code=status_code, content=validation_result)


async def _parse_all_files(
    assets: Optional[UploadFile],
    vulnerabilities: Optional[UploadFile],
    controls: Optional[UploadFile],
    incidents: Optional[UploadFile],
):
    """
    Shared helper: parse all four UploadFile objects into DataFrames.
    Returns (parsed_dfs dict, error_list).
    """
    files_map = {
        "assets": assets,
        "vulnerabilities": vulnerabilities,
        "controls": controls,
        "incidents": incidents,
    }
    parsed_dfs: Dict[str, pd.DataFrame] = {}
    errors = []
    for key, file_obj in files_map.items():
        df, err = await _parse_upload_file(file_obj, key)
        if err:
            errors.append(err)
        else:
            parsed_dfs[key] = df
    return parsed_dfs, errors


@app.post("/api/process")
async def process_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
):
    """
    Receive, validate, and process all four risk CSV files.
    Returns a normalized, asset-centric data structure.
    Does NOT compute risk scores or financial metrics.
    """
    # 1. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 2. Validate (reuse existing validation service — no duplication)
    validation_result = validate_all(
        assets_df=parsed_dfs["assets"],
        vulnerabilities_df=parsed_dfs["vulnerabilities"],
        controls_df=parsed_dfs["controls"],
        incidents_df=parsed_dfs["incidents"],
    )
    if not validation_result["valid"]:
        return JSONResponse(
            status_code=400,
            content={"success": False, "validation": validation_result},
        )

    # 3. Process validated data
    try:
        result = process_data(
            assets_df=parsed_dfs["assets"],
            vulnerabilities_df=parsed_dfs["vulnerabilities"],
            controls_df=parsed_dfs["controls"],
            incidents_df=parsed_dfs["incidents"],
        )
    except Exception as exc:
        # Log technical detail server-side; return generic message to client
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Data processing failed unexpectedly."},
        )

    return JSONResponse(
        status_code=200,
        content={"success": True, **result},
    )


@app.post("/api/analyze")
async def analyze_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
):
    """
    Receive, validate, process, and calculate modeled cyber risk scores
    for all assets and enterprise overall.
    Pipeline:
      POST /api/analyze -> Parse CSV -> validate_all() -> process_data() -> calculate_risk() -> JSON
    """
    # 1. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 2. Validate (reuse existing validation service — no duplication)
    validation_result = validate_all(
        assets_df=parsed_dfs["assets"],
        vulnerabilities_df=parsed_dfs["vulnerabilities"],
        controls_df=parsed_dfs["controls"],
        incidents_df=parsed_dfs["incidents"],
    )
    if not validation_result["valid"]:
        return JSONResponse(
            status_code=400,
            content={"success": False, "validation": validation_result},
        )

    # 3. Process validated data
    try:
        processed_result = process_data(
            assets_df=parsed_dfs["assets"],
            vulnerabilities_df=parsed_dfs["vulnerabilities"],
            controls_df=parsed_dfs["controls"],
            incidents_df=parsed_dfs["incidents"],
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Data processing failed unexpectedly."},
        )

    # 4. Calculate modeled risk scores
    try:
        risk_result = calculate_risk(processed_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Risk calculation failed unexpectedly."},
        )

    return JSONResponse(
        status_code=200,
        content=risk_result,
    )


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)
