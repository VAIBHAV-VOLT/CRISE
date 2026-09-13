import io
import json
import os
from typing import Dict, Any, Optional, Tuple, List
from fastapi import FastAPI, HTTPException, Request, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import pandas as pd

from services.validation import validate_all
from services.processing import process_data
from services.risk_engine import calculate_risk
from services.financial_engine import calculate_financial_risk
from services.threat_engine import analyze_threats
from services.intelligence_engine import build_intelligence
from services.simulation_engine import simulate_scenario
from services.optimizer import optimize_investments
from services.recommendation_engine import generate_recommendations
from services.monte_carlo import run_monte_carlo
from services.mitre_engine import build_mitre_intelligence
from services.compliance_engine import build_compliance_assessment
from services.ai_context import build_ai_context
from services.ai_service import ai_service
from config import settings

# Pydantic Response Models for OpenAPI / Swagger UI Documentation
class BaselineSummaryModel(BaseModel):
    asset_id: Optional[str] = Field(None, description="Asset ID or null for enterprise level")
    asset_name: str = Field("Enterprise", description="Asset name or Enterprise")
    risk_score: float = Field(..., description="Baseline modeled risk score (0-100)")
    risk_level: str = Field(..., description="Baseline risk level (LOW, MEDIUM, HIGH, CRITICAL)")

class ScenarioSummaryModel(BaseModel):
    asset_id: Optional[str] = Field(None, description="Asset ID or null for enterprise level")
    asset_name: str = Field("Enterprise", description="Asset name or Enterprise")
    risk_score: float = Field(..., description="Scenario modeled risk score (0-100)")
    risk_level: str = Field(..., description="Scenario risk level (LOW, MEDIUM, HIGH, CRITICAL)")

class DeltaSummaryModel(BaseModel):
    risk_score_change: float = Field(..., description="Scenario score minus baseline score")
    risk_reduction: float = Field(..., description="Baseline score minus scenario score")
    percentage_change: float = Field(..., description="Percentage change in risk score")

class AppliedChangesModel(BaseModel):
    controls: List[Dict[str, Any]] = Field([], description="Applied control changes")
    remediated_vulnerabilities: List[str] = Field([], description="Remediated vulnerability IDs")
    internet_exposure_changed: bool = Field(False, description="Whether internet exposure was changed")

class SimulationResponseModel(BaseModel):
    success: bool = Field(True, description="Whether the simulation succeeded")
    baseline: BaselineSummaryModel
    scenario: ScenarioSummaryModel
    delta: DeltaSummaryModel
    changes_applied: AppliedChangesModel
    explanation: str = Field(..., description="Deterministic impact explanation")

class BudgetSummaryModel(BaseModel):
    available: float = Field(..., description="Available budget")
    used: float = Field(..., description="Budget used by selected controls")
    remaining: float = Field(..., description="Remaining budget")

class ImpactSummaryModel(BaseModel):
    risk_reduction: float = Field(..., description="Points reduced from baseline risk score")
    percentage_reduction: float = Field(..., description="Percentage reduction from baseline risk score")

class AlgorithmModel(BaseModel):
    method: str = Field(..., description="exact_subset or greedy")
    is_optimal: bool = Field(..., description="Whether the solution is mathematically optimal")

class SelectedControlModel(BaseModel):
    control_id: str
    control_name: str
    asset_id: str
    asset_name: str
    annual_cost: float
    effectiveness: float
    original_status: str
    marginal_risk_reduction: float
    risk_reduction_per_rupee: float

class OptimizationResponseModel(BaseModel):
    success: bool = Field(True, description="Whether optimization succeeded")
    status: str = Field(..., description="optimized, no_eligible_controls, or no_affordable_controls")
    baseline: BaselineSummaryModel
    optimized: ScenarioSummaryModel
    budget: BudgetSummaryModel
    impact: ImpactSummaryModel
    selected_controls: List[SelectedControlModel] = []
    affected_assets: List[Dict[str, Any]] = []
    risk_level_changes: List[Dict[str, Any]] = []
    algorithm: AlgorithmModel
    explanation: str

class MonteCarloSimulationStats(BaseModel):
    mean: float = Field(..., description="Mean simulated risk score")
    median: float = Field(..., description="Median simulated risk score")
    std_dev: float = Field(..., description="Standard deviation of simulated risk scores")
    min: float = Field(..., description="Minimum simulated risk score")
    max: float = Field(..., description="Maximum simulated risk score")
    p5: float = Field(..., description="5th percentile simulated risk score")
    p25: float = Field(..., description="25th percentile simulated risk score")
    p75: float = Field(..., description="75th percentile simulated risk score")
    p95: float = Field(..., description="95th percentile simulated risk score")

class RiskLevelDistItem(BaseModel):
    count: int = Field(..., description="Count of iterations in risk level")
    percentage: float = Field(..., description="Percentage of iterations in risk level")

class MonteCarloResponseModel(BaseModel):
    scope: str = Field(..., description="Scope of simulation ('asset' or 'enterprise')")
    asset_id: Optional[str] = Field(None, description="Asset ID if asset-level simulation")
    iterations: int = Field(..., description="Number of simulation iterations executed")
    seed: int = Field(..., description="Random seed used for sampling")
    baseline: Dict[str, Any] = Field(..., description="Baseline risk score and level")
    simulation: MonteCarloSimulationStats = Field(..., description="Summary statistics of simulated risk scores")
    risk_level_distribution: Dict[str, RiskLevelDistItem] = Field(..., description="Distribution of iterations across risk levels")
    uncertainty_band: str = Field(..., description="Uncertainty band ('LOW', 'MODERATE', 'HIGH') based on P95-P5 range")
    explanation: str = Field(..., description="Human-readable deterministic explanation of uncertainty results")

class MitreSummaryModel(BaseModel):
    total_incidents: int = Field(..., description="Total incident count")
    mapped_incidents: int = Field(..., description="Count of mapped incidents")
    unmapped_incidents: int = Field(..., description="Count of unmapped incidents")
    mapping_coverage_percentage: float = Field(..., description="Mapping coverage percentage (0-100%)")
    unique_tactics: int = Field(..., description="Unique MITRE tactics mapped")
    unique_techniques: int = Field(..., description="Unique MITRE techniques mapped")

class MitreResponseModel(BaseModel):
    status: str = Field("success", description="Status of MITRE mapping analysis")
    metadata: Dict[str, str] = Field(..., description="Framework metadata")
    summary: MitreSummaryModel = Field(..., description="Enterprise MITRE mapping summary")
    incidents: List[Dict[str, Any]] = Field(..., description="Incident-level MITRE mappings")
    techniques: List[Dict[str, Any]] = Field(..., description="Technique-level aggregated threat intelligence")
    tactics: List[Dict[str, Any]] = Field(..., description="Tactic-level aggregated threat intelligence")

class ComplianceFrameworkModel(BaseModel):
    framework_id: str
    framework: str
    framework_version: str
    total_items: int
    addressed: int
    partially_addressed: int
    gaps: int
    not_assessed: int
    modeled_coverage_percentage: float

class ComplianceSummaryModel(BaseModel):
    framework_count: int
    total_findings: int
    total_gaps: int
    highest_priority_gaps: List[Dict[str, Any]]
    disclaimer: str

class ComplianceResponseModel(BaseModel):
    status: str = Field("success", description="Status string")
    summary: ComplianceSummaryModel
    frameworks: List[ComplianceFrameworkModel]
    findings: List[Dict[str, Any]]
    gaps: List[Dict[str, Any]]
    crosswalk: List[Dict[str, Any]]

class AIStatusResponse(BaseModel):
    configured: bool = Field(..., description="Whether AI provider & API key are configured")
    provider: str = Field(..., description="Configured AI provider")
    model: str = Field(..., description="Configured AI model name")
    available: bool = Field(..., description="Whether AI service is ready")

class AIAnalyzeRequest(BaseModel):
    question: str = Field(..., description="Natural language question for AI Security Analyst (max 4000 chars)")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional structured CRISE context payload")

class AISourceModel(BaseModel):
    type: str = Field("CRISE", description="Source type")
    reference: str = Field(..., description="Module/metric reference")

class AIAnalyzeResponse(BaseModel):
    success: bool = Field(True, description="Whether analysis succeeded")
    answer: str = Field(..., description="Natural language answer from AI Security Analyst")
    sources: List[AISourceModel] = Field([], description="CRISE source references")
    confidence: str = Field("HIGH", description="Confidence level (HIGH, MEDIUM, LOW)")
    disclaimer: str = Field(..., description="Mandatory AI analysis disclaimer")


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

    # 5. Calculate modeled financial risk
    try:
        financial_result = calculate_financial_risk(processed_result, risk_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Financial calculation failed unexpectedly."},
        )

    # Merge financial metrics into asset risk profiles so assets in response have both risk and financial
    fin_asset_map = {a["asset_id"]: a["financial"] for a in financial_result.get("assets", [])}
    merged_assets = []
    for a in risk_result.get("assets", []):
        a_copy = dict(a)
        if a["asset_id"] in fin_asset_map:
            a_copy["financial"] = fin_asset_map[a["asset_id"]]
        merged_assets.append(a_copy)

    # 6. Calculate threat and scenario metrics
    try:
        threat_result = analyze_threats(processed_result, risk_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Threat analysis failed unexpectedly."},
        )

    # 7. Calculate Asset & Vulnerability Intelligence
    try:
        intelligence_result = build_intelligence(processed_result, risk_result, financial_result, threat_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Intelligence calculation failed unexpectedly."},
        )

    # 8. Generate Cybersecurity Recommendations
    try:
        recommendation_result = generate_recommendations(
            processed_data=processed_result,
            risk_results=risk_result,
            financial_results=financial_result,
            threat_results=threat_result,
            intelligence_results=intelligence_result,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Recommendation generation failed unexpectedly."},
        )

    # 9. Generate MITRE ATT&CK Threat Mapping Intelligence
    try:
        mitre_result = build_mitre_intelligence(
            processed_data=processed_result,
            risk_results=risk_result,
            financial_results=financial_result,
            threat_results=threat_result,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "MITRE threat mapping failed unexpectedly."},
        )

    # 10. Generate Compliance & Security Framework Mapping
    try:
        compliance_result = build_compliance_assessment(
            processed_data=processed_result,
            risk_results=risk_result,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Compliance mapping failed unexpectedly."},
        )

    response_payload = {
        "success": True,
        "overall_risk": risk_result.get("overall_risk"),
        "risk_distribution": risk_result.get("risk_distribution"),
        "top_risk_assets": risk_result.get("top_risk_assets"),
        "assets": merged_assets,
        "risk": risk_result,
        "financial": financial_result,
        "threats": threat_result,
        "intelligence": intelligence_result,
        "recommendations": recommendation_result,
        "mitre": mitre_result,
        "compliance": compliance_result,
    }

    return JSONResponse(
        status_code=200,
        content=response_payload,
    )


@app.post(
    "/api/simulate",
    response_model=SimulationResponseModel,
    summary="What-If Risk Simulation",
    description="Stateless what-if simulation using supplied CSV files and scenario JSON string."
)
async def simulate_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
    scenario: Optional[str] = Form("{}", description="JSON string containing scenario modifications (e.g. {} or {\"asset_id\": \"A001\"})"),
):
    """
    Endpoint for deterministic what-if risk simulation.
    Accepts CSV files and a JSON-encoded 'scenario' string specifying modifications.
    Does NOT modify original datasets or persist state.
    """
    # 1. Parse scenario JSON
    scenario_str = scenario.strip() if scenario and scenario.strip() else "{}"
    try:
        scenario_input = json.loads(scenario_str)
    except (json.JSONDecodeError, TypeError, ValueError):
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": ["Invalid scenario JSON format."]}
        )

    if not isinstance(scenario_input, dict):
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": ["Scenario must be a JSON object."]}
        )

    # 2. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 3. Validate CSV datasets
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

    # 4. Process datasets
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

    # 5. Run simulation
    try:
        sim_result = simulate_scenario(processed_result, scenario_input)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Simulation failed unexpectedly."},
        )

    status_code = 200 if sim_result.get("success") else 400
    return JSONResponse(
        status_code=status_code,
        content=sim_result,
    )


@app.post(
    "/api/optimize",
    response_model=OptimizationResponseModel,
    summary="Investment Optimizer",
    description="Stateless budget-constrained cybersecurity investment optimization."
)
async def optimize_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
    budget: Optional[float] = Form(0.0, description="Available annual budget in INR"),
    candidate_control_ids: Optional[str] = Form(None, description="Optional JSON list of string control IDs"),
):
    """
    Endpoint for deterministic investment optimization.
    Accepts CSV files, budget, and optional candidate_control_ids list.
    Does NOT modify original datasets or persist state.
    """
    # 1. Parse budget parameter
    budget_val = budget if budget is not None else 0.0
    if budget_val < 0.0:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": ["Budget must be a non-negative number."]}
        )

    # 2. Parse candidate_control_ids if supplied
    parsed_candidate_ids: Optional[List[str]] = None
    if candidate_control_ids and candidate_control_ids.strip():
        try:
            cand_parsed = json.loads(candidate_control_ids)
            if not isinstance(cand_parsed, list):
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "errors": ["candidate_control_ids must be a JSON list of control ID strings."]}
                )
            parsed_candidate_ids = cand_parsed
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"success": False, "errors": ["Invalid candidate_control_ids JSON format."]}
            )

    # 3. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 4. Validate CSV datasets
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

    # 5. Process datasets
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

    # 6. Run Optimization
    try:
        opt_result = optimize_investments(
            processed_data=processed_result,
            budget=budget_val,
            candidate_control_ids=parsed_candidate_ids,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Optimization failed unexpectedly."},
        )

    status_code = 200 if opt_result.get("success") else 400
    return JSONResponse(
        status_code=status_code,
        content=opt_result,
    )


@app.post(
    "/api/monte-carlo",
    response_model=MonteCarloResponseModel,
    summary="Monte Carlo / Uncertainty Risk Simulation",
    description="Stateless Monte Carlo uncertainty simulation estimating a range of possible modeled risk scores using a ±10% bounded triangular distribution around continuous risk inputs. Does NOT represent attack probability."
)
async def monte_carlo_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
    iterations: int = Form(5000, description="Number of iterations (100 to 20000)"),
    seed: int = Form(42, description="Random seed for reproducibility"),
    asset_id: Optional[str] = Form(None, description="Optional asset ID to simulate a single asset"),
):
    """
    Endpoint for Monte Carlo uncertainty risk simulation.
    Validates parameter bounds (100 <= iterations <= 20000).
    Reuses standard Phase 2 validation and Phase 3 processing pipelines.
    """
    # 1. Parameter Validation
    if not isinstance(iterations, int) or iterations < 100 or iterations > 20000:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": ["Iterations must be an integer between 100 and 20000."]}
        )

    # 2. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 3. Validate CSV datasets
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

    # 4. Process datasets
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

    # 5. Run Monte Carlo Simulation
    try:
        mc_result = run_monte_carlo(
            processed_data=processed_result,
            iterations=iterations,
            seed=seed,
            asset_id=asset_id,
        )
    except KeyError as exc:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": [str(exc).strip("'")]}
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": [str(exc)]}
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Monte Carlo simulation failed unexpectedly."},
        )

    return JSONResponse(
        status_code=200,
        content=mc_result,
    )


@app.post(
    "/api/mitre",
    response_model=MitreResponseModel,
    summary="MITRE ATT&CK Threat Mapping",
    description="Stateless deterministic mapping of incident categories to MITRE ATT&CK Enterprise tactics and techniques."
)
async def mitre_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
):
    """
    Endpoint for MITRE ATT&CK threat mapping and intelligence.
    Reuses standard Phase 2 validation, Phase 3 processing, Phase 4 risk, Phase 5 financial, and Phase 6 threat pipelines.
    """
    # 1. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 2. Validate CSV datasets
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

    # 3. Process datasets
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

    # 4. Calculate Risk
    try:
        risk_result = calculate_risk(processed_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Risk calculation failed unexpectedly."},
        )

    # 5. Calculate Financial Risk
    try:
        financial_result = calculate_financial_risk(processed_result, risk_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Financial calculation failed unexpectedly."},
        )

    # 6. Analyze Threats
    try:
        threat_result = analyze_threats(processed_result, risk_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Threat analysis failed unexpectedly."},
        )

    # 7. Build MITRE Intelligence
    try:
        mitre_result = build_mitre_intelligence(
            processed_data=processed_result,
            risk_results=risk_result,
            financial_results=financial_result,
            threat_results=threat_result,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "MITRE mapping failed unexpectedly."},
        )

    return JSONResponse(
        status_code=200,
        content=mitre_result,
    )


@app.post(
    "/api/compliance",
    response_model=ComplianceResponseModel,
    summary="Compliance & Security Framework Mapping",
    description="Stateless deterministic mapping of CRISE findings to NIST CSF 2.0, ISO/IEC 27001:2022, and CIS Controls v8."
)
async def compliance_endpoint(
    assets: Optional[UploadFile] = File(None),
    vulnerabilities: Optional[UploadFile] = File(None),
    controls: Optional[UploadFile] = File(None),
    incidents: Optional[UploadFile] = File(None),
):
    """
    Endpoint for Compliance and Security Framework Mapping.
    Reuses standard Phase 2 validation, Phase 3 processing, and Phase 4 risk pipelines.
    """
    # 1. Parse uploaded files
    parsed_dfs, parse_errors = await _parse_all_files(assets, vulnerabilities, controls, incidents)
    if parse_errors:
        return JSONResponse(
            status_code=400,
            content={"success": False, "errors": parse_errors},
        )

    # 2. Validate CSV datasets
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

    # 3. Process datasets
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

    # 4. Calculate Risk
    try:
        risk_result = calculate_risk(processed_result)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Risk calculation failed unexpectedly."},
        )

    # 5. Build Compliance Assessment
    try:
        compliance_result = build_compliance_assessment(
            processed_data=processed_result,
            risk_results=risk_result,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "detail": "Compliance mapping failed unexpectedly."},
        )

    return JSONResponse(
        status_code=200,
        content=compliance_result,
    )


@app.get(
    "/api/ai/status",
    response_model=AIStatusResponse,
    summary="AI Security Analyst Status Check",
    description="Returns public status indicating whether AI provider & model credentials are configured server-side. NEVER exposes secrets."
)
async def ai_status_endpoint():
    """
    Public health/status check for AI Security Analyst service.
    """
    return ai_service.get_provider_status()


@app.post(
    "/api/ai/analyze",
    response_model=AIAnalyzeResponse,
    summary="AI Security Analyst Query Endpoint",
    description="Accepts a natural-language cybersecurity question and optional structured CRISE context. Explains existing findings without recalculating risk scores."
)
async def ai_analyze_endpoint(request: AIAnalyzeRequest):
    """
    Endpoint for AI Security Analyst natural language queries.
    """
    question = (request.question or "").strip()
    if not question:
        return JSONResponse(
            status_code=400,
            content={"success": False, "detail": "Question must be a non-empty string."},
        )

    if len(question) > 4000:
        return JSONResponse(
            status_code=400,
            content={"success": False, "detail": "Question exceeds maximum limit of 4000 characters."},
        )

    if not ai_service.is_configured():
        return JSONResponse(
            status_code=503,
            content={
                "success": False,
                "detail": "AI service is not configured. Set AI_API_KEY and AI_MODEL in backend .env file.",
                "available": False
            },
        )

    # Build context from request context or empty fallback
    provided_context = request.context or {}
    ai_context = build_ai_context(provided_context, question=question)

    result = ai_service.analyze(question=question, context=ai_context)

    if "error" in result:
        return JSONResponse(
            status_code=result.get("status_code", 503),
            content={"success": False, "detail": result["error"]},
        )

    return JSONResponse(
        status_code=200,
        content=result,
    )


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)


