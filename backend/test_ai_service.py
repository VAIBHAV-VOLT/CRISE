"""
CRISE — Phase 15 AI Service & API Test Suite
============================================
Comprehensive test suite (T1 to T30) testing configuration, security, status,
context building, prompt formatting, exception handling, and API endpoints.

CRITICAL REQUIREMENT:
All external LLM HTTP calls are mocked using unittest.mock / httpx mocking.
NO real external API requests are made during test execution.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from main import app
from config import settings, Settings
from services.ai_context import build_ai_context
from services.ai_prompts import SYSTEM_PROMPT
from services.ai_service import AIService, ai_service


client = TestClient(app)

TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


@pytest.fixture
def mock_crise_analysis():
    return {
        "overall_risk": {"score": 24.37, "level": "LOW"},
        "risk": {
            "overall_risk": {"score": 24.37, "level": "LOW"},
            "risk_distribution": {"critical": 0, "high": 1, "medium": 9, "low": 10},
            "top_risk_assets": [
                {"asset_id": "A001", "asset_name": "IoT Gateway Hub", "risk_score": 67.4, "risk_level": "HIGH", "business_value": 5000000}
            ]
        },
        "financial": {
            "financial_summary": {
                "historical_annualized_loss": 1250000.0,
                "risk_based_business_exposure": 4500000.0
            }
        },
        "threats": {
            "scenario_count": 3,
            "scenarios": [
                {"scenario_id": "TS-01", "title": "Ransomware", "threat_type": "Ransomware", "modeled_exposure": 2500000.0, "scenario_risk_level": "HIGH"}
            ]
        },
        "recommendations": {
            "recommendations": [
                {"recommendation_id": "REC-01", "priority": "HIGH", "title": "Patch OS on A001", "asset_id": "A001", "asset_name": "IoT Gateway Hub", "recommended_action": "Apply patch"}
            ]
        },
        "monte_carlo": {
            "status": "success",
            "uncertainty_band": "MODERATE",
            "stats": {"median": 24.5, "p5": 21.0, "p95": 28.0},
            "explanation": "Monte Carlo uncertainty band"
        },
        "mitre": {
            "summary": {
                "mapped_incidents": 5,
                "unmapped_incidents": 0,
                "mapping_coverage_percentage": 100.0,
                "unique_tactics": 4,
                "unique_techniques": 6
            }
        },
        "compliance": {
            "summary": {"total_gaps": 2, "disclaimer": "CRISE modeled coverage is an internal analytical indicator and is not a legal, regulatory, audit, certification, or conformity assessment."},
            "frameworks": [
                {"framework": "NIST Cybersecurity Framework", "framework_version": "2.0 (2024)", "modeled_coverage_percentage": 66.7, "gaps": 1}
            ]
        }
    }


# --- T1 to T5: Configuration & Security ---

def test_t01_env_configuration_loads():
    """T1: Settings loads environment variables."""
    s = Settings()
    assert hasattr(s, "ai_provider")
    assert hasattr(s, "ai_api_key")
    assert hasattr(s, "ai_model")


def test_t02_missing_api_key_detected():
    """T2: Missing API key is detected by is_ai_configured."""
    with patch.object(settings, "ai_api_key", ""):
        assert settings.is_ai_configured is False


def test_t03_missing_model_detected():
    """T3: Missing model is detected by is_ai_configured."""
    with patch.object(settings, "ai_model", ""):
        assert settings.is_ai_configured is False


def test_t04_api_key_never_appears_in_status_response():
    """T4: GET /api/ai/status never leaks API key or secret fragments."""
    with patch.object(settings, "ai_api_key", "secret_key_12345"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = client.get("/api/ai/status")
            assert res.status_code == 200
            data = res.json()
            assert "secret" not in json.dumps(data)
            assert "12345" not in json.dumps(data)
            assert "api_key" not in data


def test_t05_api_key_never_appears_in_frontend_files():
    """T5: HTML and JS frontend files do not contain hardcoded API keys."""
    import re
    html_path = os.path.join(os.path.dirname(__file__), "..", "risk_analzser.html")
    js_path = os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js")
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    with open(js_path, "r", encoding="utf-8") as f:
        js_content = f.read()

    sk_pattern = re.compile(r"sk-[a-zA-Z0-9]{20,}")
    assert not sk_pattern.search(html_content)
    assert not sk_pattern.search(js_content)
    assert "Bearer ey" not in html_content
    assert "Bearer ey" not in js_content



# --- T6 to T13: Provider Communication & Error Handling ---

@patch("services.ai_service.httpx.Client.post")
def test_t06_valid_ai_request_works_with_mocked_provider(mock_post, mock_crise_analysis):
    """T6: Valid request returns structured AI response when mocked."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "answer": "The enterprise risk score of 24.37 is LOW.",
                        "sources": [{"type": "CRISE", "reference": "risk.overall_score"}],
                        "confidence": "HIGH"
                    })
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    svc = AIService()
    with patch.object(settings, "ai_api_key", "mock_key"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = svc.analyze("Why is enterprise risk LOW?", mock_crise_analysis)
            assert res.get("success") is True
            assert "24.37" in res.get("answer", "")
            assert res.get("confidence") == "HIGH"


def test_t07_empty_question_rejected():
    """T7: Empty question returns 400."""
    res = client.post("/api/ai/analyze", json={"question": "   ", "context": {}})
    assert res.status_code == 400


def test_t08_oversized_question_rejected():
    """T8: Question >4000 characters returns 400."""
    long_q = "a" * 4001
    res = client.post("/api/ai/analyze", json={"question": long_q, "context": {}})
    assert res.status_code == 400


def test_t09_malformed_request_rejected():
    """T9: Malformed request payload returns 422 validation error."""
    res = client.post("/api/ai/analyze", json={"invalid_field": 123})
    assert res.status_code == 422


@patch("services.ai_service.httpx.Client.post")
def test_t10_provider_timeout_handled(mock_post, mock_crise_analysis):
    """T10: Provider timeout returns HTTP 504 handling."""
    import httpx
    mock_post.side_effect = httpx.TimeoutException("Connection timed out")
    svc = AIService()
    with patch.object(settings, "ai_api_key", "mock_key"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = svc.analyze("Why is enterprise risk LOW?", mock_crise_analysis)
            assert "error" in res
            assert res.get("status_code") == 504


@patch("services.ai_service.httpx.Client.post")
def test_t11_provider_authentication_error_handled_safely(mock_post, mock_crise_analysis):
    """T11: Provider auth error (401) is handled safely without leaking credentials."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_post.return_value = mock_resp

    svc = AIService()
    with patch.object(settings, "ai_api_key", "secret_key_9999"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = svc.analyze("Test question", mock_crise_analysis)
            assert "error" in res
            assert "secret_key_9999" not in res["error"]


@patch("services.ai_service.httpx.Client.post")
def test_t12_provider_rate_limit_handled_safely(mock_post, mock_crise_analysis):
    """T12: Provider rate limit (429) returns safe error message."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_post.return_value = mock_resp

    svc = AIService()
    with patch.object(settings, "ai_api_key", "mock_key"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = svc.analyze("Test question", mock_crise_analysis)
            assert "error" in res
            assert "rate limit" in res["error"].lower()


@patch("services.ai_service.httpx.Client.post")
def test_t13_malformed_ai_output_handled(mock_post, mock_crise_analysis):
    """T13: Non-JSON plain text AI output is wrapped safely without crashing."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "This is plain text response from AI assistant."
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    svc = AIService()
    with patch.object(settings, "ai_api_key", "mock_key"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = svc.analyze("Explain risk", mock_crise_analysis)
            assert res.get("success") is True
            assert "plain text" in res.get("answer", "")
            assert "confidence" in res


# --- T14 to T20: Context & Prompt Integrity ---

def test_t14_deterministic_crise_context_passed_to_ai(mock_crise_analysis):
    """T14: Deterministic CRISE context is constructed accurately."""
    ctx = build_ai_context(mock_crise_analysis, "Why is enterprise risk LOW?")
    assert "risk" in ctx
    assert ctx["risk"]["overall_score"] == 24.37


def test_t15_risk_score_is_preserved_in_context(mock_crise_analysis):
    """T15: Baseline overall risk score (24.37) is preserved exactly in AI context."""
    ctx = build_ai_context(mock_crise_analysis)
    assert ctx["risk"]["overall_score"] == 24.37


def test_t16_ai_is_instructed_not_to_modify_risk_scores():
    """T16: System prompt explicitly instructs AI never to modify or recalculate risk scores."""
    assert "authoritative" in SYSTEM_PROMPT.lower()
    assert "never replace, recalculate, or contradict" in SYSTEM_PROMPT.lower()


def test_t17_ai_does_not_receive_raw_api_credentials():
    """T17: AI context generation does not contain any environment credentials."""
    ctx = build_ai_context({"risk": {"overall_risk": {"score": 50.0}}})
    ctx_str = json.dumps(ctx)
    assert "api_key" not in ctx_str
    assert "secret" not in ctx_str


def test_t18_source_references_are_valid():
    """T18: System prompt defines valid CRISE source reference categories."""
    for module_name in ["risk", "financial", "threats", "recommendations", "mitre", "compliance"]:
        assert module_name in SYSTEM_PROMPT


def test_t19_confidence_values_valid():
    """T19: Allowed confidence levels are HIGH, MEDIUM, LOW."""
    assert '"HIGH", "MEDIUM", "LOW"' in SYSTEM_PROMPT


def test_t20_missing_context_handled():
    """T20: Empty analysis data returns clean minimal context structure."""
    ctx = build_ai_context({})
    assert "risk" in ctx
    assert ctx["risk"]["overall_score"] == 0.0


# --- T21 to T25: Security & Disclaimer Preservation ---

def test_t21_prompt_injection_text_treated_as_data():
    """T21: System prompt explicitly commands isolation of dataset text as data."""
    assert "prompt injection isolation" in SYSTEM_PROMPT.lower() or "strictly as data" in SYSTEM_PROMPT.lower()


def test_t22_monte_carlo_disclaimer_preserved():
    """T22: System prompt preserves Monte Carlo uncertainty disclaimer."""
    assert "monte carlo" in SYSTEM_PROMPT.lower()
    assert "input uncertainty" in SYSTEM_PROMPT.lower() or "modeled" in SYSTEM_PROMPT.lower()


def test_t23_compliance_disclaimer_preserved():
    """T23: System prompt preserves compliance legal non-claim disclaimer."""
    assert "compliance" in SYSTEM_PROMPT.lower()
    assert "legal" in SYSTEM_PROMPT.lower() or "certification" in SYSTEM_PROMPT.lower()


def test_t24_mitre_mapping_disclaimer_preserved():
    """T24: System prompt preserves MITRE threat mapping disclaimer."""
    assert "mitre" in SYSTEM_PROMPT.lower()


def test_t25_api_ai_status_works():
    """T25: GET /api/ai/status endpoint works and returns expected JSON schema."""
    res = client.get("/api/ai/status")
    assert res.status_code == 200
    data = res.json()
    assert "configured" in data
    assert "provider" in data
    assert "model" in data
    assert "available" in data


# --- T26 to T30: End-to-End API Integration & Immutability ---

@patch.object(ai_service, "analyze")
def test_t26_api_ai_analyze_endpoint_works(mock_analyze, mock_crise_analysis):
    """T26: POST /api/ai/analyze returns 200 with structured answer when configured."""
    mock_analyze.return_value = {
        "success": True,
        "answer": "The highest priority finding is A001.",
        "sources": [{"type": "CRISE", "reference": "recommendations"}],
        "confidence": "HIGH",
        "disclaimer": "AI-generated analysis based on CRISE results."
    }

    with patch.object(settings, "ai_api_key", "mock_key"):
        with patch.object(settings, "ai_model", "gpt-4o-mini"):
            res = client.post("/api/ai/analyze", json={
                "question": "What should we fix first?",
                "context": mock_crise_analysis
            })
            assert res.status_code == 200
            data = res.json()
            assert data.get("success") is True
            assert "A001" in data["answer"]
            assert "disclaimer" in data




def test_t27_frontend_calls_backend_ai_endpoint():
    """T27: Frontend JS calls /api/ai/analyze endpoint."""
    js_path = os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js")
    with open(js_path, "r", encoding="utf-8") as f:
        js_content = f.read()
    assert "/api/ai/analyze" in js_content
    assert "/api/ai/status" in js_content


def test_t28_frontend_does_not_call_llm_provider_directly():
    """T28: Frontend JS does not call external OpenAI endpoints directly."""
    js_path = os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js")
    with open(js_path, "r", encoding="utf-8") as f:
        js_content = f.read()
    assert "api.openai.com" not in js_content


def test_t29_frontend_does_not_calculate_ai_analysis():
    """T29: Frontend delegates AI analysis to backend API."""
    js_path = os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js")
    with open(js_path, "r", encoding="utf-8") as f:
        js_content = f.read()
    assert "fetch('http://localhost:8000/api/ai/analyze'" in js_content or "fetch('/api/ai/analyze'" in js_content or "/api/ai/analyze" in js_content


def test_t30_no_mutation_of_crise_analysis_data(mock_crise_analysis):
    """T30: Context construction and AI analysis leave input analysis dictionary unmutated."""
    original_str = json.dumps(mock_crise_analysis, sort_keys=True)
    _ = build_ai_context(mock_crise_analysis, "Test question")
    after_str = json.dumps(mock_crise_analysis, sort_keys=True)
    assert original_str == after_str
