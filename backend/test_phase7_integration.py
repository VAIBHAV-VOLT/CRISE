"""
Phase 7 ? Backend Dashboard Integration Test Suite
==================================================
Verifies backend payload completeness and compatibility for frontend dashboard integration.
"""

import sys
import os
import json
import requests

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(__file__))

TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))
BASE_URL = "http://127.0.0.1:8000"

def read_testfile(name: str) -> bytes:
    path = os.path.join(TESTDATA_DIR, name)
    with open(path, "rb") as f:
        return f.read()

PASSED = 0
FAILED = 0
RESULTS = []

def run_test(name, fn):
    global PASSED, FAILED
    try:
        fn()
        print(f"  [PASS] {name}")
        PASSED += 1
        RESULTS.append(("PASS", name, None))
    except AssertionError as e:
        print(f"  [FAIL] {name}: {e}")
        FAILED += 1
        RESULTS.append(("FAIL", name, str(e)))
    except Exception as e:
        print(f"  [ERROR] {name}: {type(e).__name__}: {e}")
        FAILED += 1
        RESULTS.append(("ERROR", name, str(e)))

def _check_server():
    try:
        r = requests.get(f"{BASE_URL}/docs", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

SERVER_AVAILABLE = _check_server()

def _post_analyze():
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/analyze", files=files, timeout=15)
    return resp.json()

def _skip():
    if not SERVER_AVAILABLE:
        raise AssertionError("SKIPPED -- server not running at 127.0.0.1:8000")

def test_01_payload_structure():
    """POST /api/analyze contains all required root keys for Phase 7 frontend."""
    _skip()
    r = _post_analyze()
    assert r.get("success") is True, f"Failed: {r}"
    required = {"overall_risk", "risk_distribution", "financial", "threats", "assets"}
    missing = required - set(r.keys())
    assert not missing, f"Missing root keys: {missing}"

def test_02_overview_risk_metrics():
    """overall_risk contains score and level."""
    _skip()
    r = _post_analyze()
    ov = r.get("overall_risk", {})
    assert "score" in ov, "score missing from overall_risk"
    assert "level" in ov, "level missing from overall_risk"
    assert ov["level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert len(r.get("assets", [])) == 20

def test_03_overview_financial_metrics():
    """financial.financial_summary contains historical_annualized_loss & risk_based_business_exposure."""
    _skip()
    r = _post_analyze()
    fin_sum = r.get("financial", {}).get("financial_summary", {})
    assert "historical_annualized_loss" in fin_sum
    assert "risk_based_business_exposure" in fin_sum
    assert fin_sum["historical_annualized_loss"] == 16530000.0

def test_04_overview_threat_metrics():
    """threats contains scenario_count and scenarios list with required fields."""
    _skip()
    r = _post_analyze()
    threats = r.get("threats", {})
    assert threats.get("status") == "ok"
    assert threats.get("scenario_count") > 0
    scenarios = threats.get("scenarios", [])
    assert len(scenarios) == threats["scenario_count"]
    for s in scenarios:
        assert "scenario_type" in s
        assert "total_supplied_frequency_per_year" in s
        assert "historical_annualized_loss" in s

def test_05_assets_merged_financial():
    """Every asset in root assets list contains both risk and financial dicts."""
    _skip()
    r = _post_analyze()
    assets = r.get("assets", [])
    assert len(assets) == 20
    for a in assets:
        assert "risk" in a, f"Asset {a.get('asset_id')} missing 'risk'"
        assert "financial" in a, f"Asset {a.get('asset_id')} missing 'financial'"
        assert "score" in a["risk"]
        assert "historical_annualized_loss" in a["financial"]

def test_06_financial_headline_key_present():
    """Assert backendAnalysis.financial.financial_summary.historical_annualized_loss is valid & positive."""
    _skip()
    r = _post_analyze()
    val = r.get("financial", {}).get("financial_summary", {}).get("historical_annualized_loss")
    assert val is not None, "historical_annualized_loss is None/missing"
    assert isinstance(val, (int, float)), f"Expected numeric, got {type(val)}"
    assert val > 0, f"Expected positive loss total, got {val}"

if __name__ == "__main__":
    print()
    print("=" * 65)
    print("PHASE 7 -- BACKEND DASHBOARD INTEGRATION TEST SUITE")
    print("=" * 65)

    if not SERVER_AVAILABLE:
        print("  [INFO] Server offline -- starting integration tests...")
    
    run_test("Test 1: Payload structure complete", test_01_payload_structure)
    run_test("Test 2: Overview risk metrics complete", test_02_overview_risk_metrics)
    run_test("Test 3: Overview financial metrics complete", test_03_overview_financial_metrics)
    run_test("Test 4: Overview threat metrics complete", test_04_overview_threat_metrics)
    run_test("Test 5: Assets merged with risk and financial", test_05_assets_merged_financial)
    run_test("Test 6: Financial headline key valid & positive", test_06_financial_headline_key_present)

    print()
    print("=" * 65)
    total = PASSED + FAILED
    print(f"RESULT: {PASSED}/{total} tests passed")
    print("=" * 65)
    import sys as _sys
    _sys.exit(0 if FAILED == 0 else 1)
