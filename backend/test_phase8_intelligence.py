"""
Phase 8 ? Asset & Vulnerability Intelligence Test Suite
=======================================================
20 automated tests covering unit logic, edge cases, and HTTP integration.
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

from services.intelligence_engine import build_intelligence
from services.risk_engine import calculate_risk
from services.financial_engine import calculate_financial_risk
from services.threat_engine import analyze_threats
from services.processing import process_data

SAMPLE_PROCESSED = {
    "assets": [
        {
            "asset_id": "A001",
            "asset": {"asset_id": "A001", "asset_name": "Core Server",
                       "asset_type": "Server", "department": "IT",
                       "criticality": 5, "business_value": 10000000.0,
                       "internet_exposed": True, "data_sensitivity": 5},
            "vulnerabilities": [
                {"vulnerability_id": "V001", "asset_id": "A001", "vulnerability_name": "RCE",
                 "severity": 9.8, "exploitability": 0.8, "status": "Open", "discovered_date": "2026-08-01"},
            ],
            "controls": [
                {"control_id": "C001", "asset_id": "A001", "control_name": "MFA",
                 "effectiveness": 0.6, "implementation_status": "Active", "annual_cost": 300000.0},
            ],
            "incidents": [
                {"incident_id": "I001", "asset_id": "A001", "incident_type": "Ransomware",
                 "frequency_per_year": 0.3, "average_loss": 5000000.0, "downtime_hours": 24.0},
            ],
        },
        {
            "asset_id": "A002",
            "asset": {"asset_id": "A002", "asset_name": "Workstation",
                       "asset_type": "Endpoint", "department": "HR",
                       "criticality": 2, "business_value": 500000.0,
                       "internet_exposed": False, "data_sensitivity": 2},
            "vulnerabilities": [],
            "controls": [],
            "incidents": [],
        },
    ]
}

SAMPLE_RISK = calculate_risk(SAMPLE_PROCESSED)
SAMPLE_FINANCIAL = calculate_financial_risk(SAMPLE_PROCESSED, SAMPLE_RISK)
SAMPLE_THREATS = analyze_threats(SAMPLE_PROCESSED, SAMPLE_RISK)

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

# --- UNIT TESTS ---

def test_T01_returns_intelligence():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    assert intel.get("status") == "ok"
    assert "assets" in intel
    assert "vulnerabilities" in intel
    assert "summary" in intel

def test_T02_asset_profile_completeness():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a001 = next(a for a in intel["assets"] if a["asset_id"] == "A001")
    required = {"asset_id", "asset_name", "criticality", "business_value", "risk", "financial", "vulnerabilities", "controls", "incidents"}
    missing = required - set(a001.keys())
    assert not missing, f"Missing fields: {missing}"

def test_T03_asset_risk_matches_phase4():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a001 = next(a for a in intel["assets"] if a["asset_id"] == "A001")
    p4_score = next(a["risk"]["score"] for a in SAMPLE_RISK["assets"] if a["asset_id"] == "A001")
    assert a001["risk"]["score"] == p4_score

def test_T04_asset_financial_matches_phase5():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a001 = next(a for a in intel["assets"] if a["asset_id"] == "A001")
    p5_loss = next(a["financial"]["historical_annualized_loss"] for a in SAMPLE_FINANCIAL["assets"] if a["asset_id"] == "A001")
    assert a001["financial"]["historical_annualized_loss"] == p5_loss

def test_T05_vulns_mapped_correctly():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a001 = next(a for a in intel["assets"] if a["asset_id"] == "A001")
    assert len(a001["vulnerabilities"]) == 1
    assert a001["vulnerabilities"][0]["vulnerability_id"] == "V001"

def test_T06_controls_mapped_correctly():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a001 = next(a for a in intel["assets"] if a["asset_id"] == "A001")
    assert len(a001["controls"]) == 1
    assert a001["controls"][0]["control_id"] == "C001"

def test_T07_incidents_mapped_correctly():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a001 = next(a for a in intel["assets"] if a["asset_id"] == "A001")
    assert len(a001["incidents"]) == 1
    assert a001["incidents"][0]["incident_id"] == "I001"

def test_T08_vuln_exposure_formula():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    v001 = next(v for v in intel["vulnerabilities"] if v["vulnerability_id"] == "V001")
    expected = round((9.8 / 10.0) * 0.8, 4)  # 0.784
    assert v001["vulnerability_exposure"] == expected

def test_T09_top_risk_assets_ordered():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    top_assets = intel["top_risk_assets"]
    scores = [a["risk_score"] for a in top_assets]
    assert scores == sorted(scores, reverse=True)

def test_T10_top_vulns_ordered():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    top_vulns = intel["top_vulnerabilities"]
    sevs = [v["severity"] for v in top_vulns]
    assert sevs == sorted(sevs, reverse=True)

def test_T11_summary_vuln_severity_counts():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    summary = intel["summary"]
    assert summary["total_vulnerabilities"] == 1
    assert summary["critical_vulnerabilities"] == 1  # 9.8 >= 9.0

def test_T12_summary_asset_distribution():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    summary = intel["summary"]
    dist = summary["asset_risk_distribution"]
    assert sum(dist.values()) == 2

def test_T13_no_vulns_asset_handled():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a002 = next(a for a in intel["assets"] if a["asset_id"] == "A002")
    assert a002["vulnerability_count"] == 0
    assert a002["vulnerabilities"] == []

def test_T14_no_controls_asset_handled():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a002 = next(a for a in intel["assets"] if a["asset_id"] == "A002")
    assert a002["control_count"] == 0
    assert a002["controls"] == []

def test_T15_no_incidents_asset_handled():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    a002 = next(a for a in intel["assets"] if a["asset_id"] == "A002")
    assert a002["incident_count"] == 0
    assert a002["financial"]["historical_data_available"] is False

def test_T16_empty_vulnerabilities_handled():
    empty_proc = {
        "assets": [
            {
                "asset_id": "A001",
                "asset": {"asset_id": "A001", "asset_name": "S", "asset_type": "Server", "business_value": 100.0},
                "vulnerabilities": [],
                "controls": [],
                "incidents": [],
            }
        ]
    }
    intel = build_intelligence(empty_proc)
    assert intel["status"] == "ok"
    assert intel["summary"]["total_vulnerabilities"] == 0

def test_T17_empty_incidents_handled():
    intel = build_intelligence(SAMPLE_PROCESSED)
    assert intel["status"] == "ok"

def test_T18_json_serializable():
    intel = build_intelligence(SAMPLE_PROCESSED, SAMPLE_RISK, SAMPLE_FINANCIAL, SAMPLE_THREATS)
    try:
        json.dumps(intel)
    except Exception as e:
        raise AssertionError(f"JSON dump failed: {e}")

# --- HTTP INTEGRATION TESTS ---

def test_T19_api_analyze_contains_intelligence():
    _skip()
    r = _post_analyze()
    assert r.get("success") is True
    assert "intelligence" in r, f"Key missing from response. Keys: {list(r.keys())}"
    intel = r["intelligence"]
    assert intel.get("status") == "ok"
    assert len(intel["assets"]) == 20
    assert len(intel["vulnerabilities"]) == 30

def test_T20_api_analyze_retains_previous_sections():
    _skip()
    r = _post_analyze()
    required = {"risk", "financial", "threats", "intelligence"}
    missing = required - set(r.keys())
    assert not missing, f"Missing top-level sections: {missing}"

if __name__ == "__main__":
    print()
    print("=" * 65)
    print("PHASE 8 -- ASSET & VULNERABILITY INTELLIGENCE TEST SUITE")
    print("=" * 65)

    print("\n--- UNIT TESTS ---")
    run_test("T01: Returns status ok and intelligence sections", test_T01_returns_intelligence)
    run_test("T02: Asset profile completeness",                test_T02_asset_profile_completeness)
    run_test("T03: Asset risk matches Phase 4 output",          test_T03_asset_risk_matches_phase4)
    run_test("T04: Asset financial matches Phase 5 output",     test_T04_asset_financial_matches_phase5)
    run_test("T05: Vulnerabilities mapped to correct asset IDs",test_T05_vulns_mapped_correctly)
    run_test("T06: Controls mapped to correct asset IDs",       test_T06_controls_mapped_correctly)
    run_test("T07: Incidents mapped to correct asset IDs",      test_T07_incidents_mapped_correctly)
    run_test("T08: Vulnerability exposure formula correct",     test_T08_vuln_exposure_formula)
    run_test("T09: Top risk assets deterministically ordered",  test_T09_top_risk_assets_ordered)
    run_test("T10: Top vulnerabilities ordered",               test_T10_top_vulns_ordered)
    run_test("T11: Summary vuln severity counts correct",      test_T11_summary_vuln_severity_counts)
    run_test("T12: Summary asset risk distribution correct",    test_T12_summary_asset_distribution)
    run_test("T13: Asset without vulnerabilities handled",      test_T13_no_vulns_asset_handled)
    run_test("T14: Asset without controls handled",             test_T14_no_controls_asset_handled)
    run_test("T15: Asset without incidents handled",            test_T15_no_incidents_asset_handled)
    run_test("T16: Empty vulnerabilities dataset handled",     test_T16_empty_vulnerabilities_handled)
    run_test("T17: Empty incidents dataset handled",           test_T17_empty_incidents_handled)
    run_test("T18: Intelligence output JSON serializable",      test_T18_json_serializable)

    print("\n--- INTEGRATION TESTS (HTTP) ---")
    if not SERVER_AVAILABLE:
        print("  [INFO] Server offline -- skipping integration tests")
    run_test("T19: /api/analyze contains intelligence section", test_T19_api_analyze_contains_intelligence)
    run_test("T20: /api/analyze retains all previous sections", test_T20_api_analyze_retains_previous_sections)

    print()
    print("=" * 65)
    total = PASSED + FAILED
    print(f"RESULT: {PASSED}/{total} tests passed")
    print("=" * 65)
    import sys as _sys
    _sys.exit(0 if FAILED == 0 else 1)
