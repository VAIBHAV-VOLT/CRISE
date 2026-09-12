"""
Phase 6 ? Threat & Scenario Engine Test Suite
15 tests covering unit logic, edge cases, and HTTP integration.
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

from services.threat_engine import analyze_threats

SAMPLE_PROCESSED = {
    "assets": [
        {
            "asset_id": "A001",
            "asset": {"asset_id": "A001", "asset_name": "Core Server",
                       "asset_type": "Server", "department": "IT",
                       "criticality": 5, "business_value": 10000000.0},
            "incidents": [
                {"incident_id": "I001", "asset_id": "A001", "incident_type": "Ransomware",
                 "frequency_per_year": 0.30, "average_loss": 5000000.0, "downtime_hours": 24.0},
                {"incident_id": "I002", "asset_id": "A001", "incident_type": "Server Compromise",
                 "frequency_per_year": 0.20, "average_loss": 3000000.0, "downtime_hours": 12.0},
            ],
        },
        {
            "asset_id": "A002",
            "asset": {"asset_id": "A002", "asset_name": "Workstation",
                       "asset_type": "Endpoint", "department": "HR",
                       "criticality": 2, "business_value": 500000.0},
            "incidents": [
                {"incident_id": "I003", "asset_id": "A002", "incident_type": "Ransomware",
                 "frequency_per_year": 0.10, "average_loss": 200000.0, "downtime_hours": 8.0},
            ],
        },
    ]
}

SAMPLE_RISK = {
    "assets": [
        {"asset_id": "A001", "risk": {"score": 67.4, "level": "HIGH"}},
        {"asset_id": "A002", "risk": {"score": 25.0, "level": "LOW"}},
    ]
}

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

# Unit tests
def test_01():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    assert r["status"] == "ok", f"Expected ok, got {r['status']}"

def test_02():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    assert r["scenario_count"] == 2, f"Expected 2, got {r['scenario_count']}"

def test_03():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    ids = [s["scenario_id"] for s in r["scenarios"]]
    assert ids == ["SCN-001", "SCN-002"], f"Got {ids}"

def test_04():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    types = [s["scenario_type"] for s in r["scenarios"]]
    assert types == sorted(types), f"Not sorted: {types}"

def test_05():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    rans = next(s for s in r["scenarios"] if s["scenario_type"] == "Ransomware")
    assert rans["incident_count"] == 2
    exp_freq = round(0.30 + 0.10, 4)
    assert abs(rans["total_supplied_frequency_per_year"] - exp_freq) < 0.001
    exp_loss = round(0.30 * 5000000 + 0.10 * 200000, 2)
    assert abs(rans["historical_annualized_loss"] - exp_loss) < 1.0

def test_06():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    rans = next(s for s in r["scenarios"] if s["scenario_type"] == "Ransomware")
    ids = [a["asset_id"] for a in rans["affected_assets"]]
    assert len(ids) == len(set(ids))
    assert set(ids) == {"A001", "A002"}

def test_07():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    rans = next(s for s in r["scenarios"] if s["scenario_type"] == "Ransomware")
    assert rans["highest_risk_asset"]["asset_id"] == "A001"

def test_08():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    exp_freq = round(sum(s["total_supplied_frequency_per_year"] for s in r["scenarios"]), 4)
    assert abs(r["total_supplied_frequency_per_year"] - exp_freq) < 0.001
    exp_loss = round(sum(s["historical_annualized_loss"] for s in r["scenarios"]), 2)
    assert abs(r["total_historical_annualized_loss"] - exp_loss) < 1.0

def test_09():
    empty = {"assets": [{
        "asset_id": "A001",
        "asset": {"asset_id": "A001", "asset_name": "S", "asset_type": "Server",
                   "department": "IT", "criticality": 5, "business_value": 1000000.0},
        "incidents": [],
    }]}
    r = analyze_threats(processed_data=empty, risk_results=SAMPLE_RISK)
    assert r["status"] == "no_incident_history"
    assert r["scenario_count"] == 0
    assert r["scenarios"] == []

def test_10():
    r = analyze_threats()
    assert r["status"] == "no_incident_history"

def test_11():
    incs = [{"incident_id": "I010", "asset_id": "A001", "incident_type": "Phishing",
             "frequency_per_year": 0.50, "average_loss": 100000.0, "downtime_hours": 2.0}]
    r = analyze_threats(incidents=incs)
    assert r["status"] == "ok"
    assert r["scenario_count"] == 1
    assert r["scenarios"][0]["scenario_type"] == "Phishing"

def test_12():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    for s in r["scenarios"]:
        desc = s["description"].lower()
        assert "probability" not in desc
        assert "attack likelihood" not in desc

def test_13():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for s in r["scenarios"]:
        assert s["scenario_risk_level"] in valid

def test_14():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    try:
        json.dumps(r)
    except (TypeError, ValueError) as e:
        raise AssertionError(f"Not JSON serializable: {e}")

def test_15():
    r = analyze_threats(processed_data=SAMPLE_PROCESSED, risk_results=SAMPLE_RISK)
    for s in r["scenarios"]:
        assert "incidents" in s
        assert len(s["incidents"]) > 0
        for inc in s["incidents"]:
            assert "annualized_loss" in inc
            assert "frequency_per_year" in inc

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

def _post_analyze_empty_inc():
    hdr = b"incident_id,asset_id,incident_type,frequency_per_year,average_loss,downtime_hours\n"
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", hdr, "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/analyze", files=files, timeout=15)
    return resp.json()

def _skip():
    if not SERVER_AVAILABLE:
        raise AssertionError("SKIPPED -- server not running at 127.0.0.1:8000")

def test_I01():
    _skip()
    r = _post_analyze()
    assert r.get("success") is True
    assert "threats" in r, f"threats key missing. Keys: {list(r.keys())}"

def test_I02():
    _skip()
    r = _post_analyze()
    assert r.get("threats", {}).get("status") == "ok"

def test_I03():
    _skip()
    r = _post_analyze()
    assert r.get("threats", {}).get("scenario_count", 0) > 0

def test_I04():
    _skip()
    r = _post_analyze()
    scenarios = r.get("threats", {}).get("scenarios", [])
    required = {"scenario_id", "scenario_type", "description", "incident_count",
                "total_supplied_frequency_per_year", "historical_annualized_loss",
                "affected_asset_count", "affected_assets", "highest_risk_asset",
                "scenario_risk_level", "incidents"}
    for s in scenarios:
        missing = required - set(s.keys())
        assert not missing, f"{s.get('scenario_id')} missing: {missing}"

def test_I05():
    _skip()
    r = _post_analyze_empty_inc()
    assert r.get("threats", {}).get("status") == "no_incident_history"

if __name__ == "__main__":
    print()
    print("=" * 65)
    print("PHASE 6 -- THREAT & SCENARIO ENGINE TEST SUITE")
    print("=" * 65)

    print("\n--- UNIT TESTS ---")
    run_test("T01: Returns status ok",                          test_01)
    run_test("T02: Correct scenario count",                     test_02)
    run_test("T03: Scenario IDs deterministic",                 test_03)
    run_test("T04: Scenarios sorted by type",                   test_04)
    run_test("T05: Ransomware aggregation (freq + loss)",       test_05)
    run_test("T06: Affected assets deduplicated",               test_06)
    run_test("T07: Highest-risk asset correct",                 test_07)
    run_test("T08: Enterprise totals match scenario sums",      test_08)
    run_test("T09: Empty incidents -> no_incident_history",     test_09)
    run_test("T10: No-arg call -> no crash",                    test_10)
    run_test("T11: Direct incidents= arg works",                  test_11)
    run_test("T12: No probability claims in descriptions",      test_12)
    run_test("T13: scenario_risk_level values valid",           test_13)
    run_test("T14: Output is JSON serializable",                test_14)
    run_test("T15: Preserved incidents with annualized_loss",   test_15)

    print("\n--- INTEGRATION TESTS (HTTP) ---")
    if not SERVER_AVAILABLE:
        print("  [INFO] Server offline -- integration tests will be marked SKIPPED")
    run_test("I01: /api/analyze returns threats key",           test_I01)
    run_test("I02: threats.status == ok",                       test_I02)
    run_test("I03: scenario_count > 0 for full dataset",        test_I03)
    run_test("I04: all scenarios have required fields",         test_I04)
    run_test("I05: empty incidents -> no_incident_history",     test_I05)

    print()
    print("=" * 65)
    total = PASSED + FAILED
    print(f"RESULT: {PASSED}/{total} tests passed")
    if FAILED > 0:
        print("\nFailed:")
        for status, name, msg in RESULTS:
            if status != "PASS":
                print(f"  [{status}] {name}: {msg}")
    print("=" * 65)
    import sys as _sys
    _sys.exit(0 if FAILED == 0 else 1)
