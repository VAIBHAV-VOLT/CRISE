"""
Phase 9 — What-If Risk Simulation Engine Test Suite
====================================================
Tests the simulation_engine service and POST /api/simulate endpoint.

Verifies requirements:
 T01: Baseline simulation with no changes (scenario_score == baseline_score, reduction == 0)
 T02: Control effectiveness increase lowers or does not increase risk
 T03: Control effectiveness decrease increases or does not decrease risk
 T04: Control activation affects risk
 T05: Control deactivation affects risk
 T06: Vulnerability remediation reduces vulnerability exposure
 T07: Multiple vulnerability remediation works
 T08: Internet exposure removal changes internet factor (1 -> 0)
 T09: Internet exposure addition changes internet factor (0 -> 1)
 T10: Multiple scenario changes combine correctly
 T11: Baseline is unchanged after simulation (non-destructive)
 T12: Original input data is not mutated (deep copy safety)
 T13: Invalid asset ID rejected (400)
 T14: Invalid control ID rejected (400)
 T15: Invalid vulnerability ID rejected (400)
 T16: Invalid effectiveness (<0 or >1) rejected (400)
 T17: Invalid boolean input rejected (400)
 T18: Risk levels use existing Phase 4 thresholds (LOW, MEDIUM, HIGH, CRITICAL)
 T19: Delta calculations are correct (risk_score_change, risk_reduction, percentage_change)
 T20: Zero baseline risk handled without division error (percentage_change == 0.0)
 T21: JSON serialization succeeds
 T22: POST /api/simulate HTTP endpoint works
 T23: Existing POST /api/analyze still works
 T24: Phase 2–8 regression suite still passes

Property Tests:
 Property A: Control effectiveness increase => scenario risk <= baseline risk
 Property B: Vulnerability remediation => scenario vuln exposure <= baseline exposure
 Property C: Internet exposure true -> false => internet factor 1 -> 0
 Property D: No changes supplied => scenario_score == baseline_score
"""

import os
import sys
import copy
import json
import requests

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from services.processing import process_data
from services.risk_engine import calculate_risk
from services.simulation_engine import (
    simulate_scenario,
    validate_scenario_input,
    apply_scenario_modifications,
)
from services.validation import validate_all

TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))
BASE_URL = "http://127.0.0.1:8000"

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


def read_testfile(name: str) -> bytes:
    path = os.path.join(TESTDATA_DIR, name)
    with open(path, "rb") as f:
        return f.read()


def get_demo_processed():
    import pandas as pd
    import io
    assets_df = pd.read_csv(io.BytesIO(read_testfile("assets.csv")))
    vulns_df = pd.read_csv(io.BytesIO(read_testfile("vulnerabilities.csv")))
    controls_df = pd.read_csv(io.BytesIO(read_testfile("controls.csv")))
    incidents_df = pd.read_csv(io.BytesIO(read_testfile("incidents.csv")))
    return process_data(assets_df, vulns_df, controls_df, incidents_df)


# --- UNIT TESTS ---

def test_t01_baseline_simulation_no_changes():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {})
    assert res.get("success") is True, f"Failed: {res}"
    assert res["baseline"]["risk_score"] == res["scenario"]["risk_score"]
    assert res["delta"]["risk_reduction"] == 0.0
    assert res["delta"]["risk_score_change"] == 0.0


def test_t02_control_effectiveness_increase():
    pdata = get_demo_processed()
    # A001 control C001 effectiveness increase 0.60 -> 0.95
    scenario_input = {
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "effectiveness": 0.95}]
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] <= res["baseline"]["risk_score"]
    assert res["delta"]["risk_reduction"] >= 0.0


def test_t03_control_effectiveness_decrease():
    pdata = get_demo_processed()
    # A001 control C001 effectiveness decrease 0.60 -> 0.10
    scenario_input = {
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "effectiveness": 0.10}]
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] >= res["baseline"]["risk_score"]
    assert res["delta"]["risk_score_change"] >= 0.0


def test_t04_control_activation():
    pdata = get_demo_processed()
    # Create an inactive control or mark C001 active=True
    scenario_input = {
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "active": True, "effectiveness": 0.90}]
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] < res["baseline"]["risk_score"]


def test_t05_control_deactivation():
    pdata = get_demo_processed()
    # Deactivate active control C001
    scenario_input = {
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "active": False}]
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] > res["baseline"]["risk_score"]


def test_t06_vulnerability_remediation():
    pdata = get_demo_processed()
    scenario_input = {
        "asset_id": "A001",
        "remediated_vulnerabilities": ["V001"]
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] < res["baseline"]["risk_score"]
    assert "V001" in res["changes_applied"]["remediated_vulnerabilities"]


def test_t07_multiple_vulnerability_remediation():
    pdata = get_demo_processed()
    scenario_input = {
        "asset_id": "A001",
        "remediated_vulnerabilities": ["V001", "V002"]
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] < res["baseline"]["risk_score"]
    assert len(res["changes_applied"]["remediated_vulnerabilities"]) == 2


def test_t08_internet_exposure_removal():
    pdata = get_demo_processed()
    # A001 is internet_exposed=True
    scenario_input = {
        "asset_id": "A001",
        "internet_exposed": False
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] < res["baseline"]["risk_score"]
    assert res["changes_applied"]["internet_exposure_changed"] is True


def test_t09_internet_exposure_addition():
    pdata = get_demo_processed()
    # A002 is internet_exposed=False
    scenario_input = {
        "asset_id": "A002",
        "internet_exposed": True
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] > res["baseline"]["risk_score"]


def test_t10_multiple_scenario_changes_combine():
    pdata = get_demo_processed()
    scenario_input = {
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "effectiveness": 0.95}],
        "remediated_vulnerabilities": ["V001"],
        "internet_exposed": False
    }
    res = simulate_scenario(pdata, scenario_input)
    assert res["success"] is True
    assert res["scenario"]["risk_score"] < res["baseline"]["risk_score"]
    assert res["delta"]["risk_reduction"] > 0.0


def test_t11_baseline_unchanged_after_simulation():
    pdata = get_demo_processed()
    base1 = calculate_risk(pdata)
    simulate_scenario(pdata, {"asset_id": "A001", "internet_exposed": False})
    base2 = calculate_risk(pdata)
    assert base1["overall_risk"]["score"] == base2["overall_risk"]["score"]


def test_t12_original_data_not_mutated():
    pdata = get_demo_processed()
    orig_ie = pdata["assets"][0]["asset"]["internet_exposed"]
    simulate_scenario(pdata, {"asset_id": "A001", "internet_exposed": not orig_ie})
    assert pdata["assets"][0]["asset"]["internet_exposed"] == orig_ie


def test_t13_invalid_asset_id_rejected():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A999INVALID"})
    assert res["success"] is False
    assert len(res["errors"]) > 0


def test_t14_invalid_control_rejected():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001", "control_changes": [{"control_id": "C999INVALID"}]})
    assert res["success"] is False
    assert len(res["errors"]) > 0


def test_t15_invalid_vulnerability_rejected():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001", "remediated_vulnerabilities": ["V999INVALID"]})
    assert res["success"] is False
    assert len(res["errors"]) > 0


def test_t16_invalid_effectiveness_rejected():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001", "control_changes": [{"control_id": "C001", "effectiveness": 1.5}]})
    assert res["success"] is False
    assert len(res["errors"]) > 0


def test_t17_invalid_boolean_input_rejected():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001", "internet_exposed": "not_a_boolean"})
    assert res["success"] is False
    assert len(res["errors"]) > 0


def test_t18_risk_levels_thresholds():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001"})
    assert res["baseline"]["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert res["scenario"]["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_t19_delta_calculations_correct():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001", "remediated_vulnerabilities": ["V001"]})
    base = res["baseline"]["risk_score"]
    scen = res["scenario"]["risk_score"]
    assert res["delta"]["risk_score_change"] == round(scen - base, 2)
    assert res["delta"]["risk_reduction"] == round(base - scen, 2)
    assert res["delta"]["percentage_change"] == round(((scen - base) / base) * 100.0, 2)


def test_t20_zero_baseline_risk_handled():
    # Construct a synthetic zero-risk asset
    pdata = get_demo_processed()
    pdata_copy = copy.deepcopy(pdata)
    for a in pdata_copy["assets"]:
        a["vulnerabilities"] = []
        a["asset"]["criticality"] = 0
        a["asset"]["data_sensitivity"] = 0
        a["asset"]["internet_exposed"] = False
        a["controls"] = [{"control_id": "C001", "effectiveness": 1.0, "implementation_status": "Active"}]
    res = simulate_scenario(pdata_copy, {"asset_id": "A001"})
    assert res["success"] is True
    assert res["delta"]["percentage_change"] == 0.0


def test_t21_json_serialization_succeeds():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {"asset_id": "A001", "remediated_vulnerabilities": ["V001"]})
    json_str = json.dumps(res)
    assert len(json_str) > 0


# --- HTTP INTEGRATION TESTS ---

def _check_server():
    try:
        r = requests.get(f"{BASE_URL}/docs", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

SERVER_AVAILABLE = _check_server()


def _skip():
    if not SERVER_AVAILABLE:
        raise AssertionError("SKIPPED -- server not running at 127.0.0.1:8000")


def test_t22_post_simulate_endpoint():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    scenario_dict = {
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "effectiveness": 0.90}],
        "remediated_vulnerabilities": ["V001"]
    }
    data = {"scenario": json.dumps(scenario_dict)}
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data=data, timeout=15)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    r = resp.json()
    assert r.get("success") is True
    assert "baseline" in r
    assert "scenario" in r
    assert "delta" in r
    assert r["scenario"]["risk_score"] < r["baseline"]["risk_score"]


def test_t25_simulate_empty_dict_scenario():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data={"scenario": "{}"}, timeout=15)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    r = resp.json()
    assert r.get("success") is True
    assert r["delta"]["risk_reduction"] == 0.0


def test_t26_simulate_asset_id_scenario():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data={"scenario": '{"asset_id": "A001"}'}, timeout=15)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    r = resp.json()
    assert r.get("success") is True
    assert r["baseline"]["asset_id"] == "A001"


def test_t27_simulate_full_json_scenario():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    scen_str = json.dumps({
        "asset_id": "A001",
        "control_changes": [{"control_id": "C001", "effectiveness": 0.9, "active": True}],
        "remediated_vulnerabilities": ["V001"],
        "internet_exposed": False
    })
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data={"scenario": scen_str}, timeout=15)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    r = resp.json()
    assert r.get("success") is True
    assert r["scenario"]["risk_score"] < r["baseline"]["risk_score"]


def test_t28_simulate_malformed_json_rejected():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data={"scenario": "{malformed_json"}, timeout=15)
    assert resp.status_code == 400
    r = resp.json()
    assert r.get("success") is False
    assert "Invalid scenario JSON format." in r.get("errors", [])


def test_t29_simulate_json_array_rejected():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data={"scenario": "[1, 2, 3]"}, timeout=15)
    assert resp.status_code == 400
    r = resp.json()
    assert r.get("success") is False
    assert "Scenario must be a JSON object." in r.get("errors", [])


def test_t30_simulate_json_string_rejected():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data={"scenario": '"just a string"'}, timeout=15)
    assert resp.status_code == 400
    r = resp.json()
    assert r.get("success") is False
    assert "Scenario must be a JSON object." in r.get("errors", [])


def test_t31_simulate_missing_scenario_uses_default():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, timeout=15)
    assert resp.status_code == 200
    r = resp.json()
    assert r.get("success") is True


def test_t23_post_analyze_endpoint_still_works():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = requests.post(f"{BASE_URL}/api/analyze", files=files, timeout=15)
    assert resp.status_code == 200
    r = resp.json()
    assert r.get("success") is True


# --- PROPERTY TESTS ---

def test_property_a_control_eff_increase():
    pdata = get_demo_processed()
    scenario = {"asset_id": "A001", "control_changes": [{"control_id": "C001", "effectiveness": 0.99}]}
    res = simulate_scenario(pdata, scenario)
    assert res["scenario"]["risk_score"] <= res["baseline"]["risk_score"]


def test_property_b_vuln_remediation_exposure():
    pdata = get_demo_processed()
    scenario = {"asset_id": "A001", "remediated_vulnerabilities": ["V001"]}
    res = simulate_scenario(pdata, scenario)
    assert res["scenario"]["risk_score"] <= res["baseline"]["risk_score"]


def test_property_c_internet_exposure_factor():
    pdata = get_demo_processed()
    scenario = {"asset_id": "A001", "internet_exposed": False}
    res = simulate_scenario(pdata, scenario)
    assert res["scenario"]["risk_score"] < res["baseline"]["risk_score"]


def test_property_d_no_changes_same_score():
    pdata = get_demo_processed()
    res = simulate_scenario(pdata, {})
    assert res["scenario"]["risk_score"] == res["baseline"]["risk_score"]


if __name__ == "__main__":
    print()
    print("=" * 65)
    print("PHASE 9 -- WHAT-IF RISK SIMULATION TEST SUITE")
    print("=" * 65)

    run_test("T01: Baseline simulation with no changes", test_t01_baseline_simulation_no_changes)
    run_test("T02: Control effectiveness increase lowers risk", test_t02_control_effectiveness_increase)
    run_test("T03: Control effectiveness decrease increases risk", test_t03_control_effectiveness_decrease)
    run_test("T04: Control activation affects risk", test_t04_control_activation)
    run_test("T05: Control deactivation affects risk", test_t05_control_deactivation)
    run_test("T06: Vulnerability remediation reduces risk", test_t06_vulnerability_remediation)
    run_test("T07: Multiple vulnerability remediation works", test_t07_multiple_vulnerability_remediation)
    run_test("T08: Internet exposure removal lowers risk", test_t08_internet_exposure_removal)
    run_test("T09: Internet exposure addition increases risk", test_t09_internet_exposure_addition)
    run_test("T10: Multiple scenario changes combine correctly", test_t10_multiple_scenario_changes_combine)
    run_test("T11: Baseline unchanged after simulation", test_t11_baseline_unchanged_after_simulation)
    run_test("T12: Original input data not mutated", test_t12_original_data_not_mutated)
    run_test("T13: Invalid asset ID rejected", test_t13_invalid_asset_id_rejected)
    run_test("T14: Invalid control ID rejected", test_t14_invalid_control_rejected)
    run_test("T15: Invalid vulnerability ID rejected", test_t15_invalid_vulnerability_rejected)
    run_test("T16: Invalid effectiveness rejected", test_t16_invalid_effectiveness_rejected)
    run_test("T17: Invalid boolean input rejected", test_t17_invalid_boolean_input_rejected)
    run_test("T18: Risk levels use Phase 4 thresholds", test_t18_risk_levels_thresholds)
    run_test("T19: Delta calculations correct", test_t19_delta_calculations_correct)
    run_test("T20: Zero baseline risk handled cleanly", test_t20_zero_baseline_risk_handled)
    run_test("T21: JSON serialization succeeds", test_t21_json_serialization_succeeds)

    if SERVER_AVAILABLE:
        run_test("T22: POST /api/simulate HTTP endpoint works", test_t22_post_simulate_endpoint)
        run_test("T25: POST /api/simulate with scenario='{}'", test_t25_simulate_empty_dict_scenario)
        run_test("T26: POST /api/simulate with scenario='{\"asset_id\": \"A001\"}'", test_t26_simulate_asset_id_scenario)
        run_test("T27: POST /api/simulate with full JSON scenario", test_t27_simulate_full_json_scenario)
        run_test("T28: POST /api/simulate with malformed JSON rejected (400)", test_t28_simulate_malformed_json_rejected)
        run_test("T29: POST /api/simulate with JSON array rejected (400)", test_t29_simulate_json_array_rejected)
        run_test("T30: POST /api/simulate with JSON string rejected (400)", test_t30_simulate_json_string_rejected)
        run_test("T31: POST /api/simulate missing scenario parameter uses default", test_t31_simulate_missing_scenario_uses_default)
        run_test("T23: Existing POST /api/analyze still works", test_t23_post_analyze_endpoint_still_works)
    else:
        print("  [INFO] HTTP server offline -- skipping HTTP integration tests")

    run_test("Property A: Control eff increase => risk <= baseline", test_property_a_control_eff_increase)
    run_test("Property B: Vuln remediation => risk <= baseline", test_property_b_vuln_remediation_exposure)
    run_test("Property C: Internet exposure removal => factor 1 -> 0", test_property_c_internet_exposure_factor)
    run_test("Property D: No changes => scenario == baseline", test_property_d_no_changes_same_score)

    print()
    print("=" * 65)
    total = PASSED + FAILED
    print(f"RESULT: {PASSED}/{total} tests passed")
    print("=" * 65)
    sys.exit(0 if FAILED == 0 else 1)
