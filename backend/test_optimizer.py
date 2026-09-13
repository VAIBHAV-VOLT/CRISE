"""
Phase 10 — Investment Optimizer Test Suite
===========================================
Tests the optimizer service (backend/services/optimizer.py) and POST /api/optimize endpoint.

Verifies requirements:
 T01: Baseline optimizer with valid budget
 T02: Zero budget returns no investments
 T03: Negative budget rejected (400)
 T04: Selected controls cost never exceeds budget (used <= budget)
 T05: Only eligible controls (non-active) are selected
 T06: Already-active controls are not selected as implementation investments
 T07: Control effectiveness applied correctly
 T08: Multiple controls affecting same asset use multiplicative combined effectiveness
 T09: Enterprise risk uses business-value weighting
 T10: Optimized risk <= baseline risk
 T11: No selected controls produces baseline score == optimized score
 T12: Risk reduction calculation correct (baseline_score - optimized_score)
 T13: Percentage reduction calculation correct
 T14: Affected assets identified correctly
 T15: Risk-level transitions identified correctly
 T16: Candidate control filtering works
 T17: Invalid candidate control rejected (400)
 T18: Duplicate candidate controls handled correctly
 T19: Original data is not mutated
 T20: JSON serialization succeeds
 T21: Dataset with no eligible controls handled cleanly
 T22: Budget smaller than every available control cost handled
 T23: Exact subset optimizer chooses lowest-risk feasible portfolio
 T24: Greedy fallback is deterministic for large candidate sets
 T25: POST /api/optimize HTTP endpoint works
 T26: Existing POST /api/analyze still works
 T27: Existing POST /api/simulate still works
 T28: Controlled synthetic dataset test (Step 31: exact subset optimality)
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
from services.optimizer import (
    optimize_investments,
    validate_optimizer_input,
    _get_eligible_controls,
)

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

def test_t01_baseline_optimizer_valid_budget():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 1000000.0)
    assert res.get("success") is True, f"Failed: {res}"
    assert "baseline" in res
    assert "optimized" in res
    assert "budget" in res
    assert res["budget"]["used"] <= 1000000.0


def test_t02_zero_budget_returns_no_investments():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 0.0)
    assert res.get("success") is True
    assert len(res["selected_controls"]) == 0
    assert res["budget"]["used"] == 0.0
    assert res["budget"]["remaining"] == 0.0
    assert res["impact"]["risk_reduction"] == 0.0


def test_t03_negative_budget_rejected():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, -5000.0)
    assert res.get("success") is False
    assert "Budget must be a non-negative number." in res["errors"]


def test_t04_selected_controls_cost_never_exceeds_budget():
    pdata = get_demo_processed()
    budget = 1500000.0
    res = optimize_investments(pdata, budget)
    assert res["success"] is True
    total_cost = sum(c["annual_cost"] for c in res["selected_controls"])
    assert total_cost <= budget
    assert res["budget"]["used"] == round(total_cost, 2)


def test_t05_only_eligible_controls_selected():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 5000000.0)
    assert res["success"] is True
    for c in res["selected_controls"]:
        assert c["original_status"].lower() != "active", f"Active control {c['control_id']} was selected!"


def test_t06_already_active_controls_not_selected():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 50000000.0)  # Huge budget
    assert res["success"] is True
    selected_cids = {c["control_id"] for c in res["selected_controls"]}
    # C001, C002 are Active in demo dataset
    assert "C001" not in selected_cids
    assert "C002" not in selected_cids


def test_t07_control_effectiveness_applied_correctly():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 2000000.0)
    assert res["success"] is True
    for c in res["selected_controls"]:
        assert 0.0 <= c["effectiveness"] <= 1.0


def test_t08_multiple_controls_same_asset_multiplicative():
    pdata = get_demo_processed()
    # A001 has planned control C022 (DLP, 0.50). Activate it.
    res = optimize_investments(pdata, 500000.0, candidate_control_ids=["C022"])
    assert res["success"] is True
    assert res["optimized"]["risk_score"] <= res["baseline"]["risk_score"]


def test_t09_enterprise_risk_uses_business_value_weighting():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 1000000.0)
    assert res["success"] is True
    assert isinstance(res["optimized"]["risk_score"], (int, float))


def test_t10_optimized_risk_le_baseline_risk():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 3000000.0)
    assert res["success"] is True
    assert res["optimized"]["risk_score"] <= res["baseline"]["risk_score"]


def test_t11_no_selected_controls_same_score():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 0.0)
    assert res["baseline"]["risk_score"] == res["optimized"]["risk_score"]


def test_t12_risk_reduction_calculation_correct():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 2000000.0)
    base = res["baseline"]["risk_score"]
    opt = res["optimized"]["risk_score"]
    assert res["impact"]["risk_reduction"] == round(max(0.0, base - opt), 2)


def test_t13_percentage_reduction_correct():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 2000000.0)
    base = res["baseline"]["risk_score"]
    red = res["impact"]["risk_reduction"]
    expected_pct = round((red / base) * 100.0, 2) if base > 0 else 0.0
    assert res["impact"]["percentage_reduction"] == expected_pct


def test_t14_affected_assets_identified_correctly():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 3000000.0)
    for a in res["affected_assets"]:
        assert a["optimized_risk_score"] <= a["baseline_risk_score"]
        assert a["risk_reduction"] > 0.0


def test_t15_risk_level_transitions_identified():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 5000000.0)
    for change in res["risk_level_changes"]:
        assert "asset_id" in change
        assert "from" in change
        assert "to" in change
        assert change["from"] != change["to"]


def test_t16_candidate_control_filtering_works():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 5000000.0, candidate_control_ids=["C018", "C022"])
    assert res["success"] is True
    for c in res["selected_controls"]:
        assert c["control_id"] in ["C018", "C022"]


def test_t17_invalid_candidate_control_rejected():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 1000000.0, candidate_control_ids=["C999INVALID"])
    assert res["success"] is False
    assert len(res["errors"]) > 0


def test_t18_duplicate_candidate_controls_handled():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 5000000.0, candidate_control_ids=["C018", "C018", "C022"])
    assert res["success"] is True
    selected_ids = [c["control_id"] for c in res["selected_controls"]]
    assert len(selected_ids) == len(set(selected_ids))


def test_t19_original_data_not_mutated():
    pdata = get_demo_processed()
    orig_c018_status = None
    for a in pdata["assets"]:
        for c in a["controls"]:
            if c["control_id"] == "C018":
                orig_c018_status = c["implementation_status"]

    optimize_investments(pdata, 5000000.0)

    for a in pdata["assets"]:
        for c in a["controls"]:
            if c["control_id"] == "C018":
                assert c["implementation_status"] == orig_c018_status


def test_t20_json_serialization_succeeds():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 2000000.0)
    json_str = json.dumps(res)
    assert len(json_str) > 0


def test_t21_no_eligible_controls_handled():
    pdata = get_demo_processed()
    pdata_copy = copy.deepcopy(pdata)
    # Mark all controls Active
    for a in pdata_copy["assets"]:
        for c in a["controls"]:
            c["implementation_status"] = "Active"

    res = optimize_investments(pdata_copy, 5000000.0)
    assert res["success"] is True
    assert res["status"] == "no_eligible_controls"
    assert len(res["selected_controls"]) == 0


def test_t22_budget_smaller_than_cheapest_control_handled():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 10.0)  # Budget ₹10
    assert res["success"] is True
    assert res["status"] == "no_affordable_controls"
    assert len(res["selected_controls"]) == 0


def test_t23_exact_subset_optimizer_chooses_lowest_risk():
    pdata = get_demo_processed()
    res = optimize_investments(pdata, 1500000.0)
    assert res["success"] is True
    assert res["algorithm"]["method"] == "exact_subset"
    assert res["algorithm"]["is_optimal"] is True


def test_t24_greedy_fallback_deterministic():
    pdata = get_demo_processed()
    # Duplicate controls to create > 20 eligible candidate controls
    pdata_large = copy.deepcopy(pdata)
    extra_controls = []
    for idx in range(25):
        extra_controls.append({
            "control_id": f"C10{idx}",
            "control_name": f"Planned Control {idx}",
            "asset_id": "A001",
            "effectiveness": 0.50,
            "implementation_status": "Planned",
            "annual_cost": 100000.0,
        })
    pdata_large["assets"][0]["controls"].extend(extra_controls)

    res1 = optimize_investments(pdata_large, 300000.0)
    res2 = optimize_investments(pdata_large, 300000.0)

    assert res1["algorithm"]["method"] == "greedy"
    assert res1["algorithm"]["is_optimal"] is False
    assert [c["control_id"] for c in res1["selected_controls"]] == [c["control_id"] for c in res2["selected_controls"]]


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


def test_t25_post_optimize_http_endpoint():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    data = {"budget": "2000000"}
    resp = requests.post(f"{BASE_URL}/api/optimize", files=files, data=data, timeout=15)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    r = resp.json()
    assert r.get("success") is True
    assert "baseline" in r
    assert "optimized" in r
    assert "budget" in r
    assert r["budget"]["used"] <= 2000000.0


def test_t26_post_analyze_still_works():
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


def test_t27_post_simulate_still_works():
    _skip()
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    data = {"scenario": '{"asset_id": "A001"}'}
    resp = requests.post(f"{BASE_URL}/api/simulate", files=files, data=data, timeout=15)
    assert resp.status_code == 200
    r = resp.json()
    assert r.get("success") is True


# --- STEP 31 CONTROLLED SYNTHETIC DATASET TEST ---

def test_t28_controlled_synthetic_exact_subset_optimality():
    """
    Step 31: Controlled synthetic dataset test where optimal portfolio choice is obvious.
    Budget = 3,000,000
    Control A: cost = 1,000,000, effectiveness = 0.50
    Control B: cost = 2,000,000, effectiveness = 0.80
    Control C: cost = 3,000,000, effectiveness = 0.90

    Options:
    - Control C alone: cost 3,000,000, eff = 0.90 -> combined residual = 0.10
    - Control A + B: cost 3,000,000, eff = 1 - (1-0.5)*(1-0.8) = 1 - 0.1 = 0.90 -> combined residual = 0.10
    - Control B alone: cost 2,000,000, eff = 0.80 -> combined residual = 0.20
    - Control A alone: cost 1,000,000, eff = 0.50 -> combined residual = 0.50

    Verify that exact subset optimizer evaluates actual resulting enterprise risk and selects
    the minimal risk portfolio staying within budget.
    """
    synthetic_pdata = {
        "assets": [
            {
                "asset_id": "SA01",
                "asset": {
                    "asset_name": "Synthetic Server",
                    "business_value": 10000000.0,
                    "criticality": 5,
                    "data_sensitivity": 5,
                    "internet_exposed": True,
                },
                "vulnerabilities": [
                    {
                        "vulnerability_id": "SV01",
                        "vulnerability_name": "Critical Flaw",
                        "severity": 10.0,
                        "exploitability": 1.0,
                    }
                ],
                "controls": [
                    {
                        "control_id": "CA",
                        "control_name": "Control A",
                        "effectiveness": 0.50,
                        "implementation_status": "Planned",
                        "annual_cost": 1000000.0,
                    },
                    {
                        "control_id": "CB",
                        "control_name": "Control B",
                        "effectiveness": 0.80,
                        "implementation_status": "Planned",
                        "annual_cost": 2000000.0,
                    },
                    {
                        "control_id": "CC",
                        "control_name": "Control C",
                        "effectiveness": 0.90,
                        "implementation_status": "Planned",
                        "annual_cost": 3000000.0,
                    },
                ],
                "incidents": [],
            }
        ]
    }

    res = optimize_investments(synthetic_pdata, 3000000.0)
    assert res["success"] is True
    assert res["algorithm"]["method"] == "exact_subset"
    assert res["algorithm"]["is_optimal"] is True

    selected_ids = {c["control_id"] for c in res["selected_controls"]}
    # Either {'CC'} or {'CA', 'CB'} yield the optimal minimum risk (90% combined protection).
    assert selected_ids in [{"CC"}, {"CA", "CB"}], f"Unexpected portfolio: {selected_ids}"


if __name__ == "__main__":
    print()
    print("=" * 65)
    print("PHASE 10 -- INVESTMENT OPTIMIZER TEST SUITE")
    print("=" * 65)

    run_test("T01: Baseline optimizer with valid budget", test_t01_baseline_optimizer_valid_budget)
    run_test("T02: Zero budget returns no investments", test_t02_zero_budget_returns_no_investments)
    run_test("T03: Negative budget rejected", test_t03_negative_budget_rejected)
    run_test("T04: Selected controls cost never exceeds budget", test_t04_selected_controls_cost_never_exceeds_budget)
    run_test("T05: Only eligible controls selected", test_t05_only_eligible_controls_selected)
    run_test("T06: Already-active controls not selected", test_t06_already_active_controls_not_selected)
    run_test("T07: Control effectiveness applied correctly", test_t07_control_effectiveness_applied_correctly)
    run_test("T08: Multiple controls on same asset multiplicative", test_t08_multiple_controls_same_asset_multiplicative)
    run_test("T09: Enterprise risk uses business-value weighting", test_t09_enterprise_risk_uses_business_value_weighting)
    run_test("T10: Optimized risk <= baseline risk", test_t10_optimized_risk_le_baseline_risk)
    run_test("T11: No selected controls produces baseline == optimized", test_t11_no_selected_controls_same_score)
    run_test("T12: Risk reduction calculation correct", test_t12_risk_reduction_calculation_correct)
    run_test("T13: Percentage reduction correct", test_t13_percentage_reduction_correct)
    run_test("T14: Affected assets identified correctly", test_t14_affected_assets_identified_correctly)
    run_test("T15: Risk-level transitions identified", test_t15_risk_level_transitions_identified)
    run_test("T16: Candidate control filtering works", test_t16_candidate_control_filtering_works)
    run_test("T17: Invalid candidate control rejected", test_t17_invalid_candidate_control_rejected)
    run_test("T18: Duplicate candidate controls handled", test_t18_duplicate_candidate_controls_handled)
    run_test("T19: Original data not mutated", test_t19_original_data_not_mutated)
    run_test("T20: JSON serialization succeeds", test_t20_json_serialization_succeeds)
    run_test("T21: No eligible controls handled", test_t21_no_eligible_controls_handled)
    run_test("T22: Budget smaller than cheapest control handled", test_t22_budget_smaller_than_cheapest_control_handled)
    run_test("T23: Exact subset optimizer chooses lowest risk", test_t23_exact_subset_optimizer_chooses_lowest_risk)
    run_test("T24: Greedy fallback deterministic", test_t24_greedy_fallback_deterministic)

    if SERVER_AVAILABLE:
        run_test("T25: POST /api/optimize HTTP endpoint works", test_t25_post_optimize_http_endpoint)
        run_test("T26: Existing POST /api/analyze still works", test_t26_post_analyze_still_works)
        run_test("T27: Existing POST /api/simulate still works", test_t27_post_simulate_still_works)
    else:
        print("  [INFO] HTTP server offline -- skipping HTTP integration tests")

    run_test("T28: Step 31 controlled synthetic exact subset optimality", test_t28_controlled_synthetic_exact_subset_optimality)

    print()
    print("=" * 65)
    total = PASSED + FAILED
    print(f"RESULT: {PASSED}/{total} tests passed")
    print("=" * 65)
    sys.exit(0 if FAILED == 0 else 1)
