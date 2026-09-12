"""
Comprehensive Automated Risk Engine Test Suite for Cyber Risk Analyzer (Phase 4).
Tests the calculate_risk and calculate_asset_risk functions, and the POST /api/analyze endpoint.

Verification requirements:
 1. Valid demo dataset produces a successful risk result.
 2. All 20 assets receive risk scores.
 3. Every risk score is between 0 and 100.
 4. Every asset receives exactly one risk level.
 5. Risk levels match thresholds.
 6. A001 contains vulnerability-level calculations.
 7. Active controls affect risk.
 8. Planned controls do not affect current risk.
 9. Multiple controls use combined/diminishing effectiveness.
10. Assets with no vulnerabilities are handled.
11. Assets with no active controls are handled.
12. Overall risk is business-value weighted.
13. Zero total business value uses the documented fallback.
14. Risk distribution counts sum to 20.
15. Top risk assets are sorted correctly.
16. Invalid input is rejected before risk calculation.
17. Phase 2 validation tests still pass.
18. Phase 3 processing tests still pass.

Run with: python test_risk_engine.py  (from the backend/ directory)
"""

import os
import sys
import copy
import requests

# Add backend directory to sys.path for direct module testing
sys.path.insert(0, os.path.dirname(__file__))

from services.risk_engine import (
    calculate_risk,
    calculate_asset_risk,
    calculate_vulnerability_exposure,
    get_risk_level,
)
from services.processing import process_data
from services.validation import validate_all

BASE_URL = "http://127.0.0.1:8000"
TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


def read_testfile(name: str) -> bytes:
    path = os.path.join(TESTDATA_DIR, name)
    with open(path, "rb") as f:
        return f.read()


def make_files(assets=None, vulnerabilities=None, controls=None, incidents=None):
    """Build the requests 'files' dict from raw bytes."""
    return {
        "assets": ("assets.csv", assets or read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", vulnerabilities or read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", controls or read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", incidents or read_testfile("incidents.csv"), "text/csv"),
    }


# ---------------------------------------------------------------------------
# Test 1 — Valid demo dataset produces a successful risk result via POST /api/analyze
# ---------------------------------------------------------------------------
def test_analyze_endpoint():
    print("Test 1: POST /api/analyze with demo dataset")
    r = requests.post(f"{BASE_URL}/api/analyze", files=make_files())
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert data.get("success") is True, f"Expected success=True, got {data}"
    assert "overall_risk" in data, "Missing overall_risk in response"
    assert "risk_distribution" in data, "Missing risk_distribution in response"
    assert "top_risk_assets" in data, "Missing top_risk_assets in response"
    assert "assets" in data, "Missing assets in response"
    print("[PASS] Test 1: POST /api/analyze returns 200 with complete risk result structure")
    return data


# ---------------------------------------------------------------------------
# Test 2 — All 20 assets receive risk scores
# ---------------------------------------------------------------------------
def test_all_20_assets_scored(data):
    print("Test 2: All 20 assets receive risk scores")
    assets = data.get("assets", [])
    assert len(assets) == 20, f"Expected 20 assets, got {len(assets)}"
    for a in assets:
        assert "risk" in a, f"Asset {a.get('asset_id')} missing 'risk' object"
        assert "score" in a["risk"], f"Asset {a.get('asset_id')} missing risk score"
        assert isinstance(a["risk"]["score"], (int, float)), f"Risk score not numeric for {a.get('asset_id')}"
    print("[PASS] Test 2: All 20 assets received numeric risk scores")


# ---------------------------------------------------------------------------
# Test 3 — Every risk score is between 0 and 100
# ---------------------------------------------------------------------------
def test_risk_score_bounds(data):
    print("Test 3: Every risk score is between 0 and 100")
    overall = data["overall_risk"]["score"]
    assert 0.0 <= overall <= 100.0, f"Overall risk score {overall} out of bounds [0, 100]"
    for a in data["assets"]:
        score = a["risk"]["score"]
        assert 0.0 <= score <= 100.0, f"Asset {a['asset_id']} score {score} out of bounds [0, 100]"
    print(f"[PASS] Test 3: Overall score ({overall}) and all 20 asset scores bounded within [0, 100]")


# ---------------------------------------------------------------------------
# Test 4 — Every asset receives exactly one risk level
# ---------------------------------------------------------------------------
def test_single_risk_level(data):
    print("Test 4: Every asset receives exactly one risk level")
    valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    overall_level = data["overall_risk"]["level"]
    assert overall_level in valid_levels, f"Invalid overall level: {overall_level}"
    for a in data["assets"]:
        lvl = a["risk"]["level"]
        assert lvl in valid_levels, f"Asset {a['asset_id']} has invalid level: {lvl}"
    print("[PASS] Test 4: Every asset has a valid risk level from {LOW, MEDIUM, HIGH, CRITICAL}")


# ---------------------------------------------------------------------------
# Test 5 — Risk levels match thresholds
# ---------------------------------------------------------------------------
def test_threshold_matching():
    print("Test 5: Risk levels match strict threshold definitions")
    assert get_risk_level(0.0) == "LOW"
    assert get_risk_level(25.0) == "LOW"
    assert get_risk_level(25.01) == "MEDIUM"
    assert get_risk_level(50.0) == "MEDIUM"
    assert get_risk_level(50.01) == "HIGH"
    assert get_risk_level(75.0) == "HIGH"
    assert get_risk_level(75.01) == "CRITICAL"
    assert get_risk_level(100.0) == "CRITICAL"
    print("[PASS] Test 5: Threshold boundaries strictly match (0-25: LOW, >25-50: MEDIUM, >50-75: HIGH, >75-100: CRITICAL)")


# ---------------------------------------------------------------------------
# Test 6 — A001 contains vulnerability-level calculations
# ---------------------------------------------------------------------------
def test_a001_vuln_calculations(data):
    print("Test 6: A001 contains vulnerability-level modeled exposure calculations")
    a001 = next((a for a in data["assets"] if a["asset_id"] == "A001"), None)
    assert a001 is not None, "A001 not found in response"
    vulns = a001.get("vulnerabilities", [])
    assert len(vulns) == 3, f"Expected 3 vulnerabilities for A001, got {len(vulns)}"

    v001 = next((v for v in vulns if v["vulnerability_id"] == "V001"), None)
    assert v001 is not None, "V001 missing from A001"
    assert v001["severity"] == 9.8
    assert v001["exploitability"] == 0.8
    expected_exp = round((9.8 / 10.0) * 0.8, 4)  # 0.784
    assert abs(v001["exposure_factor"] - expected_exp) < 1e-4, f"Expected {expected_exp}, got {v001['exposure_factor']}"
    print(f"[PASS] Test 6: A001 V001 modeled exposure = {v001['exposure_factor']} (matches (9.8/10)*0.8 = {expected_exp})")


# ---------------------------------------------------------------------------
# Test 7 — Active controls affect risk
# ---------------------------------------------------------------------------
def test_active_controls_reduce_risk():
    print("Test 7: Active controls affect and reduce risk")
    base_asset = {
        "asset_id": "T001",
        "asset": {
            "asset_name": "Test Server",
            "asset_type": "Server",
            "department": "IT",
            "criticality": 4,
            "business_value": 1000000.0,
            "internet_exposed": True,
            "data_sensitivity": 4,
        },
        "vulnerabilities": [
            {"vulnerability_id": "TV1", "severity": 8.0, "exploitability": 0.8}
        ],
        "controls": [],
        "incidents": []
    }

    # No controls
    res_no_ctrl = calculate_asset_risk(base_asset)

    # With active control (effectiveness 0.60)
    asset_with_ctrl = copy.deepcopy(base_asset)
    asset_with_ctrl["controls"] = [
        {"control_id": "TC1", "control_name": "MFA", "effectiveness": 0.60, "implementation_status": "Active"}
    ]
    res_with_ctrl = calculate_asset_risk(asset_with_ctrl)

    assert res_with_ctrl["risk"]["score"] < res_no_ctrl["risk"]["score"], \
        f"Active control did not reduce risk: {res_with_ctrl['risk']['score']} vs {res_no_ctrl['risk']['score']}"
    assert res_with_ctrl["risk"]["factors"]["control_effectiveness"] == 0.60
    assert res_with_ctrl["risk"]["factors"]["remaining_exposure"] == 0.40
    print(f"[PASS] Test 7: Active control reduced risk score from {res_no_ctrl['risk']['score']} to {res_with_ctrl['risk']['score']}")


# ---------------------------------------------------------------------------
# Test 8 — Planned controls do not affect current risk
# ---------------------------------------------------------------------------
def test_planned_controls_no_effect():
    print("Test 8: Planned controls do not reduce current risk")
    base_asset = {
        "asset_id": "T002",
        "asset": {
            "asset_name": "Test Server",
            "asset_type": "Server",
            "department": "IT",
            "criticality": 4,
            "business_value": 1000000.0,
            "internet_exposed": True,
            "data_sensitivity": 4,
        },
        "vulnerabilities": [
            {"vulnerability_id": "TV1", "severity": 8.0, "exploitability": 0.8}
        ],
        "controls": [],
        "incidents": []
    }

    res_no_ctrl = calculate_asset_risk(base_asset)

    asset_planned = copy.deepcopy(base_asset)
    asset_planned["controls"] = [
        {"control_id": "TC_PLANNED", "control_name": "EDR", "effectiveness": 0.80, "implementation_status": "Planned"}
    ]
    res_planned = calculate_asset_risk(asset_planned)

    assert res_planned["risk"]["score"] == res_no_ctrl["risk"]["score"], \
        f"Planned control changed risk score: {res_planned['risk']['score']} != {res_no_ctrl['risk']['score']}"
    assert res_planned["risk"]["factors"]["control_effectiveness"] == 0.0
    assert res_planned["risk"]["factors"]["remaining_exposure"] == 1.0
    assert res_planned["controls"][0]["counts_toward_current_risk"] is False
    print(f"[PASS] Test 8: Planned controls correctly excluded from current risk (score remains {res_planned['risk']['score']})")


# ---------------------------------------------------------------------------
# Test 9 — Multiple controls use combined/diminishing effectiveness
# ---------------------------------------------------------------------------
def test_multiple_controls_diminishing_return():
    print("Test 9: Multiple controls use diminishing return combination")
    asset = {
        "asset_id": "T003",
        "asset": {
            "asset_name": "Test Server",
            "asset_type": "Server",
            "department": "IT",
            "criticality": 5,
            "business_value": 5000000.0,
            "internet_exposed": True,
            "data_sensitivity": 5,
        },
        "vulnerabilities": [
            {"vulnerability_id": "TV1", "severity": 9.0, "exploitability": 0.8}
        ],
        "controls": [
            {"control_id": "C1", "control_name": "MFA", "effectiveness": 0.60, "implementation_status": "Active"},
            {"control_id": "C2", "control_name": "Firewall", "effectiveness": 0.70, "implementation_status": "Active"},
        ],
        "incidents": []
    }
    res = calculate_asset_risk(asset)
    # Expected: 1 - ((1 - 0.60) * (1 - 0.70)) = 1 - (0.40 * 0.30) = 1 - 0.12 = 0.88
    expected_eff = round(1.0 - (0.40 * 0.30), 4)
    expected_rem = round(1.0 - expected_eff, 4)
    assert abs(res["risk"]["factors"]["control_effectiveness"] - expected_eff) < 1e-4, \
        f"Expected {expected_eff}, got {res['risk']['factors']['control_effectiveness']}"
    assert abs(res["risk"]["factors"]["remaining_exposure"] - expected_rem) < 1e-4, \
        f"Expected {expected_rem}, got {res['risk']['factors']['remaining_exposure']}"
    print(f"[PASS] Test 9: Combined control effectiveness is {res['risk']['factors']['control_effectiveness']} (matches 0.88)")


# ---------------------------------------------------------------------------
# Test 10 — Assets with no vulnerabilities are handled
# ---------------------------------------------------------------------------
def test_no_vulnerabilities():
    print("Test 10: Assets with no vulnerabilities are handled")
    asset = {
        "asset_id": "T010",
        "asset": {
            "asset_name": "Clean Server",
            "asset_type": "Server",
            "department": "IT",
            "criticality": 3,
            "business_value": 500000.0,
            "internet_exposed": False,
            "data_sensitivity": 2,
        },
        "vulnerabilities": [],
        "controls": [],
        "incidents": []
    }
    res = calculate_asset_risk(asset)
    assert res["risk"]["factors"]["vulnerability_exposure"] == 0.0
    assert res["risk"]["score"] >= 0.0
    assert any("no recorded vulnerabilities" in exp.lower() for exp in res["risk"]["explanation"])
    print(f"[PASS] Test 10: Zero-vulnerability asset handled cleanly (score={res['risk']['score']}, vuln_exp=0.0)")


# ---------------------------------------------------------------------------
# Test 11 — Assets with no active controls are handled
# ---------------------------------------------------------------------------
def test_no_active_controls():
    print("Test 11: Assets with no active controls are handled")
    asset = {
        "asset_id": "T011",
        "asset": {
            "asset_name": "Unprotected Server",
            "asset_type": "Server",
            "department": "IT",
            "criticality": 4,
            "business_value": 1000000.0,
            "internet_exposed": True,
            "data_sensitivity": 4,
        },
        "vulnerabilities": [
            {"vulnerability_id": "TV1", "severity": 8.0, "exploitability": 0.8}
        ],
        "controls": [],
        "incidents": []
    }
    res = calculate_asset_risk(asset)
    assert res["risk"]["factors"]["control_effectiveness"] == 0.0
    assert res["risk"]["factors"]["remaining_exposure"] == 1.0
    assert any("no active security controls" in exp.lower() for exp in res["risk"]["explanation"])
    print(f"[PASS] Test 11: Zero-control asset handled cleanly (remaining_exposure=1.0, score={res['risk']['score']})")


# ---------------------------------------------------------------------------
# Test 12 — Overall risk is business-value weighted
# ---------------------------------------------------------------------------
def test_overall_risk_business_value_weighted():
    print("Test 12: Overall risk is business-value weighted")
    # Asset A: low score (10.0), huge value (9000000)
    # Asset B: high score (90.0), small value (1000000)
    # Expected weighted: (10*9M + 90*1M) / 10M = (90M + 90M) / 10M = 180M / 10M = 18.0
    # Simple average would be (10 + 90) / 2 = 50.0
    mock_data = {
        "assets": [
            {
                "asset_id": "A1",
                "asset": {"asset_name": "Valuable Safe Asset", "business_value": 9000000.0, "criticality": 1, "data_sensitivity": 1, "internet_exposed": False},
                "vulnerabilities": [],
                "controls": [{"control_id": "C1", "effectiveness": 0.9, "implementation_status": "Active"}],
                "incidents": []
            },
            {
                "asset_id": "A2",
                "asset": {"asset_name": "Risky Cheap Asset", "business_value": 1000000.0, "criticality": 5, "data_sensitivity": 5, "internet_exposed": True},
                "vulnerabilities": [{"vulnerability_id": "V1", "severity": 10.0, "exploitability": 1.0}],
                "controls": [],
                "incidents": []
            }
        ]
    }
    res = calculate_risk(mock_data)
    a1_score = res["assets"][0]["risk"]["score"]
    a2_score = res["assets"][1]["risk"]["score"]
    expected_weighted = round((a1_score * 9000000.0 + a2_score * 1000000.0) / 10000000.0, 2)
    assert abs(res["overall_risk"]["score"] - expected_weighted) < 0.05, \
        f"Expected business-value weighted {expected_weighted}, got {res['overall_risk']['score']}"
    print(f"[PASS] Test 12: Overall risk is properly business-value weighted ({res['overall_risk']['score']})")


# ---------------------------------------------------------------------------
# Test 13 — Zero total business value uses the documented fallback
# ---------------------------------------------------------------------------
def test_zero_business_value_fallback():
    print("Test 13: Zero total business value uses documented arithmetic average fallback")
    mock_data = {
        "assets": [
            {
                "asset_id": "A1",
                "asset": {"asset_name": "Zero Val 1", "business_value": 0.0, "criticality": 3, "data_sensitivity": 3, "internet_exposed": False},
                "vulnerabilities": [],
                "controls": [],
                "incidents": []
            },
            {
                "asset_id": "A2",
                "asset": {"asset_name": "Zero Val 2", "business_value": 0.0, "criticality": 5, "data_sensitivity": 5, "internet_exposed": True},
                "vulnerabilities": [{"vulnerability_id": "V1", "severity": 8.0, "exploitability": 0.8}],
                "controls": [],
                "incidents": []
            }
        ]
    }
    res = calculate_risk(mock_data)
    a1_score = res["assets"][0]["risk"]["score"]
    a2_score = res["assets"][1]["risk"]["score"]
    expected_avg = round((a1_score + a2_score) / 2.0, 2)
    assert abs(res["overall_risk"]["score"] - expected_avg) < 0.05, \
        f"Expected arithmetic average {expected_avg}, got {res['overall_risk']['score']}"
    print(f"[PASS] Test 13: Zero business value fallback to arithmetic mean ({res['overall_risk']['score']}) verified")


# ---------------------------------------------------------------------------
# Test 14 — Risk distribution counts sum to 20
# ---------------------------------------------------------------------------
def test_risk_distribution_sums_to_total(data):
    print("Test 14: Risk distribution counts sum to total assets (20)")
    dist = data["risk_distribution"]
    total = sum(dist.values())
    assert total == 20, f"Expected distribution sum to be 20, got {total} (dist: {dist})"
    print(f"[PASS] Test 14: Risk distribution {dist} sums to {total}")


# ---------------------------------------------------------------------------
# Test 15 — Top risk assets are sorted correctly
# ---------------------------------------------------------------------------
def test_top_risk_assets_sorted(data):
    print("Test 15: Top risk assets are sorted in descending order of risk score")
    top_assets = data["top_risk_assets"]
    assert len(top_assets) <= 10, f"Expected at most 10 top risk assets, got {len(top_assets)}"
    assert len(top_assets) > 0, "Top risk assets list is empty"
    for idx in range(len(top_assets) - 1):
        curr_score = top_assets[idx]["risk_score"]
        next_score = top_assets[idx + 1]["risk_score"]
        assert curr_score >= next_score, f"Top risk assets out of order: {curr_score} < {next_score} at index {idx}"
    print(f"[PASS] Test 15: Top {len(top_assets)} risk assets strictly sorted descending (Top asset: {top_assets[0]['asset_name']} - {top_assets[0]['risk_score']})")


# ---------------------------------------------------------------------------
# Test 16 — Invalid input is rejected before risk calculation
# ---------------------------------------------------------------------------
def test_invalid_input_rejected():
    print("Test 16: Invalid input is rejected before risk calculation")
    # Missing required column in assets
    bad_assets = b"asset_id,asset_name\nA001,Server\n"
    r = requests.post(f"{BASE_URL}/api/analyze", files=make_files(assets=bad_assets))
    assert r.status_code == 400, f"Expected 400, got {r.status_code}"
    res = r.json()
    assert res.get("success") is False
    print("[PASS] Test 16: Invalid input rejected with 400 before risk calculation")


# ---------------------------------------------------------------------------
# Test 17 — Phase 2 validation tests still pass
# ---------------------------------------------------------------------------
def test_phase2_suite():
    print("Test 17: Phase 2 validation tests pass")
    from test_validation import test_valid_dataset, test_invalid_cases
    test_valid_dataset()
    test_invalid_cases()
    print("[PASS] Test 17: Phase 2 validation test suite passed completely")


# ---------------------------------------------------------------------------
# Test 18 — Phase 3 processing tests still pass
# ---------------------------------------------------------------------------
def test_phase3_suite():
    print("Test 18: Phase 3 processing tests pass")
    from test_processing import (
        test_health,
        test_validate_demo,
        test_process_counts,
        test_a001_relationships,
        test_text_normalization,
        test_numeric_types,
        test_boolean_normalization,
        test_immutability,
        test_invalid_rejected,
    )
    test_health()
    test_validate_demo()
    proc = test_process_counts()
    test_a001_relationships(proc)
    test_text_normalization()
    test_numeric_types()
    test_boolean_normalization()
    test_immutability()
    test_invalid_rejected()
    print("[PASS] Test 18: Phase 3 processing test suite passed completely")


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("================================================================")
    print("        CYBER RISK ANALYZER — PHASE 4 RISK ENGINE TEST SUITE    ")
    print("================================================================\n")

    # Run API endpoint and risk model tests
    api_data = test_analyze_endpoint()
    test_all_20_assets_scored(api_data)
    test_risk_score_bounds(api_data)
    test_single_risk_level(api_data)
    test_threshold_matching()
    test_a001_vuln_calculations(api_data)
    test_active_controls_reduce_risk()
    test_planned_controls_no_effect()
    test_multiple_controls_diminishing_return()
    test_no_vulnerabilities()
    test_no_active_controls()
    test_overall_risk_business_value_weighted()
    test_zero_business_value_fallback()
    test_risk_distribution_sums_to_total(api_data)
    test_top_risk_assets_sorted(api_data)
    test_invalid_input_rejected()

    # Regression tests for Phase 2 & 3
    test_phase2_suite()
    test_phase3_suite()

    print("\n================================================================")
    print("   ALL 18 PHASE 4 TESTS & REGRESSIONS PASSED SUCCESSFULLY!       ")
    print("================================================================\n")
