"""
Comprehensive Automated Financial Risk Engine Test Suite for Cyber Risk Analyzer (Phase 5).
Tests the calculate_financial_risk and calculate_asset_financial_risk functions,
and the POST /api/analyze endpoint with combined risk + financial output.

Verification requirements:
 1. Demo dataset produces successful financial result.
 2. All 20 assets receive financial results.
 3. Historical annualized loss is calculated correctly.
 4. Incident annualized loss equals frequency * average_loss.
 5. A001 incident loss is calculated correctly.
 6. Incident downtime is preserved.
 7. Weighted annual downtime is calculated correctly.
 8. Risk-based business exposure equals business_value * risk_score / 100.
 9. Assets without incidents are handled correctly.
10. Financial data quality correctly identifies missing incident history.
11. Enterprise financial totals equal sum of asset-level totals.
12. Top historical-loss assets are sorted correctly.
13. Top risk-exposure assets are sorted correctly.
14. Risk-level aggregation totals 20 assets.
15. Invalid data is rejected before financial calculation.
16. Phase 2 tests still pass.
17. Phase 3 tests still pass.
18. Phase 4 tests still pass.

Run with: python test_financial_engine.py  (from the backend/ directory)
"""

import os
import sys
import copy
import requests

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add backend directory to sys.path for direct module testing
sys.path.insert(0, os.path.dirname(__file__))

from services.financial_engine import (
    calculate_financial_risk,
    calculate_asset_financial_risk,
)
from services.risk_engine import calculate_risk
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
# Test 1 — Demo dataset produces successful financial result via POST /api/analyze
# ---------------------------------------------------------------------------
def test_analyze_financial_endpoint():
    print("Test 1: POST /api/analyze returns successful combined risk + financial result")
    r = requests.post(f"{BASE_URL}/api/analyze", files=make_files())
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert data.get("success") is True, f"Expected success=True, got {data}"
    assert "financial" in data, "Missing 'financial' key in analyze response"
    fin = data["financial"]
    assert "financial_summary" in fin, "Missing 'financial_summary' in financial output"
    assert "top_historical_loss_assets" in fin, "Missing 'top_historical_loss_assets' in financial output"
    assert "top_risk_exposure_assets" in fin, "Missing 'top_risk_exposure_assets' in financial output"
    assert "by_risk_level" in fin, "Missing 'by_risk_level' in financial output"
    assert "assets" in fin, "Missing 'assets' in financial output"
    print("[PASS] Test 1: POST /api/analyze returns 200 with complete financial risk engine structure")
    return data


# ---------------------------------------------------------------------------
# Test 2 — All 20 assets receive financial results
# ---------------------------------------------------------------------------
def test_all_20_assets_financial(data):
    print("Test 2: All 20 assets receive financial results")
    fin_assets = data["financial"]["assets"]
    assert len(fin_assets) == 20, f"Expected 20 assets in financial, got {len(fin_assets)}"
    for a in fin_assets:
        assert "financial" in a, f"Asset {a.get('asset_id')} missing 'financial' object"
        f = a["financial"]
        assert "business_value" in f
        assert "historical_annualized_loss" in f
        assert "risk_based_business_exposure" in f
        assert "modeled_eal" in f
        assert "incident_count" in f
        assert "total_historical_downtime_hours" in f
        assert "weighted_annual_downtime_hours" in f
    print("[PASS] Test 2: All 20 assets received complete financial metrics")


# ---------------------------------------------------------------------------
# Test 3 — Historical annualized loss is calculated correctly
# ---------------------------------------------------------------------------
def test_historical_annualized_loss_calc():
    print("Test 3: Historical annualized loss is calculated correctly as sum(frequency * average_loss)")
    asset_profile = {
        "asset_id": "T001",
        "asset": {"asset_name": "Test Asset", "business_value": 10000000.0},
        "incidents": [
            {"incident_id": "I1", "incident_type": "Phishing", "frequency_per_year": 0.5, "average_loss": 200000.0, "downtime_hours": 4.0},
            {"incident_id": "I2", "incident_type": "Malware", "frequency_per_year": 0.2, "average_loss": 500000.0, "downtime_hours": 8.0},
        ]
    }
    risk_result = {"risk": {"score": 50.0, "level": "MEDIUM"}}
    res = calculate_asset_financial_risk(asset_profile, risk_result)
    # Expected: 0.5*200000 + 0.2*500000 = 100000 + 100000 = 200000.0
    expected_loss = 200000.0
    assert res["financial"]["historical_annualized_loss"] == expected_loss, \
        f"Expected {expected_loss}, got {res['financial']['historical_annualized_loss']}"
    print(f"[PASS] Test 3: Historical annualized loss calculation verified ({res['financial']['historical_annualized_loss']})")


# ---------------------------------------------------------------------------
# Test 4 — Incident annualized loss equals frequency * average_loss
# ---------------------------------------------------------------------------
def test_incident_annualized_loss():
    print("Test 4: Incident annualized loss equals frequency * average_loss")
    asset_profile = {
        "asset_id": "T002",
        "asset": {"asset_name": "Test Asset", "business_value": 5000000.0},
        "incidents": [
            {"incident_id": "I1", "incident_type": "DDoS", "frequency_per_year": 0.35, "average_loss": 1000000.0, "downtime_hours": 10.0}
        ]
    }
    risk_result = {"risk": {"score": 30.0, "level": "MEDIUM"}}
    res = calculate_asset_financial_risk(asset_profile, risk_result)
    inc = res["incidents"][0]
    expected_ann = round(0.35 * 1000000.0, 2)  # 350000.0
    assert inc["annualized_loss"] == expected_ann, f"Expected {expected_ann}, got {inc['annualized_loss']}"
    print(f"[PASS] Test 4: Incident annualized loss verified ({inc['annualized_loss']} = 0.35 * 1,000,000)")


# ---------------------------------------------------------------------------
# Test 5 — A001 incident loss is calculated correctly (₹2,100,000)
# ---------------------------------------------------------------------------
def test_a001_financial(data):
    print("Test 5: A001 incident loss is calculated correctly (expected Rs. 2,100,000)")
    fin_assets = data["financial"]["assets"]
    a001 = next((a for a in fin_assets if a["asset_id"] == "A001"), None)
    assert a001 is not None, "A001 not found in financial assets"
    f = a001["financial"]

    # In demo dataset: I001 (0.30 * 5,000,000 = 1,500,000) + I002 (0.20 * 3,000,000 = 600,000) = 2,100,000
    expected_hist_loss = 2100000.0
    assert abs(f["historical_annualized_loss"] - expected_hist_loss) < 1.0, \
        f"Expected historical loss {expected_hist_loss}, got {f['historical_annualized_loss']}"
    assert f["incident_count"] == 2, f"Expected 2 incidents for A001, got {f['incident_count']}"
    print(f"[PASS] Test 5: A001 historical annualized loss = Rs. {f['historical_annualized_loss']:,.2f} (matches Rs. 2,100,000)")


# ---------------------------------------------------------------------------
# Test 6 — Incident downtime is preserved
# ---------------------------------------------------------------------------
def test_a001_downtime_preserved(data):
    print("Test 6: Incident downtime is preserved (A001 total downtime = 24 + 12 = 36h)")
    fin_assets = data["financial"]["assets"]
    a001 = next((a for a in fin_assets if a["asset_id"] == "A001"), None)
    f = a001["financial"]
    # I001 downtime: 24h, I002 downtime: 12h -> total 36h
    assert f["total_historical_downtime_hours"] == 36.0, \
        f"Expected 36.0 downtime hours, got {f['total_historical_downtime_hours']}"
    print(f"[PASS] Test 6: A001 total historical downtime = {f['total_historical_downtime_hours']}h")


# ---------------------------------------------------------------------------
# Test 7 — Weighted annual downtime is calculated correctly
# ---------------------------------------------------------------------------
def test_weighted_annual_downtime(data):
    print("Test 7: Weighted annual downtime is calculated correctly as sum(frequency * downtime)")
    fin_assets = data["financial"]["assets"]
    a001 = next((a for a in fin_assets if a["asset_id"] == "A001"), None)
    f = a001["financial"]
    # I001: 0.30 * 24 = 7.2h, I002: 0.20 * 12 = 2.4h -> total = 9.6h
    expected_weighted = round(0.30 * 24.0 + 0.20 * 12.0, 2)
    assert abs(f["weighted_annual_downtime_hours"] - expected_weighted) < 0.01, \
        f"Expected {expected_weighted}, got {f['weighted_annual_downtime_hours']}"
    print(f"[PASS] Test 7: A001 weighted annual downtime = {f['weighted_annual_downtime_hours']}h/year (matches {expected_weighted}h)")


# ---------------------------------------------------------------------------
# Test 8 — Risk-based business exposure equals business_value * (risk_score / 100)
# ---------------------------------------------------------------------------
def test_risk_based_business_exposure(data):
    print("Test 8: Risk-based business exposure equals business_value * (risk_score / 100)")
    fin_assets = data["financial"]["assets"]
    a001 = next((a for a in fin_assets if a["asset_id"] == "A001"), None)
    bv = a001["financial"]["business_value"]
    score = a001["risk_score"]
    exp = a001["financial"]["risk_based_business_exposure"]
    expected_exp = round(bv * (score / 100.0), 2)
    assert abs(exp - expected_exp) < 1.0, f"Expected {expected_exp}, got {exp}"
    print(f"[PASS] Test 8: A001 risk-based business exposure = Rs. {exp:,.2f} (matches {bv} * ({score}/100))")


# ---------------------------------------------------------------------------
# Test 9 — Assets without incidents are handled correctly
# ---------------------------------------------------------------------------
def test_zero_incident_asset():
    print("Test 9: Assets without incidents are handled cleanly")
    asset_profile = {
        "asset_id": "T009",
        "asset": {"asset_name": "Zero Incident Asset", "business_value": 500000.0},
        "incidents": []
    }
    risk_result = {"risk": {"score": 20.0, "level": "LOW"}}
    res = calculate_asset_financial_risk(asset_profile, risk_result)
    f = res["financial"]
    assert f["historical_annualized_loss"] == 0.0
    assert f["incident_count"] == 0
    assert f["total_historical_downtime_hours"] == 0.0
    assert f["weighted_annual_downtime_hours"] == 0.0
    assert f["historical_data_available"] is False
    assert f["financial_data_quality"] == "no_historical_incidents"
    assert f["risk_based_business_exposure"] == round(500000.0 * 0.20, 2)  # 100,000.0
    assert "no historical incidents" in f["explanation"].lower()
    print(f"[PASS] Test 9: Zero-incident asset has historical_loss=0, data_available=False, exposure={f['risk_based_business_exposure']}")


# ---------------------------------------------------------------------------
# Test 10 — Financial data quality correctly identifies missing incident history
# ---------------------------------------------------------------------------
def test_data_quality_flags():
    print("Test 10: Financial data quality correctly distinguishes data presence vs absence")
    # Asset with incidents
    a_with_inc = {
        "asset_id": "T10A",
        "asset": {"asset_name": "Has Inc", "business_value": 1000000.0},
        "incidents": [{"incident_id": "I1", "incident_type": "Breach", "frequency_per_year": 0.1, "average_loss": 500000.0, "downtime_hours": 2.0}]
    }
    res_with = calculate_asset_financial_risk(a_with_inc, {"risk": {"score": 40.0, "level": "MEDIUM"}})
    assert res_with["financial"]["historical_data_available"] is True
    assert res_with["financial"]["financial_data_quality"] == "historical_data_available"

    # Asset without incidents
    a_without_inc = {
        "asset_id": "T10B",
        "asset": {"asset_name": "No Inc", "business_value": 1000000.0},
        "incidents": []
    }
    res_without = calculate_asset_financial_risk(a_without_inc, {"risk": {"score": 40.0, "level": "MEDIUM"}})
    assert res_without["financial"]["historical_data_available"] is False
    assert res_without["financial"]["financial_data_quality"] == "no_historical_incidents"
    print("[PASS] Test 10: Financial data quality flags verified for both present and absent incident history")


# ---------------------------------------------------------------------------
# Test 11 — Enterprise financial totals equal sum of asset-level totals
# ---------------------------------------------------------------------------
def test_enterprise_totals_match_assets(data):
    print("Test 11: Enterprise financial totals strictly equal sum of asset-level totals")
    summary = data["financial"]["financial_summary"]
    assets = data["financial"]["assets"]

    sum_bv = round(sum(a["financial"]["business_value"] for a in assets), 2)
    sum_hist = round(sum(a["financial"]["historical_annualized_loss"] for a in assets), 2)
    sum_exp = round(sum(a["financial"]["risk_based_business_exposure"] for a in assets), 2)
    sum_inc = sum(a["financial"]["incident_count"] for a in assets)
    sum_down = round(sum(a["financial"]["total_historical_downtime_hours"] for a in assets), 2)
    sum_weighted_down = round(sum(a["financial"]["weighted_annual_downtime_hours"] for a in assets), 2)

    assert abs(summary["total_business_value"] - sum_bv) < 0.05
    assert abs(summary["historical_annualized_loss"] - sum_hist) < 0.05
    assert abs(summary["risk_based_business_exposure"] - sum_exp) < 0.05
    assert summary["incident_count"] == sum_inc
    assert abs(summary["historical_downtime_hours"] - sum_down) < 0.05
    assert abs(summary["weighted_annual_downtime_hours"] - sum_weighted_down) < 0.05
    print(f"[PASS] Test 11: All 6 enterprise financial totals strictly reconcile with asset sum totals:")
    print(f"        Total BV: Rs. {summary['total_business_value']:,.2f}")
    print(f"        Historical Annualized Loss: Rs. {summary['historical_annualized_loss']:,.2f}")
    print(f"        Risk-Based Exposure: Rs. {summary['risk_based_business_exposure']:,.2f}")
    print(f"        Incident Count: {summary['incident_count']}")


# ---------------------------------------------------------------------------
# Test 12 — Top historical-loss assets are sorted correctly
# ---------------------------------------------------------------------------
def test_top_historical_loss_sorted(data):
    print("Test 12: Top historical-loss assets are sorted descending")
    top_hist = data["financial"]["top_historical_loss_assets"]
    assert len(top_hist) <= 10
    assert len(top_hist) > 0
    for idx in range(len(top_hist) - 1):
        curr = top_hist[idx]["historical_annualized_loss"]
        nxt = top_hist[idx + 1]["historical_annualized_loss"]
        assert curr >= nxt, f"Historical loss out of order: {curr} < {nxt} at {idx}"
    print(f"[PASS] Test 12: Top {len(top_hist)} historical-loss assets sorted descending (Top: {top_hist[0]['asset_name']} - Rs. {top_hist[0]['historical_annualized_loss']:,.2f})")


# ---------------------------------------------------------------------------
# Test 13 — Top risk-exposure assets are sorted correctly
# ---------------------------------------------------------------------------
def test_top_risk_exposure_sorted(data):
    print("Test 13: Top risk-exposure assets are sorted descending")
    top_exp = data["financial"]["top_risk_exposure_assets"]
    assert len(top_exp) <= 10
    assert len(top_exp) > 0
    for idx in range(len(top_exp) - 1):
        curr = top_exp[idx]["risk_based_business_exposure"]
        nxt = top_exp[idx + 1]["risk_based_business_exposure"]
        assert curr >= nxt, f"Risk exposure out of order: {curr} < {nxt} at {idx}"
    print(f"[PASS] Test 13: Top {len(top_exp)} risk-exposure assets sorted descending (Top: {top_exp[0]['asset_name']} - Rs. {top_exp[0]['risk_based_business_exposure']:,.2f})")


# ---------------------------------------------------------------------------
# Test 14 — Risk-level aggregation totals 20 assets
# ---------------------------------------------------------------------------
def test_by_risk_level_totals(data):
    print("Test 14: Risk-level aggregation categories sum to 20 assets")
    by_lvl = data["financial"]["by_risk_level"]
    total_assets = sum(v["asset_count"] for v in by_lvl.values())
    assert total_assets == 20, f"Expected 20 assets in by_risk_level, got {total_assets}"
    print(f"[PASS] Test 14: Risk-level aggregation sums to {total_assets} assets across critical, high, medium, low")


# ---------------------------------------------------------------------------
# Test 15 — Invalid data is rejected before financial calculation
# ---------------------------------------------------------------------------
def test_invalid_rejected_financial():
    print("Test 15: Invalid data is rejected with 400 before financial calculation")
    bad_assets = b"asset_id,asset_name\nA001,Server\n"
    r = requests.post(f"{BASE_URL}/api/analyze", files=make_files(assets=bad_assets))
    assert r.status_code == 400, f"Expected 400, got {r.status_code}"
    res = r.json()
    assert res.get("success") is False
    print("[PASS] Test 15: Invalid data rejected with 400 before financial calculation")


# ---------------------------------------------------------------------------
# Test 16 — Phase 2 validation tests pass
# ---------------------------------------------------------------------------
def test_phase2_regressions():
    print("Test 16: Phase 2 validation regression suite passes")
    from test_validation import test_valid_dataset, test_invalid_cases
    test_valid_dataset()
    test_invalid_cases()
    print("[PASS] Test 16: Phase 2 validation tests pass completely")


# ---------------------------------------------------------------------------
# Test 17 — Phase 3 processing tests pass
# ---------------------------------------------------------------------------
def test_phase3_regressions():
    print("Test 17: Phase 3 processing regression suite passes")
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
    print("[PASS] Test 17: Phase 3 processing tests pass completely")


# ---------------------------------------------------------------------------
# Test 18 — Phase 4 risk engine tests pass
# ---------------------------------------------------------------------------
def test_phase4_regressions():
    print("Test 18: Phase 4 risk engine regression suite passes")
    from test_risk_engine import (
        test_analyze_endpoint,
        test_all_20_assets_scored,
        test_risk_score_bounds,
        test_single_risk_level,
        test_threshold_matching,
        test_a001_vuln_calculations,
        test_active_controls_reduce_risk,
        test_planned_controls_no_effect,
        test_multiple_controls_diminishing_return,
        test_no_vulnerabilities,
        test_no_active_controls,
        test_overall_risk_business_value_weighted,
        test_zero_business_value_fallback,
        test_risk_distribution_sums_to_total,
        test_top_risk_assets_sorted,
    )
    d = test_analyze_endpoint()
    test_all_20_assets_scored(d)
    test_risk_score_bounds(d)
    test_single_risk_level(d)
    test_threshold_matching()
    test_a001_vuln_calculations(d)
    test_active_controls_reduce_risk()
    test_planned_controls_no_effect()
    test_multiple_controls_diminishing_return()
    test_no_vulnerabilities()
    test_no_active_controls()
    test_overall_risk_business_value_weighted()
    test_zero_business_value_fallback()
    test_risk_distribution_sums_to_total(d)
    test_top_risk_assets_sorted(d)
    print("[PASS] Test 18: Phase 4 risk engine tests pass completely")


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=================================================================")
    print("   CYBER RISK ANALYZER — PHASE 5 FINANCIAL RISK ENGINE TESTS    ")
    print("=================================================================\n")

    api_data = test_analyze_financial_endpoint()
    test_all_20_assets_financial(api_data)
    test_historical_annualized_loss_calc()
    test_incident_annualized_loss()
    test_a001_financial(api_data)
    test_a001_downtime_preserved(api_data)
    test_weighted_annual_downtime(api_data)
    test_risk_based_business_exposure(api_data)
    test_zero_incident_asset()
    test_data_quality_flags()
    test_enterprise_totals_match_assets(api_data)
    test_top_historical_loss_sorted(api_data)
    test_top_risk_exposure_sorted(api_data)
    test_by_risk_level_totals(api_data)
    test_invalid_rejected_financial()

    # Regressions
    test_phase2_regressions()
    test_phase3_regressions()
    test_phase4_regressions()

    print("\n=================================================================")
    print("   ALL 18 PHASE 5 TESTS & REGRESSIONS PASSED SUCCESSFULLY!        ")
    print("=================================================================\n")
