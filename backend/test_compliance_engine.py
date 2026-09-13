"""
CRISE — Phase 14 Compliance Engine Test Suite
================================================
Comprehensive unit and integration test suite (T1 to T33) verifying:
- Framework metadata & catalog integrity
- Deterministic compliance mapping for NIST CSF 2.0, ISO 27001:2022, and CIS Controls v8
- Finding extraction from vulns, controls, internet exposure, incidents, governance
- Evidence preservation & non-probabilistic mapping basis
- Recommended actions for gaps
- Status determinations (ADDRESSED, PARTIALLY_ADDRESSED, GAP, NOT_ASSESSED)
- Modeled coverage formula & NOT_ASSESSED exclusion
- Priority derivation from Phase 4 asset risk scores
- Enterprise framework aggregations & crosswalk generation
- Edge cases: zero assets, zero vulns, zero controls, zero incidents, all active/inactive controls
- Non-mutation of input DataFrames
- FastAPI endpoint `/api/compliance` & `/api/analyze` integration
"""

import os
import sys
import pytest
import pandas as pd
from fastapi.testclient import TestClient

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(__file__))

from main import app
from services.processing import process_data
from services.risk_engine import calculate_risk
from services.compliance_engine import (
    COMPLIANCE_MAPPING,
    FRAMEWORK_METADATA,
    determine_priority,
    determine_status,
    calculate_coverage,
    extract_findings_from_crise,
    build_compliance_assessment,
)

client = TestClient(app)

TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


@pytest.fixture
def sample_dfs():
    assets_df = pd.read_csv(os.path.join(TESTDATA_DIR, "assets.csv"))
    vulnerabilities_df = pd.read_csv(os.path.join(TESTDATA_DIR, "vulnerabilities.csv"))
    controls_df = pd.read_csv(os.path.join(TESTDATA_DIR, "controls.csv"))
    incidents_df = pd.read_csv(os.path.join(TESTDATA_DIR, "incidents.csv"))
    return {
        "assets": assets_df,
        "vulnerabilities": vulnerabilities_df,
        "controls": controls_df,
        "incidents": incidents_df
    }


@pytest.fixture
def processed_and_risk(sample_dfs):
    processed = process_data(
        assets_df=sample_dfs["assets"],
        vulnerabilities_df=sample_dfs["vulnerabilities"],
        controls_df=sample_dfs["controls"],
        incidents_df=sample_dfs["incidents"]
    )
    risk_res = calculate_risk(processed)
    return processed, risk_res


# --- T1 to T4: Catalog & Framework Mapping ---

def test_t01_catalog_loads():
    """T1: Compliance mapping catalog loads and has standard keys."""
    assert len(COMPLIANCE_MAPPING) >= 5
    assert "vulnerability_management" in COMPLIANCE_MAPPING
    assert "control_gap" in COMPLIANCE_MAPPING
    assert "internet_exposure" in COMPLIANCE_MAPPING
    assert "incident_response" in COMPLIANCE_MAPPING
    assert "asset_governance" in COMPLIANCE_MAPPING


def test_t02_nist_mappings():
    """T2: NIST CSF mappings exist with verified Functions/Categories."""
    for cat_key, cat_data in COMPLIANCE_MAPPING.items():
        nist_map = cat_data["mappings"].get("NIST_CSF")
        assert nist_map is not None
        assert "function" in nist_map
        assert "control_id" in nist_map


def test_t03_iso_mappings():
    """T3: ISO 27001 mappings exist with Annex A controls."""
    for cat_key, cat_data in COMPLIANCE_MAPPING.items():
        iso_map = cat_data["mappings"].get("ISO_27001")
        assert iso_map is not None
        assert "control_id" in iso_map
        assert iso_map["control_id"].startswith("A.")


def test_t04_cis_mappings():
    """T4: CIS Controls mappings exist with verified Controls."""
    for cat_key, cat_data in COMPLIANCE_MAPPING.items():
        cis_map = cat_data["mappings"].get("CIS_CONTROLS")
        assert cis_map is not None
        assert "control_id" in cis_map
        assert cis_map["control_id"].startswith("Control")


# --- T5 to T8: Finding Extraction ---

def test_t05_vulnerability_finding_extraction(processed_and_risk):
    """T5: Known vulnerability finding maps correctly."""
    processed, risk_res = processed_and_risk
    findings = extract_findings_from_crise(processed, risk_res)
    vuln_findings = [f for f in findings if f["category"] == "vulnerability_management"]
    assert len(vuln_findings) > 0
    first_v = vuln_findings[0]
    assert first_v["finding_id"].startswith("CF-VULN-")
    assert "affected_asset_id" in first_v


def test_t06_internet_exposure_finding_extraction(processed_and_risk):
    """T6: Internet exposure finding maps correctly."""
    processed, risk_res = processed_and_risk
    findings = extract_findings_from_crise(processed, risk_res)
    net_findings = [f for f in findings if f["category"] == "internet_exposure"]
    assert len(net_findings) > 0
    first_net = net_findings[0]
    assert first_net["finding_id"].startswith("CF-NET-")


def test_t07_inactive_control_finding_extraction(processed_and_risk):
    """T7: Inactive control finding maps correctly."""
    processed, risk_res = processed_and_risk
    findings = extract_findings_from_crise(processed, risk_res)
    ctrl_findings = [f for f in findings if f["category"] == "control_gap"]
    assert len(ctrl_findings) > 0
    first_ctrl = ctrl_findings[0]
    assert first_ctrl["finding_id"].startswith("CF-CTRL-")


def test_t08_incident_finding_extraction(processed_and_risk):
    """T8: Incident finding maps correctly."""
    processed, risk_res = processed_and_risk
    findings = extract_findings_from_crise(processed, risk_res)
    inc_findings = [f for f in findings if f["category"] == "incident_response"]
    assert len(inc_findings) > 0
    first_inc = inc_findings[0]
    assert first_inc["finding_id"].startswith("CF-INC-")


# --- T9 to T11: Evidence & Explanations ---

def test_t09_evidence_preserved(processed_and_risk):
    """T9: Evidence is preserved for all compliance findings."""
    processed, risk_res = processed_and_risk
    findings = extract_findings_from_crise(processed, risk_res)
    for f in findings:
        assert "evidence" in f
        assert isinstance(f["evidence"], list)
        assert len(f["evidence"]) > 0


def test_t10_mapping_basis_exists(processed_and_risk):
    """T10: Mapping basis exists in framework items."""
    processed, risk_res = processed_and_risk
    assessment = build_compliance_assessment(processed, risk_res)
    for g in assessment["gaps"]:
        assert "mapping_basis" in g
        assert len(g["mapping_basis"]) > 0


def test_t11_recommended_action_exists_for_gaps(processed_and_risk):
    """T11: Recommended action exists for gaps and partially addressed items."""
    processed, risk_res = processed_and_risk
    assessment = build_compliance_assessment(processed, risk_res)
    for gap in assessment["gaps"]:
        assert "recommended_action" in gap
        assert len(gap["recommended_action"]) > 0


# --- T12 to T16: Status Logic ---

def test_t12_status_calculation_logic():
    """T12: Status calculation function returns valid enum values."""
    valid_statuses = {"ADDRESSED", "PARTIALLY_ADDRESSED", "GAP", "NOT_ASSESSED"}
    assert determine_status(True, 0.9, False, True) in valid_statuses
    assert determine_status(True, 0.5, True, True) in valid_statuses
    assert determine_status(False, 0.0, True, True) in valid_statuses
    assert determine_status(False, 0.0, False, False) in valid_statuses


def test_t13_addressed_status_works():
    """T13: ADDRESSED status assigned when active control high eff and no high exposure."""
    st = determine_status(has_active_controls=True, control_effectiveness=0.8, has_high_exposure=False, has_evidence=True)
    assert st == "ADDRESSED"


def test_t14_partially_addressed_status_works():
    """T14: PARTIALLY_ADDRESSED status assigned when active control exists but partial exposure."""
    st = determine_status(has_active_controls=True, control_effectiveness=0.5, has_high_exposure=True, has_evidence=True)
    assert st == "PARTIALLY_ADDRESSED"


def test_t15_gap_status_works():
    """T15: GAP status assigned when control inactive/missing and high exposure."""
    st = determine_status(has_active_controls=False, control_effectiveness=0.0, has_high_exposure=True, has_evidence=True)
    assert st == "GAP"


def test_t16_not_assessed_status_works():
    """T16: NOT_ASSESSED status assigned when insufficient evidence."""
    st = determine_status(has_active_controls=False, control_effectiveness=0.0, has_high_exposure=False, has_evidence=False)
    assert st == "NOT_ASSESSED"


# --- T17 to T18: Coverage Mathematics ---

def test_t17_modeled_coverage_formula_correct():
    """T17: Modeled coverage formula is correct: (addressed + 0.5*partially) / total_assessed * 100."""
    # 2 addressed, 2 partially, 1 gap = 2 + 1 = 3 / 5 = 60.0%
    cov = calculate_coverage(2, 2, 1)
    assert cov == 60.0


def test_t18_not_assessed_excluded_from_coverage_denominator():
    """T18: NOT_ASSESSED is excluded from coverage denominator."""
    # 1 addressed, 0 partially, 1 gap -> assessed = 2. Coverage = 1/2 = 50.0%.
    cov = calculate_coverage(1, 0, 1)
    assert cov == 50.0

    # Zero assessed items -> 0.0%
    cov_zero = calculate_coverage(0, 0, 0)
    assert cov_zero == 0.0


# --- T19 to T22: Aggregation, Crosswalk, Priority ---

def test_t19_framework_aggregation(processed_and_risk):
    """T19: Framework aggregation summarizes NIST, ISO, CIS."""
    processed, risk_res = processed_and_risk
    assessment = build_compliance_assessment(processed, risk_res)
    assert len(assessment["frameworks"]) == 3
    fw_ids = [fw["framework_id"] for fw in assessment["frameworks"]]
    assert "NIST_CSF" in fw_ids
    assert "ISO_27001" in fw_ids
    assert "CIS_CONTROLS" in fw_ids


def test_t20_crosswalk_mapping_works(processed_and_risk):
    """T20: Crosswalk mapping unifies CRISE findings across 3 frameworks."""
    processed, risk_res = processed_and_risk
    assessment = build_compliance_assessment(processed, risk_res)
    cw = assessment["crosswalk"]
    assert len(cw) > 0
    first_cw = cw[0]
    assert "mappings" in first_cw
    assert "NIST_CSF" in first_cw["mappings"]
    assert "ISO_27001" in first_cw["mappings"]
    assert "CIS_CONTROLS" in first_cw["mappings"]


def test_t21_priority_uses_existing_risk_score():
    """T21: Priority is derived strictly from existing risk scores."""
    assert determine_priority(80.0) == "CRITICAL"
    assert determine_priority(60.0) == "HIGH"
    assert determine_priority(40.0) == "MEDIUM"
    assert determine_priority(15.0) == "LOW"


def test_t22_no_new_risk_calculation_introduced(processed_and_risk):
    """T22: Compliance engine does not alter risk_results object."""
    processed, risk_res = processed_and_risk
    original_overall_risk = risk_res["overall_risk"]
    _ = build_compliance_assessment(processed, risk_res)
    assert risk_res["overall_risk"] == original_overall_risk


# --- T23 to T28: Edge Cases, Determinism & Immutability ---

def test_t23_zero_assets_handled():
    """T23: Zero assets handled cleanly returning empty assessment."""
    empty_processed = {"assets": [], "vulnerabilities": [], "controls": [], "incidents": []}
    assessment = build_compliance_assessment(empty_processed)
    assert assessment["status"] == "success"
    assert assessment["summary"]["total_findings"] == 0
    assert assessment["summary"]["total_gaps"] == 0


def test_t24_zero_vulnerabilities_handled(sample_dfs):
    """T24: Dataset with zero vulnerabilities handled cleanly."""
    processed = process_data(
        assets_df=sample_dfs["assets"],
        vulnerabilities_df=pd.DataFrame(columns=["vulnerability_id", "asset_id", "vulnerability_name", "severity", "exploitability", "status", "discovered_date"]),
        controls_df=sample_dfs["controls"],
        incidents_df=sample_dfs["incidents"]
    )
    assessment = build_compliance_assessment(processed)
    assert assessment["status"] == "success"



def test_t25_zero_controls_handled(sample_dfs):
    """T25: Dataset with zero controls handled cleanly."""
    processed = process_data(
        assets_df=sample_dfs["assets"],
        vulnerabilities_df=sample_dfs["vulnerabilities"],
        controls_df=pd.DataFrame(columns=["control_id", "control_name", "asset_id", "effectiveness", "annual_cost", "status"]),
        incidents_df=sample_dfs["incidents"]
    )
    assessment = build_compliance_assessment(processed)
    assert assessment["status"] == "success"


def test_t26_zero_incidents_handled(sample_dfs):
    """T26: Dataset with zero incidents handled cleanly."""
    processed = process_data(
        assets_df=sample_dfs["assets"],
        vulnerabilities_df=sample_dfs["vulnerabilities"],
        controls_df=sample_dfs["controls"],
        incidents_df=pd.DataFrame(columns=["incident_id", "asset_id", "incident_type", "frequency_per_year", "average_loss", "downtime_hours"])
    )
    assessment = build_compliance_assessment(processed)
    assert assessment["status"] == "success"


def test_t27_deterministic_repeated_execution(processed_and_risk):
    """T27: Multiple runs on identical input produce identical output."""
    processed, risk_res = processed_and_risk
    r1 = build_compliance_assessment(processed, risk_res)
    r2 = build_compliance_assessment(processed, risk_res)
    assert r1 == r2


def test_t28_source_data_not_mutated(processed_and_risk):
    """T28: Processed data dictionary is not mutated during assessment."""
    processed, risk_res = processed_and_risk
    asset_count_before = len(processed["assets"])
    _ = build_compliance_assessment(processed, risk_res)
    assert len(processed["assets"]) == asset_count_before


# --- T29 to T33: API Integration & Frontend Data Source ---

def test_t29_api_compliance_response_validates():
    """T29: POST /api/compliance returns 200 and schema compliant JSON."""
    files = {
        "assets": ("assets.csv", open(os.path.join(TESTDATA_DIR, "assets.csv"), "rb"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", open(os.path.join(TESTDATA_DIR, "vulnerabilities.csv"), "rb"), "text/csv"),
        "controls": ("controls.csv", open(os.path.join(TESTDATA_DIR, "controls.csv"), "rb"), "text/csv"),
        "incidents": ("incidents.csv", open(os.path.join(TESTDATA_DIR, "incidents.csv"), "rb"), "text/csv"),
    }
    response = client.post("/api/compliance", files=files)
    for _, f_obj, _ in files.values():
        f_obj.close()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "summary" in data
    assert "frameworks" in data
    assert "findings" in data
    assert "gaps" in data
    assert "crosswalk" in data


def test_t30_api_analyze_contains_compliance():
    """T30: POST /api/analyze contains top-level compliance object."""
    files = {
        "assets": ("assets.csv", open(os.path.join(TESTDATA_DIR, "assets.csv"), "rb"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", open(os.path.join(TESTDATA_DIR, "vulnerabilities.csv"), "rb"), "text/csv"),
        "controls": ("controls.csv", open(os.path.join(TESTDATA_DIR, "controls.csv"), "rb"), "text/csv"),
        "incidents": ("incidents.csv", open(os.path.join(TESTDATA_DIR, "incidents.csv"), "rb"), "text/csv"),
    }
    response = client.post("/api/analyze", files=files)
    for _, f_obj, _ in files.values():
        f_obj.close()

    assert response.status_code == 200
    data = response.json()
    assert "compliance" in data
    assert data["compliance"]["status"] == "success"


def test_t31_existing_analyze_fields_remain_intact():
    """T31: Existing POST /api/analyze response fields are preserved."""
    files = {
        "assets": ("assets.csv", open(os.path.join(TESTDATA_DIR, "assets.csv"), "rb"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", open(os.path.join(TESTDATA_DIR, "vulnerabilities.csv"), "rb"), "text/csv"),
        "controls": ("controls.csv", open(os.path.join(TESTDATA_DIR, "controls.csv"), "rb"), "text/csv"),
        "incidents": ("incidents.csv", open(os.path.join(TESTDATA_DIR, "incidents.csv"), "rb"), "text/csv"),
    }
    response = client.post("/api/analyze", files=files)
    for _, f_obj, _ in files.values():
        f_obj.close()

    assert response.status_code == 200
    data = response.json()
    required_keys = ["success", "overall_risk", "risk_distribution", "assets", "risk", "financial", "threats", "intelligence", "recommendations", "mitre", "compliance"]
    for k in required_keys:
        assert k in data


def test_t32_disclaimer_present_in_summary(processed_and_risk):
    """T32: Summary contains the required legal non-claim disclaimer."""
    processed, risk_res = processed_and_risk
    assessment = build_compliance_assessment(processed, risk_res)
    assert "disclaimer" in assessment["summary"]
    assert "not a legal" in assessment["summary"]["disclaimer"].lower()


def test_t33_coverage_percentages_bounded(processed_and_risk):
    """T33: All modeled coverage percentages are bounded in [0.0, 100.0]."""
    processed, risk_res = processed_and_risk
    assessment = build_compliance_assessment(processed, risk_res)
    for fw in assessment["frameworks"]:
        pct = fw["modeled_coverage_percentage"]
        assert 0.0 <= pct <= 100.0
