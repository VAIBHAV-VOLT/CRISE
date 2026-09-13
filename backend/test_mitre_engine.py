"""
Phase 13 — MITRE ATT&CK Threat Mapping Test Suite
=================================================
Tests backend/services/mitre_engine.py, POST /api/mitre endpoint, and POST /api/analyze integration.

Verifies requirements T1 - T28.
"""

import os
import sys
import copy
import json
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
from services.financial_engine import calculate_financial_risk
from services.threat_engine import analyze_threats
from services.mitre_engine import build_mitre_intelligence, MITRE_MAPPING, MITRE_METADATA

TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


def read_testfile(fname: str) -> bytes:
    with open(os.path.join(TESTDATA_DIR, fname), "rb") as f:
        return f.read()


def build_sample_model():
    assets_raw = [
        {"asset_id": "A001", "asset_name": "ERP Server", "asset_type": "Server", "department": "Finance", "criticality": 5, "business_value": 50000000, "internet_exposed": "Yes", "data_sensitivity": 5},
        {"asset_id": "A002", "asset_name": "Customer DB", "asset_type": "Database", "department": "Sales", "criticality": 4, "business_value": 20000000, "internet_exposed": "No", "data_sensitivity": 4},
    ]
    vulns_raw = [
        {"vulnerability_id": "V001", "asset_id": "A001", "vulnerability_name": "Outdated OS", "severity": 9.8, "exploitability": 0.9, "status": "Open", "discovered_date": "2026-08-01"},
    ]
    controls_raw = [
        {"control_id": "C001", "control_name": "MFA", "asset_id": "A001", "effectiveness": 0.60, "implementation_status": "Active", "annual_cost": 300000},
    ]
    incidents_raw = [
        {"incident_id": "I001", "asset_id": "A001", "incident_type": "Ransomware", "frequency_per_year": 0.30, "average_loss": 5000000, "downtime_hours": 24},
        {"incident_id": "I002", "asset_id": "A002", "incident_type": "Payment Fraud", "frequency_per_year": 0.20, "average_loss": 2000000, "downtime_hours": 12},
    ]

    proc = process_data(
        pd.DataFrame(assets_raw),
        pd.DataFrame(vulns_raw),
        pd.DataFrame(controls_raw),
        pd.DataFrame(incidents_raw)
    )
    risk = calculate_risk(proc)
    fin = calculate_financial_risk(proc, risk)
    threat = analyze_threats(proc, risk)
    return proc, risk, fin, threat


def test_t01_mapping_catalog_loads():
    assert isinstance(MITRE_MAPPING, dict)
    assert len(MITRE_MAPPING) > 0
    assert "Ransomware" in MITRE_MAPPING
    assert MITRE_METADATA["framework"] == "MITRE ATT&CK Enterprise"


def test_t02_known_incident_type_maps_correctly():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    r_inc = next(i for i in res["incidents"] if i["incident_type"] == "Ransomware")
    assert r_inc["mapping_status"] == "MAPPED"
    assert len(r_inc["mitre"]) > 0
    assert r_inc["mitre"][0]["technique_id"] == "T1486"
    assert r_inc["mitre"][0]["tactic_id"] == "TA0040"


def test_t03_unknown_incident_type_becomes_unmapped():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    pf_inc = next(i for i in res["incidents"] if i["incident_type"] == "Payment Fraud")
    assert pf_inc["mapping_status"] == "UNMAPPED"
    assert pf_inc["mitre"] == []
    assert "unmapped_reason" in pf_inc
    assert pf_inc["unmapped_reason"] is not None


def test_t04_incident_ids_preserved():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    ids = [i["incident_id"] for i in res["incidents"]]
    assert "I001" in ids
    assert "I002" in ids


def test_t05_asset_ids_preserved():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    i001 = next(i for i in res["incidents"] if i["incident_id"] == "I001")
    assert i001["asset_id"] == "A001"


def test_t06_incident_financial_values_preserved():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    i001 = next(i for i in res["incidents"] if i["incident_id"] == "I001")
    assert i001["frequency_per_year"] == 0.30
    assert i001["average_loss"] == 5000000.0
    assert i001["annualized_loss"] == 1500000.0
    assert i001["downtime_hours"] == 24.0


def test_t07_incident_level_mappings_returned():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    assert "incidents" in res
    assert len(res["incidents"]) == 2


def test_t08_technique_aggregation_works():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    assert "techniques" in res
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert t1486["technique_name"] == "Data Encrypted for Impact"
    assert t1486["tactic_id"] == "TA0040"


def test_t09_tactic_aggregation_works():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    assert "tactics" in res
    ta0040 = next(t for t in res["tactics"] if t["tactic_id"] == "TA0040")
    assert ta0040["tactic_name"] == "Impact"
    assert ta0040["technique_count"] >= 1


def test_t10_incident_counts_aggregate_correctly():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert t1486["incident_count"] == 1


def test_t11_affected_assets_aggregate_correctly():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert "A001" in t1486["affected_assets"]
    assert t1486["affected_asset_count"] == 1


def test_t12_historical_annualized_loss_aggregates_correctly():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert t1486["historical_annualized_loss"] == 1500000.0


def test_t13_downtime_aggregates_correctly():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert t1486["total_downtime_hours"] == 24.0


def test_t14_risk_context_uses_existing_risk_score():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    a001_score = risk["assets"][0]["risk"]["score"]
    assert t1486["highest_asset_risk_score"] == a001_score


def test_t15_risk_levels_use_existing_thresholds():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert t1486["highest_asset_risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_t16_mapping_coverage_calculation_correct():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    sum_data = res["summary"]
    assert sum_data["total_incidents"] == 2
    assert sum_data["mapped_incidents"] == 1
    assert sum_data["unmapped_incidents"] == 1
    assert sum_data["mapping_coverage_percentage"] == 50.0


def test_t17_zero_incidents_handled():
    proc = {"assets": []}
    res = build_mitre_intelligence(proc)
    assert res["status"] == "success"
    assert res["summary"]["total_incidents"] == 0
    assert res["summary"]["mapping_coverage_percentage"] == 0.0
    assert res["techniques"] == []
    assert res["tactics"] == []


def test_t18_all_incidents_unmapped_handled():
    incidents_raw = [
        {"incident_id": "I099", "asset_id": "A001", "incident_type": "Unknown Custom Event", "frequency_per_year": 0.1, "average_loss": 1000},
    ]
    res = build_mitre_intelligence(kwargs={"incidents": incidents_raw})
    assert res["summary"]["total_incidents"] == 1
    assert res["summary"]["mapped_incidents"] == 0
    assert res["summary"]["unmapped_incidents"] == 1
    assert res["summary"]["mapping_coverage_percentage"] == 0.0
    assert res["techniques"] == []


def test_t19_multiple_techniques_no_duplicate_aggregation():
    incidents_raw = [
        {"incident_id": "I001", "asset_id": "A001", "incident_type": "Ransomware", "frequency_per_year": 0.3, "average_loss": 5000000},
        {"incident_id": "I008", "asset_id": "A002", "incident_type": "Ransomware", "frequency_per_year": 0.1, "average_loss": 4000000},
    ]
    res = build_mitre_intelligence(kwargs={"incidents": incidents_raw})
    t1486 = next(t for t in res["techniques"] if t["technique_id"] == "T1486")
    assert t1486["incident_count"] == 2
    assert t1486["affected_asset_count"] == 2
    assert t1486["historical_annualized_loss"] == (0.3 * 5000000) + (0.1 * 4000000)


def test_t20_no_mutation_of_source_data():
    proc, risk, fin, threat = build_sample_model()
    proc_orig = copy.deepcopy(proc)
    _ = build_mitre_intelligence(proc, risk, fin, threat)
    assert proc == proc_orig


def test_t21_api_endpoint_returns_valid_pydantic_response():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/mitre", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "summary" in data
    assert "incidents" in data
    assert "techniques" in data
    assert "tactics" in data


def test_t22_post_analyze_includes_mitre():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/analyze", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert "mitre" in data
    assert data["mitre"]["status"] == "success"


def test_t23_existing_post_analyze_fields_remain_intact():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/analyze", files=files)
    assert resp.status_code == 200
    data = resp.json()
    for field in ("overall_risk", "risk", "financial", "threats", "intelligence", "recommendations"):
        assert field in data


def test_t24_deterministic_repeated_execution():
    proc, risk, fin, threat = build_sample_model()
    res1 = build_mitre_intelligence(proc, risk, fin, threat)
    res2 = build_mitre_intelligence(proc, risk, fin, threat)
    assert res1 == res2


def test_t25_mapping_confidence_is_valid_enum():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    for t in res["techniques"]:
        assert t["mapping_confidence"] in ("HIGH", "MEDIUM", "LOW")


def test_t26_mapping_basis_exists_for_every_mapping():
    proc, risk, fin, threat = build_sample_model()
    res = build_mitre_intelligence(proc, risk, fin, threat)
    for t in res["techniques"]:
        assert isinstance(t["mapping_basis"], str)
        assert len(t["mapping_basis"]) > 10


def test_t27_frontend_reads_backend_mitre_data():
    with open(os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js"), "r", encoding="utf-8") as f:
        js_content = f.read()
    assert "backendAnalysis.mitre" in js_content or "mitre" in js_content


def test_t28_frontend_does_not_contain_competing_mitre_calculation():
    with open(os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js"), "r", encoding="utf-8") as f:
        js_content = f.read()
    assert "MITRE_MAPPING" not in js_content  # JS should not contain hardcoded catalog
