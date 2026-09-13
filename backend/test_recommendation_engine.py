"""
Phase 11 — Recommendation Engine Test Suite
============================================
Tests backend/services/recommendation_engine.py and POST /api/analyze recommendations integration.

Verifies requirements T01 - T29.
"""

import os
import sys
import copy
import json
import pytest
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
from services.intelligence_engine import build_intelligence
from services.optimizer import optimize_investments
from services.recommendation_engine import generate_recommendations

TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


import pandas as pd

def build_sample_model():
    assets_raw = [
        {"asset_id": "A001", "asset_name": "ERP Server", "asset_type": "Server", "department": "Finance", "criticality": 5, "business_value": 100000000, "internet_exposed": "Yes", "data_sensitivity": 5},
        {"asset_id": "A002", "asset_name": "Customer DB", "asset_type": "Database", "department": "Sales", "criticality": 4, "business_value": 20000000, "internet_exposed": "No", "data_sensitivity": 4},
    ]
    vulns_raw = [
        {"vulnerability_id": "V001", "asset_id": "A001", "vulnerability_name": "Outdated OS", "severity": 9.8, "exploitability": 0.9, "status": "Open", "discovered_date": "2026-08-01"},
        {"vulnerability_id": "V002", "asset_id": "A002", "vulnerability_name": "Weak Auth", "severity": 5.0, "exploitability": 0.4, "status": "Open", "discovered_date": "2026-08-05"},
    ]
    controls_raw = [
        {"control_id": "C001", "control_name": "MFA", "asset_id": "A001", "effectiveness": 0.10, "implementation_status": "Active", "annual_cost": 300000},
        {"control_id": "C002", "control_name": "EDR", "asset_id": "A001", "effectiveness": 0.70, "implementation_status": "Planned", "annual_cost": 40000},
        {"control_id": "C003", "control_name": "Backup", "asset_id": "A002", "effectiveness": 0.50, "implementation_status": "Inactive", "annual_cost": 25000},
    ]
    incidents_raw = [
        {"incident_id": "I001", "asset_id": "A001", "incident_type": "Ransomware", "frequency_per_year": 0.30, "average_loss": 5000000, "downtime_hours": 24},
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
    intel = build_intelligence(proc, risk, fin, threat)
    opt = optimize_investments(proc, budget=100000)

    return proc, risk, fin, threat, intel, opt


def test_t01_empty_dataset_returns_valid_structure():
    proc = {"assets": []}
    res = generate_recommendations(proc)
    assert isinstance(res, dict)
    assert res["status"] == "no_recommendations"
    assert res["summary"]["total_recommendations"] == 0
    assert res["recommendations"] == []
    assert res["quick_wins"] == []


def test_t02_high_risk_asset_generates_asset_protection_rec():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    categories = [r["category"] for r in res["recommendations"]]
    assert "ASSET_PROTECTION" in categories
    rec = next(r for r in res["recommendations"] if r["category"] == "ASSET_PROTECTION")
    assert rec["asset_id"] == "A001"
    assert rec["priority"] in ("CRITICAL", "HIGH")


def test_t03_high_severity_vuln_generates_remediation_rec():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    recs = [r for r in res["recommendations"] if r["category"] == "VULNERABILITY_REMEDIATION"]
    assert len(recs) > 0
    v1_rec = next(r for r in recs if r["evidence"].get("vulnerability_id") == "V001")
    assert v1_rec["evidence"]["severity"] == 9.8
    assert v1_rec["evidence"]["exploitability"] == 0.9


def test_t04_inactive_control_generates_implementation_rec():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    c_recs = [r for r in res["recommendations"] if r["category"] == "CONTROL_IMPLEMENTATION"]
    c_ids = [r["evidence"]["control_id"] for r in c_recs]
    assert "C002" in c_ids
    assert "C003" in c_ids
    assert "C001" not in c_ids  # C001 is Active


def test_t05_internet_exposed_asset_generates_exposure_reduction_rec():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    exp_recs = [r for r in res["recommendations"] if r["category"] == "EXPOSURE_REDUCTION"]
    assert len(exp_recs) == 1
    assert exp_recs[0]["asset_id"] == "A001"
    assert exp_recs[0]["evidence"]["internet_exposed"] is True


def test_t06_incident_history_generates_mitigation_rec():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    inc_recs = [r for r in res["recommendations"] if r["category"] == "INCIDENT_MITIGATION"]
    assert len(inc_recs) >= 1
    assert inc_recs[0]["asset_id"] == "A001"


def test_t07_vulnerability_exposure_formula_correctness():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    rec = next(r for r in res["recommendations"] if r.get("evidence", {}).get("vulnerability_id") == "V001")
    exp = (9.8 / 10.0) * 0.9
    assert abs(rec["evidence"]["vulnerability_exposure"] - round(exp, 4)) < 1e-4


def test_t08_priority_critical_assigned_correctly():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    crit_recs = [r for r in res["recommendations"] if r["priority"] == "CRITICAL"]
    assert len(crit_recs) > 0


def test_t09_priority_high_assigned_correctly():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    high_recs = [r for r in res["recommendations"] if r["priority"] == "HIGH"]
    assert len(high_recs) > 0


def test_t10_priority_medium_assigned_correctly():
    proc = {
        "assets": [
            {
                "asset_id": "A088",
                "asset": {"asset_name": "Internal Server", "internet_exposed": False},
                "vulnerabilities": [{"vulnerability_id": "V088", "severity": 5.0, "exploitability": 0.4}],
                "controls": [{"control_id": "C088", "control_name": "Medium Control", "implementation_status": "Inactive", "effectiveness": 0.45, "annual_cost": 20000}],
                "incidents": []
            }
        ]
    }
    risk = {"assets": [{"asset_id": "A088", "risk": {"score": 35.0, "level": "MEDIUM"}}]}
    res = generate_recommendations(proc, risk)
    med_recs = [r for r in res["recommendations"] if r["priority"] == "MEDIUM"]
    assert len(med_recs) > 0


def test_t11_priority_low_assigned_correctly():
    proc = {
        "assets": [
            {
                "asset_id": "A099",
                "asset": {"asset_name": "Low Risk Printer", "internet_exposed": False},
                "vulnerabilities": [{"vulnerability_id": "V099", "severity": 4.0, "exploitability": 0.4}],
                "controls": [{"control_id": "C099", "control_name": "Paper Check", "implementation_status": "Inactive", "effectiveness": 0.1, "annual_cost": 1000}],
                "incidents": []
            }
        ]
    }
    risk = {"assets": [{"asset_id": "A099", "risk": {"score": 10.0, "level": "LOW"}}]}
    res = generate_recommendations(proc, risk)
    low_recs = [r for r in res["recommendations"] if r["priority"] == "LOW"]
    assert len(low_recs) > 0


def test_t12_elevation_of_priority_extreme_vuln():
    proc = {
        "assets": [
            {
                "asset_id": "A010",
                "asset": {"asset_name": "Server X", "internet_exposed": False},
                "vulnerabilities": [{"vulnerability_id": "V999", "severity": 9.9, "exploitability": 0.9}],
                "controls": [],
                "incidents": []
            }
        ]
    }
    risk = {"assets": [{"asset_id": "A010", "risk": {"score": 30.0, "level": "LOW"}}]}
    res = generate_recommendations(proc, risk)
    v_rec = next(r for r in res["recommendations"] if r.get("evidence", {}).get("vulnerability_id") == "V999")
    assert v_rec["priority"] == "CRITICAL"


def test_t13_deterministic_ordering():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    recs = res["recommendations"]
    prio_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for i in range(len(recs) - 1):
        r1, r2 = recs[i], recs[i + 1]
        p1, p2 = prio_map[r1["priority"]], prio_map[r2["priority"]]
        assert p1 >= p2  # Priority DESC


def test_t14_quick_wins_identification():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    assert len(res["quick_wins"]) > 0
    for qw in res["quick_wins"]:
        cost = qw["estimated_annual_cost"]
        prio = qw["priority"]
        cat = qw["category"]
        assert (cost <= 50000) or (cat == "VULNERABILITY_REMEDIATION")


def test_t15_quick_wins_empty_when_none():
    proc = {
        "assets": [
            {
                "asset_id": "A050",
                "asset": {"asset_name": "Costly Asset", "internet_exposed": False},
                "vulnerabilities": [],
                "controls": [{"control_id": "C050", "control_name": "Expensive Shield", "implementation_status": "Inactive", "effectiveness": 0.2, "annual_cost": 500000}],
                "incidents": []
            }
        ]
    }
    risk = {"assets": [{"asset_id": "A050", "risk": {"score": 20.0, "level": "LOW"}}]}
    res = generate_recommendations(proc, risk)
    assert res["quick_wins"] == []


def test_t16_integration_with_optimizer_result():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    # Control C002 is selected by optimizer (cost 40,000 <= 100,000)
    c002_rec = next(r for r in res["recommendations"] if r.get("evidence", {}).get("control_id") == "C002")
    assert "Selected by Investment Optimizer" in c002_rec["reason"]


def test_t17_recommendation_id_generation():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    ids = [r["recommendation_id"] for r in res["recommendations"]]
    assert ids == [f"REC-{i+1:03d}" for i in range(len(ids))]


def test_t18_evidence_dictionary_required_fields():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    for r in res["recommendations"]:
        ev = r["evidence"]
        assert "risk_score" in ev
        assert "risk_level" in ev


def test_t19_recommended_actions_clarity():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    for r in res["recommendations"]:
        assert isinstance(r["recommended_action"], str)
        assert len(r["recommended_action"]) > 10


def test_t20_expected_impact_structure():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    for r in res["recommendations"]:
        imp = r["expected_impact"]
        assert isinstance(imp, dict)
        assert imp.get("type") == "modeled_risk_reduction"
        assert "description" in imp


def test_t21_estimated_annual_cost_accuracy():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    c002_rec = next(r for r in res["recommendations"] if r.get("evidence", {}).get("control_id") == "C002")
    assert c002_rec["estimated_annual_cost"] == 40000


def test_t22_no_invented_data():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    for r in res["recommendations"]:
        assert r["asset_id"] in ("A001", "A002")


def test_t23_zero_vulnerabilities_zero_inactive_controls():
    proc = {
        "assets": [
            {
                "asset_id": "A001",
                "asset": {"asset_name": "Perfect Asset", "internet_exposed": False},
                "vulnerabilities": [],
                "controls": [{"control_id": "C001", "implementation_status": "Active"}],
                "incidents": []
            }
        ]
    }
    risk = {"assets": [{"asset_id": "A001", "risk": {"score": 5.0, "level": "LOW"}}]}
    res = generate_recommendations(proc, risk)
    assert res["status"] == "no_recommendations"
    assert res["recommendations"] == []


def test_t24_deep_copy_non_mutation():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    proc_orig = copy.deepcopy(proc)
    _ = generate_recommendations(proc, risk, fin, threat, intel, opt)
    assert proc == proc_orig


def test_t25_json_serialization_succeeds():
    proc, risk, fin, threat, intel, opt = build_sample_model()
    res = generate_recommendations(proc, risk, fin, threat, intel, opt)
    serialized = json.dumps(res)
    assert isinstance(serialized, str)


def read_testfile(fname):
    with open(os.path.join(TESTDATA_DIR, fname), "rb") as f:
        return f.read()


def test_t26_post_analyze_includes_recommendations():
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
    assert data["success"] is True
    assert "recommendations" in data
    assert data["recommendations"]["status"] == "ok"
    assert len(data["recommendations"]["recommendations"]) > 0


def test_t27_existing_post_analyze_fields_preserved():
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
    for field in ("overall_risk", "risk", "financial", "threats", "intelligence"):
        assert field in data


def test_t28_existing_post_simulate_still_works():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    data_form = {"scenario": "{}"}
    resp = client.post("/api/simulate", files=files, data=data_form)

    assert resp.status_code == 200
    res = resp.json()
    assert res["success"] is True


def test_t29_existing_post_optimize_still_works():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    data_form = {"budget": "500000"}
    resp = client.post("/api/optimize", files=files, data=data_form)

    assert resp.status_code == 200
    res = resp.json()
    assert res["success"] is True
