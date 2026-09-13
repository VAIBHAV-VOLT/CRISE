"""
Phase 12 — Monte Carlo / Uncertainty Risk Simulation Test Suite
================================================================
Tests backend/services/monte_carlo.py and POST /api/monte-carlo endpoint.

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
from services.monte_carlo import run_monte_carlo, _sample_triangular

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
        {"vulnerability_id": "V002", "asset_id": "A002", "vulnerability_name": "Weak Auth", "severity": 5.0, "exploitability": 0.4, "status": "Open", "discovered_date": "2026-08-05"},
    ]
    controls_raw = [
        {"control_id": "C001", "control_name": "MFA", "asset_id": "A001", "effectiveness": 0.60, "implementation_status": "Active", "annual_cost": 300000},
        {"control_id": "C002", "control_name": "EDR", "asset_id": "A001", "effectiveness": 0.70, "implementation_status": "Planned", "annual_cost": 40000},
        {"control_id": "C003", "control_name": "Backup", "asset_id": "A002", "effectiveness": 0.50, "implementation_status": "Active", "annual_cost": 25000},
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
    return proc, risk


def test_t01_baseline_unchanged():
    proc, risk = build_sample_model()
    baseline_score_before = risk["overall_risk"]["score"]
    _ = run_monte_carlo(proc, risk, iterations=500, seed=42)
    risk_after = calculate_risk(proc)
    assert risk_after["overall_risk"]["score"] == baseline_score_before


def test_t02_same_seed_same_input_identical_result():
    proc, risk = build_sample_model()
    res1 = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    res2 = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    assert res1["simulation"] == res2["simulation"]
    assert res1["risk_level_distribution"] == res2["risk_level_distribution"]


def test_t03_different_seed_different_result():
    proc, risk = build_sample_model()
    res1 = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    res2 = run_monte_carlo(proc, risk, iterations=1000, seed=999)
    assert res1["simulation"]["std_dev"] != res2["simulation"]["std_dev"] or \
           res1["simulation"]["min"] != res2["simulation"]["min"] or \
           res1["simulation"]["max"] != res2["simulation"]["max"]


def test_t04_default_iterations():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, seed=42)
    assert res["iterations"] == 5000


def test_t05_minimum_iterations_accepted():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, iterations=100, seed=42)
    assert res["iterations"] == 100


def test_t06_iterations_below_100_rejected():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/monte-carlo", files=files, data={"iterations": "50", "seed": "42"})
    assert resp.status_code == 400
    assert "errors" in resp.json()


def test_t07_iterations_above_20000_rejected():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/monte-carlo", files=files, data={"iterations": "25000", "seed": "42"})
    assert resp.status_code == 400
    assert "errors" in resp.json()


def test_t08_asset_level_simulation_works():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, iterations=500, seed=42, asset_id="A001")
    assert res["scope"] == "asset"
    assert res["asset_id"] == "A001"
    assert "baseline" in res
    assert "simulation" in res


def test_t09_enterprise_level_simulation_works():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, iterations=500, seed=42)
    assert res["scope"] == "enterprise"
    assert res.get("asset_id") is None
    assert "baseline" in res
    assert "simulation" in res


def test_t10_enterprise_weighted_risk_formula():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    # Baseline enterprise risk matches Phase 4 weighted calculation
    bv1, bv2 = 50000000, 20000000
    r1 = risk["assets"][0]["risk"]["score"]
    r2 = risk["assets"][1]["risk"]["score"]
    expected_baseline = (r1 * bv1 + r2 * bv2) / (bv1 + bv2)
    assert abs(res["baseline"]["risk_score"] - round(expected_baseline, 2)) < 1e-2


def test_t11_percentiles_ordered():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    sim = res["simulation"]
    assert sim["min"] <= sim["p5"]
    assert sim["p5"] <= sim["p25"]
    assert sim["p25"] <= sim["median"]
    assert sim["median"] <= sim["p75"]
    assert sim["p75"] <= sim["p95"]
    assert sim["p95"] <= sim["max"]


def test_t12_risk_distribution_counts_sum_to_iterations():
    proc, risk = build_sample_model()
    N = 1500
    res = run_monte_carlo(proc, risk, iterations=N, seed=42)
    dist = res["risk_level_distribution"]
    total_count = dist["LOW"]["count"] + dist["MEDIUM"]["count"] + dist["HIGH"]["count"] + dist["CRITICAL"]["count"]
    assert total_count == N


def test_t13_risk_distribution_percentages_sum_to_100():
    proc, risk = build_sample_model()
    res = run_monte_carlo(proc, risk, iterations=2000, seed=42)
    dist = res["risk_level_distribution"]
    total_pct = dist["LOW"]["percentage"] + dist["MEDIUM"]["percentage"] + dist["HIGH"]["percentage"] + dist["CRITICAL"]["percentage"]
    assert abs(total_pct - 100.0) < 0.1


def test_t14_severity_samples_bounded_0_to_10():
    import numpy as np
    rng = np.random.default_rng(42)
    samples = _sample_triangular(rng, val=9.8, min_bound=0.0, max_bound=10.0, size=5000)
    assert np.all(samples >= 0.0)
    assert np.all(samples <= 10.0)


def test_t15_exploitability_samples_bounded_0_to_1():
    import numpy as np
    rng = np.random.default_rng(42)
    samples = _sample_triangular(rng, val=0.9, min_bound=0.0, max_bound=1.0, size=5000)
    assert np.all(samples >= 0.0)
    assert np.all(samples <= 1.0)


def test_t16_effectiveness_samples_bounded_0_to_1():
    import numpy as np
    rng = np.random.default_rng(42)
    samples = _sample_triangular(rng, val=0.7, min_bound=0.0, max_bound=1.0, size=5000)
    assert np.all(samples >= 0.0)
    assert np.all(samples <= 1.0)


def test_t17_criticality_samples_bounded_0_to_5():
    import numpy as np
    rng = np.random.default_rng(42)
    samples = _sample_triangular(rng, val=5.0, min_bound=0.0, max_bound=5.0, size=5000)
    assert np.all(samples >= 0.0)
    assert np.all(samples <= 5.0)


def test_t18_sensitivity_samples_bounded_0_to_5():
    import numpy as np
    rng = np.random.default_rng(42)
    samples = _sample_triangular(rng, val=4.0, min_bound=0.0, max_bound=5.0, size=5000)
    assert np.all(samples >= 0.0)
    assert np.all(samples <= 5.0)


def test_t19_business_values_never_modified():
    proc, risk = build_sample_model()
    bv1_before = proc["assets"][0]["asset"]["business_value"]
    _ = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    assert proc["assets"][0]["asset"]["business_value"] == bv1_before


def test_t20_annual_costs_never_modified():
    proc, risk = build_sample_model()
    c1_cost_before = proc["assets"][0]["controls"][0]["annual_cost"]
    _ = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    assert proc["assets"][0]["controls"][0]["annual_cost"] == c1_cost_before


def test_t21_internet_exposure_remains_categorical():
    proc, risk = build_sample_model()
    ie_before = proc["assets"][0]["asset"]["internet_exposed"]
    _ = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    assert proc["assets"][0]["asset"]["internet_exposed"] == ie_before


def test_t22_ids_and_relationships_unchanged():
    proc, risk = build_sample_model()
    a1_id = proc["assets"][0]["asset_id"]
    _ = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    assert proc["assets"][0]["asset_id"] == a1_id


def test_t23_no_mutation_of_input_data():
    proc, risk = build_sample_model()
    proc_copy = copy.deepcopy(proc)
    _ = run_monte_carlo(proc, risk, iterations=1000, seed=42)
    assert proc == proc_copy


def test_t24_unknown_asset_id_rejected():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/monte-carlo", files=files, data={"asset_id": "NON_EXISTENT_ID"})
    assert resp.status_code == 400
    assert "errors" in resp.json()


def test_t25_empty_dataset_handled_correctly():
    proc = {"assets": []}
    res = run_monte_carlo(proc, iterations=500, seed=42)
    assert res["scope"] == "enterprise"
    assert res["baseline"]["risk_score"] == 0.0
    assert res["simulation"]["mean"] == 0.0


def test_t26_api_response_conforms_to_schema():
    client = TestClient(app)
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    resp = client.post("/api/monte-carlo", files=files, data={"iterations": "500", "seed": "42"})
    assert resp.status_code == 200
    data = resp.json()
    assert "scope" in data
    assert "iterations" in data
    assert "seed" in data
    assert "baseline" in data
    assert "simulation" in data
    assert "risk_level_distribution" in data
    assert "uncertainty_band" in data
    assert "explanation" in data


def test_t27_frontend_uses_backend_endpoint():
    with open(os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js"), "r", encoding="utf-8") as f:
        js_content = f.read()
    assert "/api/monte-carlo" in js_content
    assert "sendBackendMonteCarlo" in js_content


def test_t28_frontend_does_not_calculate_monte_carlo_itself():
    with open(os.path.join(os.path.dirname(__file__), "..", "risk_analyzer.js"), "r", encoding="utf-8") as f:
        js_content = f.read()
    # Frontend should receive backend simulation statistics and render them
    assert "backendAnalysis.monte_carlo" in js_content or "mcResult" in js_content
    assert "triangular" not in js_content  # JS should not compute triangular distribution
