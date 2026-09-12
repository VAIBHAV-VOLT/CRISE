"""
Automated Processing Test Suite for Cyber Risk Analyzer.
Tests the POST /api/process endpoint along with all Phase 2 validation tests.
Run with: python test_processing.py  (from the backend/ directory)
"""

import os
import sys
import io
import pandas as pd
import requests

BASE_URL = "http://127.0.0.1:8000"
TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


def read_testfile(name: str) -> bytes:
    path = os.path.join(TESTDATA_DIR, name)
    with open(path, "rb") as f:
        return f.read()


def make_files(
    assets=None, vulnerabilities=None, controls=None, incidents=None
):
    """Build the requests 'files' dict from raw bytes."""
    return {
        "assets": ("assets.csv", assets or read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", vulnerabilities or read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", controls or read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", incidents or read_testfile("incidents.csv"), "text/csv"),
    }


# ---------------------------------------------------------------------------
# Test 1 – Health check still returns 200
# ---------------------------------------------------------------------------
def test_health():
    print("Test 1: GET /api/health")
    r = requests.get(f"{BASE_URL}/api/health")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert r.json()["status"] == "ok"
    print("[PASS] GET /api/health returns 200 ok")


# ---------------------------------------------------------------------------
# Test 2 – Validate demo dataset still returns valid
# ---------------------------------------------------------------------------
def test_validate_demo():
    print("Test 2: POST /api/validate with demo dataset")
    r = requests.post(f"{BASE_URL}/api/validate", files=make_files())
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert data["valid"] is True, f"Expected valid=True, got {data}"
    print("[PASS] POST /api/validate returns valid=true for demo dataset")


# ---------------------------------------------------------------------------
# Test 3 – Process demo dataset: counts correct
# ---------------------------------------------------------------------------
def test_process_counts():
    print("Test 3: POST /api/process – correct counts")
    r = requests.post(f"{BASE_URL}/api/process", files=make_files())
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert data["success"] is True, f"Expected success=True, got {data}"
    s = data["summary"]
    assert s["asset_count"] == 20, f"Expected 20 assets, got {s['asset_count']}"
    assert s["vulnerability_count"] == 30, f"Expected 30 vulns, got {s['vulnerability_count']}"
    assert s["control_count"] == 25, f"Expected 25 controls, got {s['control_count']}"
    assert s["incident_count"] == 25, f"Expected 25 incidents, got {s['incident_count']}"
    print(f"[PASS] POST /api/process: assets={s['asset_count']}, vulns={s['vulnerability_count']}, controls={s['control_count']}, incidents={s['incident_count']}")
    return data


# ---------------------------------------------------------------------------
# Test 4 – A001 relationship verification
# ---------------------------------------------------------------------------
def test_a001_relationships(process_data):
    print("Test 4: A001 relationship verification")
    assets = process_data.get("assets", [])
    a001 = next((a for a in assets if a["asset_id"] == "A001"), None)
    assert a001 is not None, "A001 not found in processed output"

    vuln_ids = {v["vulnerability_id"] for v in a001["vulnerabilities"]}
    assert "V001" in vuln_ids, f"V001 missing from A001 vulns: {vuln_ids}"
    assert "V002" in vuln_ids, f"V002 missing from A001 vulns: {vuln_ids}"
    assert "V026" in vuln_ids, f"V026 missing from A001 vulns: {vuln_ids}"
    assert len(a001["vulnerabilities"]) == 3, f"Expected 3 vulns for A001, got {len(a001['vulnerabilities'])}"

    ctrl_ids = {c["control_id"] for c in a001["controls"]}
    assert "C001" in ctrl_ids, f"C001 missing from A001 controls: {ctrl_ids}"
    assert "C002" in ctrl_ids, f"C002 missing from A001 controls: {ctrl_ids}"
    assert "C022" in ctrl_ids, f"C022 missing from A001 controls: {ctrl_ids}"
    assert len(a001["controls"]) == 3, f"Expected 3 controls for A001, got {len(a001['controls'])}"

    inc_ids = {i["incident_id"] for i in a001["incidents"]}
    assert "I001" in inc_ids, f"I001 missing from A001 incidents: {inc_ids}"
    assert "I002" in inc_ids, f"I002 missing from A001 incidents: {inc_ids}"
    assert len(a001["incidents"]) == 2, f"Expected 2 incidents for A001, got {len(a001['incidents'])}"

    print(f"[PASS] A001 has correct vulns={sorted(vuln_ids)}, controls={sorted(ctrl_ids)}, incidents={sorted(inc_ids)}")


# ---------------------------------------------------------------------------
# Test 5 – Text normalization: whitespace trimmed, case preserved
# ---------------------------------------------------------------------------
def test_text_normalization():
    print("Test 5: Text normalization")
    # Build an assets CSV with leading/trailing whitespace in text fields
    csv_with_spaces = (
        "asset_id,asset_name,asset_type,department,criticality,business_value,internet_exposed,data_sensitivity\n"
        "  A001  ,  ERP Server  ,  Server  ,  Finance  ,5,50000000,Yes,5\n"
    )
    vuln_csv = (
        "vulnerability_id,asset_id,vulnerability_name,severity,exploitability,status,discovered_date\n"
        "V001,A001,  Outdated Software  ,9.8,0.8,  Open  ,2026-08-01\n"
    )
    ctrl_csv = (
        "control_id,control_name,asset_id,effectiveness,implementation_status,annual_cost\n"
        "C001,  MFA  ,A001,0.6,  Active  ,300000\n"
    )
    inc_csv = (
        "incident_id,asset_id,incident_type,frequency_per_year,average_loss,downtime_hours\n"
        "I001,A001,  Ransomware  ,0.3,5000000,24\n"
    )

    # Test normalization directly via the processing module
    sys.path.insert(0, os.path.dirname(__file__))
    from services.processing import process_data as _process

    assets_df = pd.read_csv(io.StringIO(csv_with_spaces))
    vulns_df = pd.read_csv(io.StringIO(vuln_csv))
    ctrls_df = pd.read_csv(io.StringIO(ctrl_csv))
    incs_df = pd.read_csv(io.StringIO(inc_csv))

    result = _process(assets_df, vulns_df, ctrls_df, incs_df)
    a = result["assets"][0]["asset"]

    # asset_id stripped
    assert result["assets"][0]["asset_id"] == "A001", "asset_id whitespace not stripped"
    # Names trimmed but case preserved
    assert a["asset_name"] == "ERP Server", f"asset_name not trimmed: '{a['asset_name']}'"
    assert a["asset_type"] == "Server", f"asset_type not trimmed: '{a['asset_type']}'"
    assert a["department"] == "Finance", f"department not trimmed: '{a['department']}'"

    vuln = result["assets"][0]["vulnerabilities"][0]
    assert vuln["vulnerability_name"] == "Outdated Software", f"vuln name not trimmed: '{vuln['vulnerability_name']}'"
    assert vuln["status"] == "Open", f"status not trimmed: '{vuln['status']}'"

    ctrl = result["assets"][0]["controls"][0]
    assert ctrl["control_name"] == "MFA", f"control_name not trimmed: '{ctrl['control_name']}'"
    assert ctrl["implementation_status"] == "Active", f"impl_status not trimmed: '{ctrl['implementation_status']}'"

    inc = result["assets"][0]["incidents"][0]
    assert inc["incident_type"] == "Ransomware", f"incident_type not trimmed: '{inc['incident_type']}'"

    print("[PASS] Text normalization: whitespace trimmed, case preserved")


# ---------------------------------------------------------------------------
# Test 6 – Numeric type normalization (int, float)
# ---------------------------------------------------------------------------
def test_numeric_types():
    print("Test 6: Numeric type normalization")
    sys.path.insert(0, os.path.dirname(__file__))
    from services.processing import process_data as _process

    assets_df = pd.read_csv(io.StringIO(
        "asset_id,asset_name,asset_type,department,criticality,business_value,internet_exposed,data_sensitivity\n"
        "A001,ERP Server,Server,Finance,5,50000000,Yes,5\n"
    ))
    vulns_df = pd.read_csv(io.StringIO(
        "vulnerability_id,asset_id,vulnerability_name,severity,exploitability,status,discovered_date\n"
        "V001,A001,Test,9.8,0.8,Open,2026-08-01\n"
    ))
    ctrls_df = pd.read_csv(io.StringIO(
        "control_id,control_name,asset_id,effectiveness,implementation_status,annual_cost\n"
        "C001,MFA,A001,0.6,Active,300000\n"
    ))
    incs_df = pd.read_csv(io.StringIO(
        "incident_id,asset_id,incident_type,frequency_per_year,average_loss,downtime_hours\n"
        "I001,A001,Ransomware,0.3,5000000,24\n"
    ))

    result = _process(assets_df, vulns_df, ctrls_df, incs_df)
    a = result["assets"][0]["asset"]

    assert isinstance(a["criticality"], int), f"criticality should be int, got {type(a['criticality'])}"
    assert isinstance(a["business_value"], float), f"business_value should be float, got {type(a['business_value'])}"
    assert isinstance(a["data_sensitivity"], int), f"data_sensitivity should be int, got {type(a['data_sensitivity'])}"

    v = result["assets"][0]["vulnerabilities"][0]
    assert isinstance(v["severity"], float), f"severity should be float, got {type(v['severity'])}"
    assert isinstance(v["exploitability"], float), f"exploitability should be float, got {type(v['exploitability'])}"

    c = result["assets"][0]["controls"][0]
    assert isinstance(c["effectiveness"], float), f"effectiveness should be float, got {type(c['effectiveness'])}"
    assert isinstance(c["annual_cost"], float), f"annual_cost should be float, got {type(c['annual_cost'])}"

    i = result["assets"][0]["incidents"][0]
    assert isinstance(i["frequency_per_year"], float), f"frequency_per_year should be float, got {type(i['frequency_per_year'])}"
    assert isinstance(i["average_loss"], float), f"average_loss should be float, got {type(i['average_loss'])}"
    assert isinstance(i["downtime_hours"], float), f"downtime_hours should be float, got {type(i['downtime_hours'])}"

    print("[PASS] Numeric types normalized correctly (int/float)")


# ---------------------------------------------------------------------------
# Test 7 – Boolean normalization (internet_exposed)
# ---------------------------------------------------------------------------
def test_boolean_normalization():
    print("Test 7: Boolean normalization (internet_exposed)")
    sys.path.insert(0, os.path.dirname(__file__))
    from services.processing import process_data as _process

    def _run(ie_val: str) -> bool:
        df = pd.read_csv(io.StringIO(
            f"asset_id,asset_name,asset_type,department,criticality,business_value,internet_exposed,data_sensitivity\n"
            f"A001,Server,Server,IT,3,1000000,{ie_val},3\n"
        ))
        empty_df = pd.DataFrame(columns=["vulnerability_id","asset_id","vulnerability_name","severity","exploitability","status","discovered_date"])
        empty_ctrl = pd.DataFrame(columns=["control_id","control_name","asset_id","effectiveness","implementation_status","annual_cost"])
        empty_inc = pd.DataFrame(columns=["incident_id","asset_id","incident_type","frequency_per_year","average_loss","downtime_hours"])
        res = _process(df, empty_df, empty_ctrl, empty_inc)
        return res["assets"][0]["asset"]["internet_exposed"]

    assert _run("Yes") is True, "Yes should map to True"
    assert _run("yes") is True, "yes should map to True"
    assert _run("true") is True, "true should map to True"
    assert _run("1") is True, "1 should map to True"
    assert _run("No") is False, "No should map to False"
    assert _run("false") is False, "false should map to False"
    assert _run("0") is False, "0 should map to False"
    assert isinstance(_run("Yes"), bool), "internet_exposed should be Python bool"

    print("[PASS] Boolean normalization for internet_exposed works correctly")


# ---------------------------------------------------------------------------
# Test 8 – Input DataFrames are not mutated
# ---------------------------------------------------------------------------
def test_immutability():
    print("Test 8: Input DataFrames not mutated by process_data")
    sys.path.insert(0, os.path.dirname(__file__))
    from services.processing import process_data as _process

    assets_df = pd.read_csv(io.StringIO(
        "asset_id,asset_name,asset_type,department,criticality,business_value,internet_exposed,data_sensitivity\n"
        "A001,ERP Server,Server,Finance,5,50000000,Yes,5\n"
    ))
    vuln_df = pd.read_csv(io.StringIO(
        "vulnerability_id,asset_id,vulnerability_name,severity,exploitability,status,discovered_date\n"
        "V001,A001,Test,9.8,0.8,Open,2026-08-01\n"
    ))
    ctrl_df = pd.DataFrame(columns=["control_id","control_name","asset_id","effectiveness","implementation_status","annual_cost"])
    inc_df = pd.DataFrame(columns=["incident_id","asset_id","incident_type","frequency_per_year","average_loss","downtime_hours"])

    # Capture original values BEFORE processing
    original_ie = str(assets_df["internet_exposed"].iloc[0])
    original_crit = str(assets_df["criticality"].iloc[0])

    _process(assets_df, vuln_df, ctrl_df, inc_df)

    # After processing, original strings must be unchanged
    assert str(assets_df["internet_exposed"].iloc[0]) == original_ie, \
        f"internet_exposed mutated in original DF: was '{original_ie}', now '{assets_df['internet_exposed'].iloc[0]}'"
    assert str(assets_df["criticality"].iloc[0]) == original_crit, \
        f"criticality mutated in original DF"

    print("[PASS] Input DataFrames are not mutated by process_data")


# ---------------------------------------------------------------------------
# Test 9 – Invalid data rejected before processing
# ---------------------------------------------------------------------------
def test_invalid_rejected():
    print("Test 9: Invalid data rejected before processing")
    # Asset with criticality out of range
    bad_assets = (
        b"asset_id,asset_name,asset_type,department,criticality,business_value,internet_exposed,data_sensitivity\n"
        b"A001,Server,Server,IT,99,100000,Yes,5\n"
    )
    r = requests.post(f"{BASE_URL}/api/process", files=make_files(assets=bad_assets))
    assert r.status_code == 400, f"Expected 400, got {r.status_code}"
    data = r.json()
    assert data["success"] is False, "Expected success=False for invalid data"
    print("[PASS] Invalid data correctly rejected by process endpoint (validation runs before processing)")


# ---------------------------------------------------------------------------
# Test 10-13 — Phase 2 validation tests still pass
# ---------------------------------------------------------------------------
def test_phase2_validation():
    print("Test 10-13: Phase 2 validation tests still passing")
    assets_csv = read_testfile("assets.csv")

    # Missing required column
    bad_col = b"asset_id,asset_name,criticality\nA001,Server,5\n"
    r = requests.post(f"{BASE_URL}/api/validate", files=make_files(assets=bad_col))
    assert r.status_code == 400 and r.json()["valid"] is False
    print("[PASS] 10. Missing column still detected")

    # Severity > 10
    vulns_bad_sev = read_testfile("vulnerabilities.csv").replace(b"9.8", b"15.5")
    r = requests.post(f"{BASE_URL}/api/validate", files=make_files(vulnerabilities=vulns_bad_sev))
    assert r.status_code == 400
    print("[PASS] 11. Severity > 10 still detected")

    # Duplicate asset_id
    dup_assets = assets_csv + b"\nA001,Dup,Server,Finance,5,50000000,Yes,5\n"
    r = requests.post(f"{BASE_URL}/api/validate", files=make_files(assets=dup_assets))
    assert r.status_code == 400
    print("[PASS] 12. Duplicate asset_id still detected")

    # Foreign key failure
    orphan_vulns = read_testfile("vulnerabilities.csv").replace(b"A001", b"A999")
    r = requests.post(f"{BASE_URL}/api/validate", files=make_files(vulnerabilities=orphan_vulns))
    assert r.status_code == 400
    print("[PASS] 13. Foreign key failure still detected")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_health()
    test_validate_demo()
    process_result = test_process_counts()
    test_a001_relationships(process_result)
    test_text_normalization()
    test_numeric_types()
    test_boolean_normalization()
    test_immutability()
    test_invalid_rejected()
    test_phase2_validation()
    print("\nALL PHASE 3 PROCESSING TESTS PASSED SUCCESSFULLY!")
