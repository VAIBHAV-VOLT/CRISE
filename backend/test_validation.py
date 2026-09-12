"""
Automated Validation Test Suite for Cyber Risk Analyzer.
Tests the POST /api/validate endpoint with both valid demo datasets and 10 invalid edge cases.
"""

import os
import requests

BASE_URL = "http://127.0.0.1:8000"
TESTDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))


def read_testfile(name: str) -> bytes:
    path = os.path.join(TESTDATA_DIR, name)
    with open(path, "rb") as f:
        return f.read()


def test_valid_dataset():
    print("--- Test 0: Valid baseline dataset ---")
    files = {
        "assets": ("assets.csv", read_testfile("assets.csv"), "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert data["valid"] is True, f"Expected valid=True, got {data}"
    summary = data["summary"]
    assert summary["assets"] == 20, f"Expected 20 assets, got {summary['assets']}"
    assert summary["vulnerabilities"] == 30, f"Expected 30 vulnerabilities, got {summary['vulnerabilities']}"
    assert summary["controls"] == 25, f"Expected 25 controls, got {summary['controls']}"
    assert summary["incidents"] == 25, f"Expected 25 incidents, got {summary['incidents']}"
    print("[PASS] Valid baseline dataset passed! (Assets: 20, Vulns: 30, Controls: 25, Incidents: 25)")


def test_invalid_cases():
    print("\n--- Testing 10 Invalid Edge Cases ---")

    # 1. Missing required column
    csv_missing_col = b"asset_id,asset_name,criticality\nA001,Server,5\n"
    files = {
        "assets": ("assets.csv", csv_missing_col, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    assert r.json()["valid"] is False
    print("[PASS] 1. Missing required column detected.")

    # 2. Invalid severity > 10
    assets_csv = read_testfile("assets.csv")
    vulns_bad_sev = read_testfile("vulnerabilities.csv").replace(b"9.8", b"15.5")
    files = {
        "assets": ("assets.csv", assets_csv, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", vulns_bad_sev, "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    errs = r.json()["files"]["vulnerabilities"]["errors"]
    assert any("Severity must be between 0 and 10" in e["message"] for e in errs)
    print("[PASS] 2. Invalid severity (>10) detected.")

    # 3. Invalid exploitability > 1
    vulns_bad_exp = read_testfile("vulnerabilities.csv").replace(b"0.8", b"2.5")
    files = {
        "assets": ("assets.csv", assets_csv, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", vulns_bad_exp, "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    errs = r.json()["files"]["vulnerabilities"]["errors"]
    assert any("Exploitability must be between 0 and 1" in e["message"] for e in errs)
    print("[PASS] 3. Invalid exploitability (>1) detected.")

    # 4. Negative business value
    assets_neg_bv = read_testfile("assets.csv").replace(b"50000000", b"-100")
    files = {
        "assets": ("assets.csv", assets_neg_bv, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    errs = r.json()["files"]["assets"]["errors"]
    assert any("Business value must be a numeric value >= 0" in e["message"] for e in errs)
    print("[PASS] 4. Negative business value detected.")

    # 5. Duplicate asset_id
    assets_dup = assets_csv + b"\nA001,Duplicate Server,Server,Finance,5,50000000,Yes,5\n"
    files = {
        "assets": ("assets.csv", assets_dup, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    errs = r.json()["files"]["assets"]["errors"]
    assert any("Duplicate asset ID 'A001'" in e["message"] for e in errs)
    print("[PASS] 5. Duplicate asset_id detected.")

    # 6. Invalid asset_id reference (foreign key failure)
    vulns_orphan = read_testfile("vulnerabilities.csv").replace(b"A001", b"A999")
    files = {
        "assets": ("assets.csv", assets_csv, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", vulns_orphan, "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    rel_errs = r.json()["relationship_errors"]
    assert any("Asset ID 'A999' does not exist in assets.csv" in e["message"] for e in rel_errs)
    print("[PASS] 6. Invalid asset_id reference (foreign key failure) detected.")

    # 7. Empty CSV
    files = {
        "assets": ("assets.csv", b"", "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    assert "assets.csv is empty." in r.json()["errors"]
    print("[PASS] 7. Empty CSV detected.")

    # 8. Missing CSV file
    files = {
        "assets": ("assets.csv", assets_csv, "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    assert "Missing required file: vulnerabilities.csv" in r.json()["errors"]
    print("[PASS] 8. Missing CSV file detected.")

    # 9. Unsupported file type
    files = {
        "assets": ("assets.exe", b"binary content", "application/octet-stream"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    assert any("Only .csv files are allowed" in e for e in r.json()["errors"])
    print("[PASS] 9. Unsupported file type detected.")

    # 10. Malformed CSV
    malformed_csv = b"asset_id,asset_name\nA001,Server,1,2,3,4,5,6,7,8,9\n"
    files = {
        "assets": ("assets.csv", malformed_csv, "text/csv"),
        "vulnerabilities": ("vulnerabilities.csv", read_testfile("vulnerabilities.csv"), "text/csv"),
        "controls": ("controls.csv", read_testfile("controls.csv"), "text/csv"),
        "incidents": ("incidents.csv", read_testfile("incidents.csv"), "text/csv"),
    }
    r = requests.post(f"{BASE_URL}/api/validate", files=files)
    assert r.status_code == 400
    # Will fail required columns or parsing
    assert r.json()["valid"] is False
    print("[PASS] 10. Malformed CSV detected.")


if __name__ == "__main__":
    test_valid_dataset()
    test_invalid_cases()
    print("\nALL VALIDATION TESTS PASSED SUCCESSFULLY!")
