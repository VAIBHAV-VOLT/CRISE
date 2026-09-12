"""
Validation Service for Cyber Risk Analyzer.
Handles schema verification, data type validation, value range checks, duplicate ID detection,
and foreign key relationship verification across assets, vulnerabilities, controls, and incidents.
"""

from typing import Any, Dict, List, Set, Tuple
import pandas as pd


def _is_empty(val: Any) -> bool:
    """Check if value is null, NaN, empty string, or whitespace only."""
    if pd.isna(val) or val is None:
        return True
    s = str(val).strip()
    return len(s) == 0


def _parse_num(val: Any) -> float | None:
    """Safely parse numeric value, returning float or None if invalid."""
    if _is_empty(val):
        return None
    try:
        # Strip currency symbols, commas, spaces
        cleaned = str(val).replace(",", "").replace("$", "").replace("₹", "").strip()
        return float(cleaned)
    except (ValueError, TypeError):
        return None


def validate_assets(df: pd.DataFrame) -> Tuple[Dict[str, Any], Set[str]]:
    """
    Validate assets DataFrame.
    Returns (result_dict, valid_asset_ids_set).
    """
    required_cols = [
        "asset_id", "asset_name", "asset_type", "department",
        "criticality", "business_value", "internet_exposed", "data_sensitivity"
    ]
    errors: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    valid_ids: Set[str] = set()

    # Check column presence
    missing_cols = [c for c in required_cols if c not in df.columns]
    if missing_cols:
        for c in missing_cols:
            errors.append({
                "row": 1,
                "column": c,
                "message": f"Missing required column '{c}' in assets.csv."
            })
        return {"valid": False, "rows": len(df), "errors": errors}, valid_ids

    # Row-by-row validation
    for idx, row in df.iterrows():
        row_num = idx + 2  # CSV row 1 is header, data starts at row 2

        # asset_id
        aid_val = row.get("asset_id")
        if _is_empty(aid_val):
            errors.append({
                "row": row_num,
                "column": "asset_id",
                "message": "Asset ID is required and cannot be empty."
            })
        else:
            aid_str = str(aid_val).strip()
            if aid_str in seen_ids:
                errors.append({
                    "row": row_num,
                    "column": "asset_id",
                    "message": f"Duplicate asset ID '{aid_str}'."
                })
            else:
                seen_ids.add(aid_str)
                valid_ids.add(aid_str)

        # asset_name
        aname_val = row.get("asset_name")
        if _is_empty(aname_val):
            errors.append({
                "row": row_num,
                "column": "asset_name",
                "message": "Asset name is required and cannot be empty."
            })

        # criticality (1 to 5)
        crit_val = _parse_num(row.get("criticality"))
        if crit_val is None or crit_val < 1 or crit_val > 5:
            errors.append({
                "row": row_num,
                "column": "criticality",
                "message": "Criticality must be a numeric value between 1 and 5."
            })

        # business_value (>= 0)
        bv_val = _parse_num(row.get("business_value"))
        if bv_val is None or bv_val < 0:
            errors.append({
                "row": row_num,
                "column": "business_value",
                "message": "Business value must be a numeric value >= 0."
            })

        # internet_exposed (Yes/No, true/false, 1/0)
        ie_val = row.get("internet_exposed")
        if _is_empty(ie_val):
            errors.append({
                "row": row_num,
                "column": "internet_exposed",
                "message": "internet_exposed is required."
            })
        else:
            ie_str = str(ie_val).strip().lower()
            if ie_str not in {"yes", "no", "true", "false", "1", "0"}:
                errors.append({
                    "row": row_num,
                    "column": "internet_exposed",
                    "message": "internet_exposed must be 'Yes'/'No' or 'true'/'false'."
                })

        # data_sensitivity (1 to 5)
        ds_val = _parse_num(row.get("data_sensitivity"))
        if ds_val is None or ds_val < 1 or ds_val > 5:
            errors.append({
                "row": row_num,
                "column": "data_sensitivity",
                "message": "Data sensitivity must be a numeric value between 1 and 5."
            })

    is_valid = len(errors) == 0
    return {"valid": is_valid, "rows": len(df), "errors": errors}, valid_ids


def validate_vulnerabilities(df: pd.DataFrame, valid_asset_ids: Set[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Validate vulnerabilities DataFrame.
    Returns (result_dict, relationship_errors).
    """
    required_cols = [
        "vulnerability_id", "asset_id", "vulnerability_name",
        "severity", "exploitability", "status", "discovered_date"
    ]
    errors: List[Dict[str, Any]] = []
    rel_errors: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    missing_cols = [c for c in required_cols if c not in df.columns]
    if missing_cols:
        for c in missing_cols:
            errors.append({
                "row": 1,
                "column": c,
                "message": f"Missing required column '{c}' in vulnerabilities.csv."
            })
        return {"valid": False, "rows": len(df), "errors": errors}, rel_errors

    for idx, row in df.iterrows():
        row_num = idx + 2

        # vulnerability_id
        vid_val = row.get("vulnerability_id")
        if _is_empty(vid_val):
            errors.append({
                "row": row_num,
                "column": "vulnerability_id",
                "message": "Vulnerability ID is required and cannot be empty."
            })
        else:
            vid_str = str(vid_val).strip()
            if vid_str in seen_ids:
                errors.append({
                    "row": row_num,
                    "column": "vulnerability_id",
                    "message": f"Duplicate vulnerability ID '{vid_str}'."
                })
            else:
                seen_ids.add(vid_str)

        # asset_id (Foreign Key)
        aid_val = row.get("asset_id")
        if _is_empty(aid_val):
            errors.append({
                "row": row_num,
                "column": "asset_id",
                "message": "Asset ID is required and cannot be empty."
            })
        else:
            aid_str = str(aid_val).strip()
            if aid_str not in valid_asset_ids:
                err_item = {
                    "row": row_num,
                    "column": "asset_id",
                    "message": f"Asset ID '{aid_str}' does not exist in assets.csv."
                }
                errors.append(err_item)
                rel_errors.append(err_item)

        # vulnerability_name
        vname_val = row.get("vulnerability_name")
        if _is_empty(vname_val):
            errors.append({
                "row": row_num,
                "column": "vulnerability_name",
                "message": "Vulnerability name is required and cannot be empty."
            })

        # severity (0 to 10)
        sev_val = _parse_num(row.get("severity"))
        if sev_val is None or sev_val < 0 or sev_val > 10:
            errors.append({
                "row": row_num,
                "column": "severity",
                "message": "Severity must be between 0 and 10."
            })

        # exploitability (0 to 1)
        exp_val = _parse_num(row.get("exploitability"))
        if exp_val is None or exp_val < 0 or exp_val > 1:
            errors.append({
                "row": row_num,
                "column": "exploitability",
                "message": "Exploitability must be between 0 and 1."
            })

        # status
        st_val = row.get("status")
        if _is_empty(st_val):
            errors.append({
                "row": row_num,
                "column": "status",
                "message": "Status is required and cannot be empty."
            })

        # discovered_date
        dd_val = row.get("discovered_date")
        if _is_empty(dd_val):
            errors.append({
                "row": row_num,
                "column": "discovered_date",
                "message": "Discovered date is required."
            })
        else:
            try:
                pd.to_datetime(str(dd_val).strip())
            except Exception:
                errors.append({
                    "row": row_num,
                    "column": "discovered_date",
                    "message": f"Discovered date '{dd_val}' is not a valid date format."
                })

    is_valid = len(errors) == 0
    return {"valid": is_valid, "rows": len(df), "errors": errors}, rel_errors


def validate_controls(df: pd.DataFrame, valid_asset_ids: Set[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Validate controls DataFrame.
    Returns (result_dict, relationship_errors).
    """
    required_cols = [
        "control_id", "control_name", "asset_id",
        "effectiveness", "implementation_status", "annual_cost"
    ]
    errors: List[Dict[str, Any]] = []
    rel_errors: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    missing_cols = [c for c in required_cols if c not in df.columns]
    if missing_cols:
        for c in missing_cols:
            errors.append({
                "row": 1,
                "column": c,
                "message": f"Missing required column '{c}' in controls.csv."
            })
        return {"valid": False, "rows": len(df), "errors": errors}, rel_errors

    for idx, row in df.iterrows():
        row_num = idx + 2

        # control_id
        cid_val = row.get("control_id")
        if _is_empty(cid_val):
            errors.append({
                "row": row_num,
                "column": "control_id",
                "message": "Control ID is required and cannot be empty."
            })
        else:
            cid_str = str(cid_val).strip()
            if cid_str in seen_ids:
                errors.append({
                    "row": row_num,
                    "column": "control_id",
                    "message": f"Duplicate control ID '{cid_str}'."
                })
            else:
                seen_ids.add(cid_str)

        # control_name
        cname_val = row.get("control_name")
        if _is_empty(cname_val):
            errors.append({
                "row": row_num,
                "column": "control_name",
                "message": "Control name is required and cannot be empty."
            })

        # asset_id (Foreign Key)
        aid_val = row.get("asset_id")
        if _is_empty(aid_val):
            errors.append({
                "row": row_num,
                "column": "asset_id",
                "message": "Asset ID is required and cannot be empty."
            })
        else:
            aid_str = str(aid_val).strip()
            if aid_str not in valid_asset_ids:
                err_item = {
                    "row": row_num,
                    "column": "asset_id",
                    "message": f"Asset ID '{aid_str}' does not exist in assets.csv."
                }
                errors.append(err_item)
                rel_errors.append(err_item)

        # effectiveness (0 to 1)
        eff_val = _parse_num(row.get("effectiveness"))
        if eff_val is None or eff_val < 0 or eff_val > 1:
            errors.append({
                "row": row_num,
                "column": "effectiveness",
                "message": "Effectiveness must be between 0 and 1."
            })

        # implementation_status
        ist_val = row.get("implementation_status")
        if _is_empty(ist_val):
            errors.append({
                "row": row_num,
                "column": "implementation_status",
                "message": "Implementation status is required and cannot be empty."
            })

        # annual_cost (>= 0)
        cost_val = _parse_num(row.get("annual_cost"))
        if cost_val is None or cost_val < 0:
            errors.append({
                "row": row_num,
                "column": "annual_cost",
                "message": "Annual cost must be a numeric value >= 0."
            })

    is_valid = len(errors) == 0
    return {"valid": is_valid, "rows": len(df), "errors": errors}, rel_errors


def validate_incidents(df: pd.DataFrame, valid_asset_ids: Set[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Validate incidents DataFrame.
    Returns (result_dict, relationship_errors).
    """
    required_cols = [
        "incident_id", "asset_id", "incident_type",
        "frequency_per_year", "average_loss", "downtime_hours"
    ]
    errors: List[Dict[str, Any]] = []
    rel_errors: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    missing_cols = [c for c in required_cols if c not in df.columns]
    if missing_cols:
        for c in missing_cols:
            errors.append({
                "row": 1,
                "column": c,
                "message": f"Missing required column '{c}' in incidents.csv."
            })
        return {"valid": False, "rows": len(df), "errors": errors}, rel_errors

    for idx, row in df.iterrows():
        row_num = idx + 2

        # incident_id
        iid_val = row.get("incident_id")
        if _is_empty(iid_val):
            errors.append({
                "row": row_num,
                "column": "incident_id",
                "message": "Incident ID is required and cannot be empty."
            })
        else:
            iid_str = str(iid_val).strip()
            if iid_str in seen_ids:
                errors.append({
                    "row": row_num,
                    "column": "incident_id",
                    "message": f"Duplicate incident ID '{iid_str}'."
                })
            else:
                seen_ids.add(iid_str)

        # asset_id (Foreign Key)
        aid_val = row.get("asset_id")
        if _is_empty(aid_val):
            errors.append({
                "row": row_num,
                "column": "asset_id",
                "message": "Asset ID is required and cannot be empty."
            })
        else:
            aid_str = str(aid_val).strip()
            if aid_str not in valid_asset_ids:
                err_item = {
                    "row": row_num,
                    "column": "asset_id",
                    "message": f"Asset ID '{aid_str}' does not exist in assets.csv."
                }
                errors.append(err_item)
                rel_errors.append(err_item)

        # incident_type
        itype_val = row.get("incident_type")
        if _is_empty(itype_val):
            errors.append({
                "row": row_num,
                "column": "incident_type",
                "message": "Incident type is required and cannot be empty."
            })

        # frequency_per_year (>= 0)
        freq_val = _parse_num(row.get("frequency_per_year"))
        if freq_val is None or freq_val < 0:
            errors.append({
                "row": row_num,
                "column": "frequency_per_year",
                "message": "Frequency per year must be a numeric value >= 0."
            })

        # average_loss (>= 0)
        loss_val = _parse_num(row.get("average_loss"))
        if loss_val is None or loss_val < 0:
            errors.append({
                "row": row_num,
                "column": "average_loss",
                "message": "Average loss must be a numeric value >= 0."
            })

        # downtime_hours (>= 0)
        dt_val = _parse_num(row.get("downtime_hours"))
        if dt_val is None or dt_val < 0:
            errors.append({
                "row": row_num,
                "column": "downtime_hours",
                "message": "Downtime hours must be a numeric value >= 0."
            })

    is_valid = len(errors) == 0
    return {"valid": is_valid, "rows": len(df), "errors": errors}, rel_errors


def validate_all(
    assets_df: pd.DataFrame,
    vulnerabilities_df: pd.DataFrame,
    controls_df: pd.DataFrame,
    incidents_df: pd.DataFrame
) -> Dict[str, Any]:
    """
    Validate all four risk DataFrames and return a comprehensive, structured response.
    """
    assets_res, valid_asset_ids = validate_assets(assets_df)
    vulns_res, vulns_rel_errors = validate_vulnerabilities(vulnerabilities_df, valid_asset_ids)
    controls_res, controls_rel_errors = validate_controls(controls_df, valid_asset_ids)
    incidents_res, incidents_rel_errors = validate_incidents(incidents_df, valid_asset_ids)

    all_rel_errors = vulns_rel_errors + controls_rel_errors + incidents_rel_errors

    overall_valid = (
        assets_res["valid"] and
        vulns_res["valid"] and
        controls_res["valid"] and
        incidents_res["valid"]
    )

    return {
        "valid": overall_valid,
        "files": {
            "assets": assets_res,
            "vulnerabilities": vulns_res,
            "controls": controls_res,
            "incidents": incidents_res
        },
        "relationship_errors": all_rel_errors,
        "summary": {
            "assets": assets_res["rows"],
            "vulnerabilities": vulns_res["rows"],
            "controls": controls_res["rows"],
            "incidents": incidents_res["rows"]
        }
    }
