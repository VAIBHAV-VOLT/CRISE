"""
Processing Service for Cyber Risk Analyzer.
Normalizes validated CSV DataFrames and organizes them into a clean,
asset-centric internal representation ready for the risk engine.

NO risk scores or financial calculations are performed here.
This layer is strictly about data normalization and grouping.
"""

from typing import Any, Dict, List, Set
import pandas as pd
import numpy as np


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _norm_str(val: Any) -> str:
    """Strip leading/trailing whitespace from string fields, preserve case."""
    if val is None or (isinstance(val, float) and np.isnan(val)):
        return ""
    return str(val).strip()


def _to_float(val: Any, fallback: float = 0.0) -> float:
    """Safely convert to float."""
    try:
        return float(str(val).replace(",", "").replace("$", "").replace("₹", "").strip())
    except (ValueError, TypeError):
        return fallback


def _to_int(val: Any, fallback: int = 0) -> int:
    """Safely convert to int (via float first to handle '5.0' strings)."""
    try:
        return int(round(float(str(val).strip())))
    except (ValueError, TypeError):
        return fallback


def _to_bool(val: Any) -> bool:
    """
    Normalize internet_exposed field to bool.
    Accepts: Yes/No, True/False, 1/0 (case-insensitive).
    """
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    return s in {"yes", "true", "1"}


def _to_date_str(val: Any) -> str:
    """
    Normalize date to ISO 8601 string (YYYY-MM-DD).
    Returns empty string if unparseable.
    """
    if val is None or (isinstance(val, float) and np.isnan(val)):
        return ""
    try:
        return pd.to_datetime(str(val).strip()).strftime("%Y-%m-%d")
    except Exception:
        return str(val).strip()


# ---------------------------------------------------------------------------
# Per-dataset normalization functions
# ---------------------------------------------------------------------------

def _normalize_assets(df: pd.DataFrame) -> pd.DataFrame:
    """Return a fully normalized copy of the assets DataFrame."""
    out = df.copy()
    # Text fields
    for col in ["asset_id", "asset_name", "asset_type", "department"]:
        if col in out.columns:
            out[col] = out[col].apply(_norm_str)
    # Numeric fields
    out["criticality"] = out["criticality"].apply(_to_int)
    out["business_value"] = out["business_value"].apply(_to_float)
    out["data_sensitivity"] = out["data_sensitivity"].apply(_to_int)
    # Boolean field
    out["internet_exposed"] = out["internet_exposed"].apply(_to_bool)
    return out


def _normalize_vulnerabilities(df: pd.DataFrame) -> pd.DataFrame:
    """Return a fully normalized copy of the vulnerabilities DataFrame."""
    out = df.copy()
    # Text fields
    for col in ["vulnerability_id", "asset_id", "vulnerability_name", "status"]:
        if col in out.columns:
            out[col] = out[col].apply(_norm_str)
    # Numeric fields
    out["severity"] = out["severity"].apply(_to_float)
    out["exploitability"] = out["exploitability"].apply(_to_float)
    # Date field
    out["discovered_date"] = out["discovered_date"].apply(_to_date_str)
    return out


def _normalize_controls(df: pd.DataFrame) -> pd.DataFrame:
    """Return a fully normalized copy of the controls DataFrame."""
    out = df.copy()
    # Text fields
    for col in ["control_id", "control_name", "asset_id", "implementation_status"]:
        if col in out.columns:
            out[col] = out[col].apply(_norm_str)
    # Numeric fields
    out["effectiveness"] = out["effectiveness"].apply(_to_float)
    out["annual_cost"] = out["annual_cost"].apply(_to_float)
    return out


def _normalize_incidents(df: pd.DataFrame) -> pd.DataFrame:
    """Return a fully normalized copy of the incidents DataFrame."""
    out = df.copy()
    # Text fields
    for col in ["incident_id", "asset_id", "incident_type"]:
        if col in out.columns:
            out[col] = out[col].apply(_norm_str)
    # Numeric fields
    out["frequency_per_year"] = out["frequency_per_year"].apply(_to_float)
    out["average_loss"] = out["average_loss"].apply(_to_float)
    out["downtime_hours"] = out["downtime_hours"].apply(_to_float)
    return out


# ---------------------------------------------------------------------------
# Asset profile builder
# ---------------------------------------------------------------------------

def _build_asset_profile(
    asset_row: pd.Series,
    vuln_records: List[Dict],
    control_records: List[Dict],
    incident_records: List[Dict],
) -> Dict[str, Any]:
    """Build a single asset-centric profile dict from normalized data."""
    return {
        "asset_id": asset_row["asset_id"],
        "asset": {
            "asset_name": asset_row["asset_name"],
            "asset_type": asset_row["asset_type"],
            "department": asset_row["department"],
            "criticality": int(asset_row["criticality"]),
            "business_value": float(asset_row["business_value"]),
            "internet_exposed": bool(asset_row["internet_exposed"]),
            "data_sensitivity": int(asset_row["data_sensitivity"]),
        },
        "vulnerabilities": vuln_records,
        "controls": control_records,
        "incidents": incident_records,
    }


def _vuln_to_dict(row: pd.Series) -> Dict[str, Any]:
    return {
        "vulnerability_id": row["vulnerability_id"],
        "vulnerability_name": row["vulnerability_name"],
        "severity": float(row["severity"]),
        "exploitability": float(row["exploitability"]),
        "status": row["status"],
        "discovered_date": row["discovered_date"],
    }


def _control_to_dict(row: pd.Series) -> Dict[str, Any]:
    return {
        "control_id": row["control_id"],
        "control_name": row["control_name"],
        "effectiveness": float(row["effectiveness"]),
        "implementation_status": row["implementation_status"],
        "annual_cost": float(row["annual_cost"]),
    }


def _incident_to_dict(row: pd.Series) -> Dict[str, Any]:
    return {
        "incident_id": row["incident_id"],
        "incident_type": row["incident_type"],
        "frequency_per_year": float(row["frequency_per_year"]),
        "average_loss": float(row["average_loss"]),
        "downtime_hours": float(row["downtime_hours"]),
    }


# ---------------------------------------------------------------------------
# Summary statistics (descriptive only — no risk metrics)
# ---------------------------------------------------------------------------

def _build_summary(
    assets_norm: pd.DataFrame,
    vulns_norm: pd.DataFrame,
    controls_norm: pd.DataFrame,
    incidents_norm: pd.DataFrame,
) -> Dict[str, Any]:
    """Compute descriptive statistics from normalized DataFrames."""

    # Control status counts
    active_controls = int(
        controls_norm["implementation_status"]
        .str.lower()
        .eq("active")
        .sum()
    ) if "implementation_status" in controls_norm.columns else 0

    planned_controls = int(
        controls_norm["implementation_status"]
        .str.lower()
        .eq("planned")
        .sum()
    ) if "implementation_status" in controls_norm.columns else 0

    # Vulnerability open count
    open_vulns = int(
        vulns_norm["status"]
        .str.lower()
        .eq("open")
        .sum()
    ) if "status" in vulns_norm.columns else 0

    # Severity stats
    sev_avg = float(round(vulns_norm["severity"].mean(), 4)) if not vulns_norm.empty else 0.0
    sev_max = float(vulns_norm["severity"].max()) if not vulns_norm.empty else 0.0

    # Financial totals
    total_control_cost = float(controls_norm["annual_cost"].sum()) if "annual_cost" in controls_norm.columns else 0.0
    total_incident_loss = float(incidents_norm["average_loss"].sum()) if "average_loss" in incidents_norm.columns else 0.0
    total_downtime = float(incidents_norm["downtime_hours"].sum()) if "downtime_hours" in incidents_norm.columns else 0.0

    # Internet-exposed asset count
    internet_exposed_count = int(assets_norm["internet_exposed"].sum()) if "internet_exposed" in assets_norm.columns else 0

    # Unique departments and asset types (sorted for determinism)
    departments = sorted(assets_norm["department"].dropna().unique().tolist()) if "department" in assets_norm.columns else []
    asset_types = sorted(assets_norm["asset_type"].dropna().unique().tolist()) if "asset_type" in assets_norm.columns else []

    return {
        "asset_count": len(assets_norm),
        "vulnerability_count": len(vulns_norm),
        "control_count": len(controls_norm),
        "incident_count": len(incidents_norm),
        "internet_exposed_assets": internet_exposed_count,
        "active_controls": active_controls,
        "planned_controls": planned_controls,
        "open_vulnerabilities": open_vulns,
        "vulnerability_severity_avg": sev_avg,
        "vulnerability_severity_max": sev_max,
        "total_annual_control_cost": total_control_cost,
        "total_historical_incident_loss": total_incident_loss,
        "total_incident_downtime_hours": total_downtime,
        "departments": departments,
        "asset_types": asset_types,
    }


# ---------------------------------------------------------------------------
# Main processing function
# ---------------------------------------------------------------------------

def process_data(
    assets_df: pd.DataFrame,
    vulnerabilities_df: pd.DataFrame,
    controls_df: pd.DataFrame,
    incidents_df: pd.DataFrame,
) -> Dict[str, Any]:
    """
    Normalize and organize validated risk data into an asset-centric structure.

    Assumes validation has already passed. Input DataFrames are NOT mutated;
    deep copies are made internally.

    Returns a dict with:
      - "summary":  descriptive statistics
      - "assets":   list of per-asset profile dicts
    """

    # --- 1. Normalize (always on copies) ------------------------------------
    assets_norm = _normalize_assets(assets_df)
    vulns_norm = _normalize_vulnerabilities(vulnerabilities_df)
    controls_norm = _normalize_controls(controls_df)
    incidents_norm = _normalize_incidents(incidents_df)

    # --- 2. Build look-up maps grouped by asset_id -------------------------
    # Using groupby on pandas for efficiency; fall back to empty dicts where needed.
    vuln_groups: Dict[str, List[Dict]] = {}
    for asset_id, grp in vulns_norm.groupby("asset_id", sort=False):
        vuln_groups[str(asset_id)] = [_vuln_to_dict(row) for _, row in grp.iterrows()]

    control_groups: Dict[str, List[Dict]] = {}
    for asset_id, grp in controls_norm.groupby("asset_id", sort=False):
        control_groups[str(asset_id)] = [_control_to_dict(row) for _, row in grp.iterrows()]

    incident_groups: Dict[str, List[Dict]] = {}
    for asset_id, grp in incidents_norm.groupby("asset_id", sort=False):
        incident_groups[str(asset_id)] = [_incident_to_dict(row) for _, row in grp.iterrows()]

    # --- 3. Assemble asset profiles ----------------------------------------
    asset_profiles: List[Dict[str, Any]] = []
    for _, asset_row in assets_norm.iterrows():
        aid = str(asset_row["asset_id"])
        profile = _build_asset_profile(
            asset_row,
            vuln_groups.get(aid, []),
            control_groups.get(aid, []),
            incident_groups.get(aid, []),
        )
        asset_profiles.append(profile)

    # --- 4. Build summary ---------------------------------------------------
    summary = _build_summary(assets_norm, vulns_norm, controls_norm, incidents_norm)

    return {
        "summary": summary,
        "assets": asset_profiles,
    }
