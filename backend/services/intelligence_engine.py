"""
Asset & Vulnerability Intelligence Engine Service for Cyber Risk Analyzer (Phase 8).
Provides structured, explainable intelligence profiles for assets and vulnerabilities,
combining Phase 4 (Risk Engine) and Phase 5 (Financial Engine) outputs with deterministic
prioritization and enterprise summary metrics.

DISCLAIMER:
Intelligence evaluations are descriptive modeling outputs based solely on user-supplied
CSV data and Phase 4-5 calculations. They do not represent real-world threat telemetry
or automated exploit detection.
"""

from typing import Any, Dict, List, Optional


def build_intelligence(
    processed_data: Optional[Dict[str, Any]] = None,
    risk_results: Optional[Dict[str, Any]] = None,
    financial_results: Optional[Dict[str, Any]] = None,
    threat_results: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Build structured asset and vulnerability intelligence profiles.

    Args:
        processed_data: Output of process_data() (Phase 3)
        risk_results: Output of calculate_risk() (Phase 4)
        financial_results: Output of calculate_financial_risk() (Phase 5)
        threat_results: Output of analyze_threats() (Phase 6)

    Returns:
        Dict containing asset profiles, vulnerability profiles, enterprise summary,
        and deterministic rankings.
    """

    # 1. Resolve raw assets from processed_data or kwargs
    raw_assets: List[Dict[str, Any]] = []
    if processed_data and isinstance(processed_data, dict):
        raw_assets = processed_data.get("assets", [])
    elif "assets" in kwargs and isinstance(kwargs["assets"], list):
        raw_assets = kwargs["assets"]

    # 2. Resolve Phase 4 Risk Scored Assets Map
    scored_assets: List[Dict[str, Any]] = []
    if risk_results and isinstance(risk_results, dict):
        scored_assets = risk_results.get("assets", [])
    risk_map: Dict[str, Dict[str, Any]] = {}
    for a in scored_assets:
        aid = str(a.get("asset_id", ""))
        r_obj = a.get("risk", {})
        risk_map[aid] = {
            "score": float(r_obj.get("score", 0.0)),
            "level": str(r_obj.get("level", "LOW")),
            "risk_factor": float(r_obj.get("risk_factor", 0.0)),
            "combined_vulnerability_exposure": float(r_obj.get("combined_vulnerability_exposure", 0.0)),
            "combined_control_effectiveness": float(r_obj.get("combined_control_effectiveness", 0.0)),
            "remaining_exposure": float(r_obj.get("remaining_exposure", 1.0)),
            "base_exposure": float(r_obj.get("base_exposure", 0.0)),
        }

    # 3. Resolve Phase 5 Financial Scored Assets Map
    fin_assets: List[Dict[str, Any]] = []
    if financial_results and isinstance(financial_results, dict):
        fin_assets = financial_results.get("assets", [])
    fin_map: Dict[str, Dict[str, Any]] = {}
    for a in fin_assets:
        aid = str(a.get("asset_id", ""))
        f_obj = a.get("financial", {})
        fin_map[aid] = {
            "historical_annualized_loss": float(f_obj.get("historical_annualized_loss", 0.0)),
            "risk_based_business_exposure": float(f_obj.get("risk_based_business_exposure", 0.0)),
            "total_historical_downtime_hours": float(f_obj.get("total_historical_downtime_hours", 0.0)),
            "weighted_annual_downtime_hours": float(f_obj.get("weighted_annual_downtime_hours", 0.0)),
            "financial_data_available": bool(f_obj.get("financial_data_available", False)),
            "historical_data_available": bool(f_obj.get("financial_data_available", False)),
            "financial_risk_level": str(a.get("financial_risk_level", "LOW")),
        }

    # 4. Process Asset Intelligence Profiles
    asset_profiles: List[Dict[str, Any]] = []
    all_vulnerabilities: List[Dict[str, Any]] = []
    all_controls: List[Dict[str, Any]] = []
    all_incidents: List[Dict[str, Any]] = []

    for a in raw_assets:
        aid = str(a.get("asset_id", ""))
        info = a.get("asset", {})
        aname = info.get("asset_name", aid)

        # Vulnerabilities
        v_records = []
        for v in a.get("vulnerabilities", []):
            vid = str(v.get("vulnerability_id", ""))
            vname = str(v.get("vulnerability_name", vid))
            sev = float(v.get("severity", 0.0))
            exp = float(v.get("exploitability", 0.0))
            status = str(v.get("status", "Open")).strip()
            disc_date = str(v.get("discovered_date", ""))
            v_exp = round((sev / 10.0) * exp, 4)

            rec = {
                "vulnerability_id": vid,
                "asset_id": aid,
                "asset_name": aname,
                "vulnerability_name": vname,
                "severity": sev,
                "exploitability": exp,
                "status": status,
                "discovered_date": disc_date,
                "vulnerability_exposure": v_exp,
            }
            v_records.append(rec)
            all_vulnerabilities.append(rec)

        # Controls
        c_records = []
        for c in a.get("controls", []):
            cid = str(c.get("control_id", ""))
            cname = str(c.get("control_name", cid))
            eff = float(c.get("effectiveness", 0.0))
            imp_status = str(c.get("implementation_status", "Active")).strip()
            is_active = imp_status.lower() in ("active", "implemented", "yes", "true", "1")
            cost = float(c.get("annual_cost", 0.0))

            rec = {
                "control_id": cid,
                "asset_id": aid,
                "asset_name": aname,
                "control_name": cname,
                "effectiveness": eff,
                "implementation_status": imp_status,
                "is_active": is_active,
                "annual_cost": cost,
            }
            c_records.append(rec)
            all_controls.append(rec)

        # Incidents
        i_records = []
        for i in a.get("incidents", []):
            iid = str(i.get("incident_id", ""))
            itype = str(i.get("incident_type", ""))
            freq = float(i.get("frequency_per_year", 0.0))
            loss = float(i.get("average_loss", 0.0))
            down = float(i.get("downtime_hours", 0.0))

            rec = {
                "incident_id": iid,
                "asset_id": aid,
                "asset_name": aname,
                "incident_type": itype,
                "frequency_per_year": freq,
                "average_loss": loss,
                "downtime_hours": down,
                "annualized_loss": round(freq * loss, 2),
            }
            i_records.append(rec)
            all_incidents.append(rec)

        # Risk metrics fallback
        r_info = risk_map.get(aid, {
            "score": 0.0, "level": "LOW", "risk_factor": 0.0,
            "combined_vulnerability_exposure": 0.0,
            "combined_control_effectiveness": 0.0,
            "remaining_exposure": 1.0, "base_exposure": 0.0
        })

        # Financial metrics fallback
        f_info = fin_map.get(aid, {
            "historical_annualized_loss": 0.0,
            "risk_based_business_exposure": round(float(info.get("business_value", 0.0)) * (r_info["score"] / 100.0), 2),
            "total_historical_downtime_hours": 0.0,
            "weighted_annual_downtime_hours": 0.0,
            "financial_data_available": len(i_records) > 0,
            "historical_data_available": len(i_records) > 0,
            "financial_risk_level": r_info["level"],
        })

        profile = {
            "asset_id": aid,
            "asset_name": aname,
            "asset_type": str(info.get("asset_type", "")),
            "department": str(info.get("department", "")),
            "criticality": int(info.get("criticality", 1)),
            "business_value": float(info.get("business_value", 0.0)),
            "internet_exposed": bool(info.get("internet_exposed", False)),
            "data_sensitivity": int(info.get("data_sensitivity", 1)),
            "risk": r_info,
            "financial": f_info,
            "vulnerabilities": v_records,
            "controls": c_records,
            "incidents": i_records,
            "vulnerability_count": len(v_records),
            "control_count": len(c_records),
            "incident_count": len(i_records),
        }
        asset_profiles.append(profile)

    # 5. Asset Prioritization (Sorted by risk_score DESC, business_value DESC, asset_id ASC)
    sorted_asset_profiles = sorted(
        asset_profiles,
        key=lambda x: (-x["risk"]["score"], -x["business_value"], x["asset_id"])
    )
    for rank, ap in enumerate(sorted_asset_profiles, start=1):
        ap["asset_rank"] = rank

    # 6. Vulnerability Prioritization (Sorted by severity DESC, exploitability DESC, vulnerability_id ASC)
    sorted_vulnerabilities = sorted(
        all_vulnerabilities,
        key=lambda x: (-x["severity"], -x["exploitability"], x["vulnerability_id"])
    )
    for rank, vp in enumerate(sorted_vulnerabilities, start=1):
        vp["vulnerability_rank"] = rank

    # 7. Enterprise Summary Statistics
    total_vulns = len(all_vulnerabilities)
    crit_vulns = sum(1 for v in all_vulnerabilities if v["severity"] >= 9.0)
    high_vulns = sum(1 for v in all_vulnerabilities if 7.0 <= v["severity"] < 9.0)
    med_vulns = sum(1 for v in all_vulnerabilities if 4.0 <= v["severity"] < 7.0)
    low_vulns = sum(1 for v in all_vulnerabilities if v["severity"] < 4.0)

    open_vulns = sum(1 for v in all_vulnerabilities if v["status"].lower() in ("open", "active", "unpatched"))
    resolved_vulns = sum(1 for v in all_vulnerabilities if v["status"].lower() in ("resolved", "closed", "fixed", "patched"))

    # Asset Risk Distribution
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for ap in sorted_asset_profiles:
        lvl = ap["risk"]["level"].lower()
        if lvl in dist:
            dist[lvl] += 1

    summary = {
        "asset_count": len(sorted_asset_profiles),
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": crit_vulns,
        "high_vulnerabilities": high_vulns,
        "medium_vulnerabilities": med_vulns,
        "low_vulnerabilities": low_vulns,
        "open_vulnerabilities": open_vulns,
        "resolved_vulnerabilities": resolved_vulns,
        "total_controls": len(all_controls),
        "active_controls": sum(1 for c in all_controls if c["is_active"]),
        "total_incidents": len(all_incidents),
        "asset_risk_distribution": dist,
    }

    # Top Risk Assets & Top Vulnerabilities
    top_risk_assets = [
        {
            "asset_id": a["asset_id"],
            "asset_name": a["asset_name"],
            "risk_score": a["risk"]["score"],
            "risk_level": a["risk"]["level"],
            "business_value": a["business_value"],
            "asset_rank": a["asset_rank"],
        }
        for a in sorted_asset_profiles[:10]
    ]

    top_vulnerabilities = [
        {
            "vulnerability_id": v["vulnerability_id"],
            "asset_id": v["asset_id"],
            "asset_name": v["asset_name"],
            "vulnerability_name": v["vulnerability_name"],
            "severity": v["severity"],
            "exploitability": v["exploitability"],
            "vulnerability_exposure": v["vulnerability_exposure"],
            "status": v["status"],
            "vulnerability_rank": v["vulnerability_rank"],
        }
        for v in sorted_vulnerabilities[:10]
    ]

    return {
        "status": "ok",
        "assets": sorted_asset_profiles,
        "vulnerabilities": sorted_vulnerabilities,
        "summary": summary,
        "top_risk_assets": top_risk_assets,
        "top_vulnerabilities": top_vulnerabilities,
    }
