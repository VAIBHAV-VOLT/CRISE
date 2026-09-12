"""
Threat & Scenario Engine Service for Cyber Risk Analyzer (Phase 6).
Derives deterministic, explainable scenarios from supplied incident history,
mapping affected assets and providing cybersecurity risk context.

DISCLAIMER:
Threat and scenario evaluations are descriptive and modeling-focused, not
predictive intelligence. Scenarios are derived solely from user-supplied incident
records. The model does NOT predict future attack likelihoods or calculate
probabilities of compromise.
"""

from typing import Any, Dict, List, Optional


def analyze_threats(
    processed_data: Optional[Dict[str, Any]] = None,
    risk_results: Optional[Dict[str, Any]] = None,
    assets: Optional[List[Dict[str, Any]]] = None,
    incidents: Optional[List[Dict[str, Any]]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Analyze threats and generate scenario-level metrics derived from incident history.

    Accepts:
      - processed_data: Output of process_data() containing asset profiles with incidents
      - risk_results: Output of calculate_risk() containing Phase 4 modeled risk scores
      - assets (optional): Direct list of asset profiles
      - incidents (optional): Direct list of incident dictionaries
    """
    # 1. Resolve Assets
    raw_assets: List[Dict[str, Any]] = []
    if processed_data and isinstance(processed_data, dict):
        raw_assets = processed_data.get("assets", [])
    elif assets and isinstance(assets, list):
        raw_assets = assets

    # 2. Resolve Phase 4 Scored Assets
    scored_assets: List[Dict[str, Any]] = []
    if risk_results and isinstance(risk_results, dict):
        scored_assets = risk_results.get("assets", [])
    elif "risk_result" in kwargs and isinstance(kwargs["risk_result"], dict):
        scored_assets = kwargs["risk_result"].get("assets", [])

    scored_map = {str(a.get("asset_id")): a for a in scored_assets}

    # 3. Resolve Incidents
    all_incidents: List[Dict[str, Any]] = []
    if incidents is not None and isinstance(incidents, list):
        all_incidents = [dict(i) for i in incidents]
    else:
        for a in raw_assets:
            aid = str(a.get("asset_id", ""))
            for inc in a.get("incidents", []):
                inc_dict = dict(inc)
                if not inc_dict.get("asset_id"):
                    inc_dict["asset_id"] = aid
                all_incidents.append(inc_dict)

    # 4. Handle No Incident History Gracefully
    if not all_incidents:
        return {
            "status": "no_incident_history",
            "scenario_count": 0,
            "scenarios": [],
            "message": "No incident history is available for threat/scenario analysis.",
        }

    # 5. Build Asset Lookup Map
    asset_info_map: Dict[str, Dict[str, Any]] = {}
    for a in raw_assets:
        aid = str(a.get("asset_id", ""))
        info = a.get("asset", {})
        matching_scored = scored_map.get(aid, {})
        risk_obj = matching_scored.get("risk", {})
        score = float(risk_obj.get("score", 0.0))
        level = str(risk_obj.get("level", "LOW"))

        asset_info_map[aid] = {
            "asset_id": aid,
            "asset_name": info.get("asset_name", aid),
            "asset_type": info.get("asset_type", ""),
            "department": info.get("department", ""),
            "criticality": int(info.get("criticality", 1)),
            "business_value": float(info.get("business_value", 0.0)),
            "risk_score": score,
            "risk_level": level,
        }

    # 6. Group Incidents by incident_type
    grouped_incidents: Dict[str, List[Dict[str, Any]]] = {}
    for inc in all_incidents:
        itype = str(inc.get("incident_type", "")).strip()
        if not itype:
            itype = "Unclassified"
        grouped_incidents.setdefault(itype, []).append(inc)

    # 7. Build Scenarios Deterministically (Sorted by Scenario Type)
    sorted_types = sorted(grouped_incidents.keys())
    scenarios: List[Dict[str, Any]] = []

    for idx, itype in enumerate(sorted_types, start=1):
        scenario_id = f"SCN-{idx:03d}"
        inc_list = grouped_incidents[itype]

        incident_count = len(inc_list)
        total_freq = round(sum(float(i.get("frequency_per_year", 0.0)) for i in inc_list), 4)
        hist_loss = round(sum(float(i.get("frequency_per_year", 0.0)) * float(i.get("average_loss", 0.0)) for i in inc_list), 2)
        total_downtime = round(sum(float(i.get("downtime_hours", 0.0)) for i in inc_list), 2)
        weighted_downtime = round(sum(float(i.get("frequency_per_year", 0.0)) * float(i.get("downtime_hours", 0.0)) for i in inc_list), 2)

        # Preserve raw incident details with annualized loss
        preserved_incidents = []
        for i in inc_list:
            freq = float(i.get("frequency_per_year", 0.0))
            avg_loss = float(i.get("average_loss", 0.0))
            down = float(i.get("downtime_hours", 0.0))
            preserved_incidents.append({
                "incident_id": i.get("incident_id", ""),
                "asset_id": i.get("asset_id", ""),
                "incident_type": itype,
                "frequency_per_year": freq,
                "average_loss": avg_loss,
                "downtime_hours": down,
                "annualized_loss": round(freq * avg_loss, 2),
            })

        # Affected unique assets
        affected_ids = sorted(list({str(i.get("asset_id")) for i in inc_list if i.get("asset_id")}))
        affected_assets = [asset_info_map[aid] for aid in affected_ids if aid in asset_info_map]
        affected_asset_count = len(affected_assets)
        affected_asset_bv = round(sum(a["business_value"] for a in affected_assets), 2)

        # Risk context and highest-risk asset determination
        if affected_assets:
            # Sort deterministically by descending risk score, with tie-breaking by lowest asset_id
            sorted_by_risk = sorted(affected_assets, key=lambda a: (-a["risk_score"], a["asset_id"]))
            top_asset = sorted_by_risk[0]
            highest_risk_asset = {
                "asset_id": top_asset["asset_id"],
                "asset_name": top_asset["asset_name"],
                "risk_score": top_asset["risk_score"],
                "risk_level": top_asset["risk_level"],
            }
            highest_risk_score = top_asset["risk_score"]
            highest_risk_level = top_asset["risk_level"]
            avg_risk_score = round(sum(a["risk_score"] for a in affected_assets) / affected_asset_count, 2)
            if affected_asset_bv > 0.0:
                bv_weighted_score = round(sum(a["risk_score"] * a["business_value"] for a in affected_assets) / affected_asset_bv, 2)
            else:
                bv_weighted_score = avg_risk_score
        else:
            highest_risk_asset = None
            highest_risk_score = 0.0
            highest_risk_level = "LOW"
            avg_risk_score = 0.0
            bv_weighted_score = 0.0

        scenario_risk_level = highest_risk_level

        # Deterministic, rule-based description (no AI, no probability claims)
        description = (
            f"{itype} affects {affected_asset_count} asset(s). Supplied incident history corresponds to "
            f"₹{hist_loss:,.2f} historical annualized loss and {weighted_downtime:.1f} weighted downtime hours/year. "
            f"Reported annual frequency is {total_freq:.2f} events/year."
        )

        scenarios.append({
            "scenario_id": scenario_id,
            "scenario_type": itype,
            "description": description,
            "incident_count": incident_count,
            "total_supplied_frequency_per_year": total_freq,
            "historical_annualized_loss": hist_loss,
            "total_historical_downtime": total_downtime,
            "weighted_annual_downtime": weighted_downtime,
            "affected_asset_count": affected_asset_count,
            "affected_asset_business_value": affected_asset_bv,
            "affected_assets": affected_assets,
            "highest_risk_asset": highest_risk_asset,
            "highest_risk_score": highest_risk_score,
            "highest_risk_level": highest_risk_level,
            "average_affected_asset_risk_score": avg_risk_score,
            "business_value_weighted_risk_score": bv_weighted_score,
            "scenario_risk_level": scenario_risk_level,
            "incidents": preserved_incidents,
        })

    total_supplied_freq = round(sum(s["total_supplied_frequency_per_year"] for s in scenarios), 4)
    total_hist_loss = round(sum(s["historical_annualized_loss"] for s in scenarios), 2)
    total_weighted_down = round(sum(s["weighted_annual_downtime"] for s in scenarios), 2)

    return {
        "status": "ok",
        "scenario_count": len(scenarios),
        "total_supplied_frequency_per_year": total_supplied_freq,
        "total_historical_annualized_loss": total_hist_loss,
        "total_weighted_annual_downtime": total_weighted_down,
        "scenarios": scenarios,
    }
