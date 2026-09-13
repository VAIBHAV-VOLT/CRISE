"""
Recommendation Engine Service for Cyber Risk Analyzer (Phase 11).
Generates deterministic, explainable, prioritized cybersecurity recommendations
consuming Phase 4-10 risk, financial, threat, intelligence, and optimizer outputs.

No invented data. Operates strictly on user-supplied CSV data and calculated Phase 4-10 metrics.
"""

import copy
from typing import Any, Dict, List, Optional


PRIORITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def generate_recommendations(
    processed_data: Optional[Dict[str, Any]] = None,
    risk_results: Optional[Dict[str, Any]] = None,
    financial_results: Optional[Dict[str, Any]] = None,
    threat_results: Optional[Dict[str, Any]] = None,
    intelligence_results: Optional[Dict[str, Any]] = None,
    optimizer_results: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Generate prioritized, explainable cybersecurity recommendations.

    Args:
        processed_data: Output of process_data() (Phase 3)
        risk_results: Output of calculate_risk() (Phase 4)
        financial_results: Output of calculate_financial_risk() (Phase 5)
        threat_results: Output of analyze_threats() (Phase 6)
        intelligence_results: Output of build_intelligence() (Phase 8)
        optimizer_results: Optional output of optimize_investments() (Phase 10)

    Returns:
        JSON-serializable dict containing status, summary, recommendations, and quick_wins.
    """
    # 1. Resolve raw data safely
    raw_assets: List[Dict[str, Any]] = []
    if processed_data and isinstance(processed_data, dict):
        raw_assets = processed_data.get("assets", [])
    elif "assets" in kwargs and isinstance(kwargs["assets"], list):
        raw_assets = kwargs["assets"]

    # If processed_data is empty, check risk_results
    risk_assets: List[Dict[str, Any]] = []
    if risk_results and isinstance(risk_results, dict):
        risk_assets = risk_results.get("assets", [])

    fin_assets: List[Dict[str, Any]] = []
    if financial_results and isinstance(financial_results, dict):
        fin_assets = financial_results.get("assets", [])

    # Maps for fast lookup
    proc_asset_map: Dict[str, Dict[str, Any]] = {
        str(a.get("asset_id", "")): a for a in raw_assets if "asset_id" in a
    }
    risk_asset_map: Dict[str, Dict[str, Any]] = {
        str(a.get("asset_id", "")): a for a in risk_assets if "asset_id" in a
    }
    fin_asset_map: Dict[str, Dict[str, Any]] = {
        str(a.get("asset_id", "")): a for a in fin_assets if "asset_id" in a
    }

    # Optimizer selected control IDs set
    opt_selected_control_ids = set()
    if optimizer_results and isinstance(optimizer_results, dict):
        for ctrl in optimizer_results.get("selected_controls", []):
            if isinstance(ctrl, dict) and "control_id" in ctrl:
                opt_selected_control_ids.add(str(ctrl["control_id"]))

    # Combine all known asset IDs
    all_asset_ids = sorted(list(set(proc_asset_map.keys()) | set(risk_asset_map.keys())))

    raw_recs: List[Dict[str, Any]] = []
    seen_rec_keys = set()

    for aid in all_asset_ids:
        proc_item = proc_asset_map.get(aid, {})
        risk_item = risk_asset_map.get(aid, {})
        fin_item = fin_asset_map.get(aid, {})

        # Asset basic metadata
        asset_meta = proc_item.get("asset", {})
        asset_name = asset_meta.get("asset_name") or proc_item.get("asset_name") or risk_item.get("asset_name") or aid

        # Risk metrics
        r_obj = risk_item.get("risk", {})
        risk_score = float(r_obj.get("score", 0.0))
        risk_level = str(r_obj.get("level", "LOW")).upper()

        # Financial metrics
        f_obj = fin_item.get("financial", {}) if "financial" in fin_item else fin_item
        hist_loss = float(f_obj.get("historical_annualized_loss", 0.0))

        # Internet exposure
        raw_exposed = asset_meta.get("internet_exposed", proc_item.get("internet_exposed", False))
        internet_exposed = str(raw_exposed).lower() in ("true", "1", "yes")

        # Inactive controls list
        controls = proc_item.get("controls", [])
        inactive_controls = [
            c for c in controls
            if str(c.get("implementation_status", "")).strip().lower() not in ("active", "implemented", "1", "true")
        ]
        inactive_control_ids = [str(c.get("control_id")) for c in inactive_controls if "control_id" in c]

        # -------------------------------------------------------------
        # Driver 1: High-Risk Asset (ASSET_PROTECTION)
        # -------------------------------------------------------------
        if risk_level in ("CRITICAL", "HIGH") or risk_score >= 60.0:
            rec_key = f"ASSET_PROTECTION_{aid}"
            if rec_key not in seen_rec_keys:
                seen_rec_keys.add(rec_key)
                priority = "CRITICAL" if risk_level == "CRITICAL" or risk_score >= 80.0 else "HIGH"
                est_cost = sum(float(c.get("annual_cost", c.get("implementation_cost", 0.0))) for c in inactive_controls)
                raw_recs.append({
                    "priority": priority,
                    "category": "ASSET_PROTECTION",
                    "title": f"Enhance Protection for High-Risk Asset: {asset_name}",
                    "asset_id": aid,
                    "asset_name": asset_name,
                    "reason": f"Asset '{asset_name}' (ID: {aid}) exhibits elevated modeled risk score of {risk_score:.2f} ({risk_level}).",
                    "evidence": {
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    },
                    "recommended_action": f"Review and apply comprehensive security controls and monitoring for asset {asset_name}.",
                    "expected_impact": {
                        "type": "modeled_risk_reduction",
                        "description": f"Reduces overall exposure on high-risk asset {asset_name} (baseline risk score {risk_score:.2f})."
                    },
                    "related_control_ids": inactive_control_ids,
                    "estimated_annual_cost": est_cost,
                })

        # -------------------------------------------------------------
        # Driver 2: Vulnerability Remediation (VULNERABILITY_REMEDIATION)
        # -------------------------------------------------------------
        vulnerabilities = proc_item.get("vulnerabilities", [])
        for v in vulnerabilities:
            vid = str(v.get("vulnerability_id", ""))
            vname = v.get("vulnerability_name") or v.get("description") or vid
            sev = float(v.get("severity", 0.0))
            exp = float(v.get("exploitability", 0.0))
            vuln_exposure = round((sev / 10.0) * exp, 4)

            # Check threshold for recommendation
            if sev >= 6.0 or exp >= 0.6 or vuln_exposure >= 0.36:
                rec_key = f"VULN_{aid}_{vid}"
                if rec_key not in seen_rec_keys:
                    seen_rec_keys.add(rec_key)

                    # Priority evaluation (T12: priority elevation for extreme severity/exploitability)
                    if sev >= 9.0 and exp >= 0.8:
                        priority = "CRITICAL"
                    elif sev >= 7.0 or vuln_exposure >= 0.5:
                        priority = "HIGH"
                    elif sev >= 4.0:
                        priority = "MEDIUM"
                    else:
                        priority = "LOW"

                    raw_recs.append({
                        "priority": priority,
                        "category": "VULNERABILITY_REMEDIATION",
                        "title": f"Remediate {sev:.1f}-Severity Vulnerability {vid} on {asset_name}",
                        "asset_id": aid,
                        "asset_name": asset_name,
                        "reason": f"Vulnerability {vid} presents exposure factor of {vuln_exposure:.2f} (Severity {sev}, Exploitability {exp}).",
                        "evidence": {
                            "risk_score": risk_score,
                            "risk_level": risk_level,
                            "vulnerability_id": vid,
                            "severity": sev,
                            "exploitability": exp,
                            "vulnerability_exposure": vuln_exposure,
                        },
                        "recommended_action": f"Patch or remediate vulnerability {vid} ({vname}) on asset {asset_name}.",
                        "expected_impact": {
                            "type": "modeled_risk_reduction",
                            "description": f"Eliminates vulnerability exposure factor of {vuln_exposure:.2f} associated with {vid}."
                        },
                        "related_control_ids": inactive_control_ids,
                        "estimated_annual_cost": 0.0,
                    })

        # -------------------------------------------------------------
        # Driver 3: Control Implementation (CONTROL_IMPLEMENTATION)
        # -------------------------------------------------------------
        for c in inactive_controls:
            cid = str(c.get("control_id", ""))
            cname = c.get("control_name") or cid
            status = str(c.get("implementation_status", "Inactive"))
            eff = float(c.get("effectiveness", 0.0))
            cost = float(c.get("annual_cost", c.get("implementation_cost", 0.0)))

            rec_key = f"CTRL_{aid}_{cid}"
            if rec_key not in seen_rec_keys:
                seen_rec_keys.add(rec_key)

                # Determine priority
                if cid in opt_selected_control_ids:
                    priority = "CRITICAL" if risk_level in ("CRITICAL", "HIGH") else "HIGH"
                elif risk_level == "CRITICAL":
                    priority = "CRITICAL"
                elif risk_level == "HIGH" or eff >= 0.7:
                    priority = "HIGH"
                elif risk_level == "MEDIUM" or eff >= 0.4:
                    priority = "MEDIUM"
                else:
                    priority = "LOW"

                opt_note = " (Selected by Investment Optimizer)" if cid in opt_selected_control_ids else ""

                raw_recs.append({
                    "priority": priority,
                    "category": "CONTROL_IMPLEMENTATION",
                    "title": f"Implement Control {cid}: {cname} on {asset_name}",
                    "asset_id": aid,
                    "asset_name": asset_name,
                    "reason": f"Control {cid} ({cname}) is currently {status} but offers {eff * 100:.0f}% risk reduction effectiveness{opt_note}.",
                    "evidence": {
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "control_id": cid,
                        "control_name": cname,
                        "effectiveness": eff,
                        "implementation_status": status,
                        "annual_cost": cost,
                    },
                    "recommended_action": f"Deploy and activate security control {cid} ({cname}) on asset {asset_name}.",
                    "expected_impact": {
                        "type": "modeled_risk_reduction",
                        "description": f"Achieves up to {eff * 100:.0f}% modeled risk mitigation on asset {asset_name}."
                    },
                    "related_control_ids": [cid],
                    "estimated_annual_cost": cost,
                })

        # -------------------------------------------------------------
        # Driver 4: Exposure Reduction (EXPOSURE_REDUCTION)
        # -------------------------------------------------------------
        if internet_exposed:
            rec_key = f"EXPOSURE_{aid}"
            if rec_key not in seen_rec_keys:
                seen_rec_keys.add(rec_key)
                priority = "CRITICAL" if risk_level in ("CRITICAL", "HIGH") else "HIGH"
                raw_recs.append({
                    "priority": priority,
                    "category": "EXPOSURE_REDUCTION",
                    "title": f"Reduce Public Internet Exposure for Asset: {asset_name}",
                    "asset_id": aid,
                    "asset_name": asset_name,
                    "reason": f"Asset '{asset_name}' (ID: {aid}) is accessible from the public internet, increasing external exposure.",
                    "evidence": {
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "internet_exposed": True,
                    },
                    "recommended_action": f"Restrict direct internet accessibility for {asset_name} using VPN, WAF, or firewall isolation.",
                    "expected_impact": {
                        "type": "modeled_risk_reduction",
                        "description": f"Removes internet exposure multiplier for asset {asset_name}."
                    },
                    "related_control_ids": inactive_control_ids,
                    "estimated_annual_cost": 0.0,
                })

        # -------------------------------------------------------------
        # Driver 5: Incident Mitigation (INCIDENT_MITIGATION)
        # -------------------------------------------------------------
        incidents = proc_item.get("incidents", [])
        if hist_loss > 0 or len(incidents) > 0:
            rec_key = f"INCIDENT_{aid}"
            if rec_key not in seen_rec_keys:
                seen_rec_keys.add(rec_key)
                if hist_loss >= 500000 or risk_level == "CRITICAL":
                    priority = "CRITICAL"
                elif hist_loss >= 100000 or risk_level == "HIGH":
                    priority = "HIGH"
                else:
                    priority = "MEDIUM"

                raw_recs.append({
                    "priority": priority,
                    "category": "INCIDENT_MITIGATION",
                    "title": f"Mitigate Historical Incident Risk on Asset: {asset_name}",
                    "asset_id": aid,
                    "asset_name": asset_name,
                    "reason": f"Asset {asset_name} has a recorded history of {len(incidents)} incident(s) with annualized loss of ₹{hist_loss:,.2f}.",
                    "evidence": {
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "historical_annualized_loss": hist_loss,
                        "incident_count": len(incidents),
                    },
                    "recommended_action": f"Implement targeted controls and incident response procedures for asset {asset_name}.",
                    "expected_impact": {
                        "type": "modeled_risk_reduction",
                        "description": f"Mitigates recurrence of historical incident losses (₹{hist_loss:,.2f} annualized)."
                    },
                    "related_control_ids": inactive_control_ids,
                    "estimated_annual_cost": 0.0,
                })

    # 2. Deterministic Sorting:
    # Priority DESC -> Asset Risk Score DESC -> Vuln Severity DESC -> Vuln Exploitability DESC -> Cost ASC -> Title ASC
    def sort_key(r: Dict[str, Any]):
        p_weight = PRIORITY_WEIGHTS.get(r.get("priority", "LOW"), 1)
        ev = r.get("evidence", {})
        r_score = float(ev.get("risk_score", 0.0))
        sev = float(ev.get("severity", 0.0))
        exp = float(ev.get("exploitability", 0.0))
        cost = float(r.get("estimated_annual_cost", 0.0))
        title = str(r.get("title", ""))
        return (-p_weight, -r_score, -sev, -exp, cost, title)

    sorted_recs = sorted(raw_recs, key=sort_key)

    # 3. Assign recommendation IDs deterministically: REC-001, REC-002, ...
    final_recommendations: List[Dict[str, Any]] = []
    for idx, rec in enumerate(sorted_recs):
        rec_copy = dict(rec)
        rec_copy["recommendation_id"] = f"REC-{idx+1:03d}"
        final_recommendations.append(rec_copy)

    # 4. Identify Quick-Wins
    # Definition: low cost (cost <= 50,000) AND high effectiveness/high priority, OR 0 cost high priority remediations
    quick_wins: List[Dict[str, Any]] = []
    for rec in final_recommendations:
        cost = float(rec.get("estimated_annual_cost", 0.0))
        prio = rec.get("priority", "LOW")
        cat = rec.get("category", "")
        ev = rec.get("evidence", {})
        eff = float(ev.get("effectiveness", 0.0))

        if (cat == "CONTROL_IMPLEMENTATION" and cost <= 50000 and (eff >= 0.5 or prio in ("CRITICAL", "HIGH"))) or \
           (cat == "VULNERABILITY_REMEDIATION" and prio in ("CRITICAL", "HIGH")):
            quick_wins.append(rec)

    # 5. Compute summary metrics
    summary = {
        "total_recommendations": len(final_recommendations),
        "critical": sum(1 for r in final_recommendations if r.get("priority") == "CRITICAL"),
        "high": sum(1 for r in final_recommendations if r.get("priority") == "HIGH"),
        "medium": sum(1 for r in final_recommendations if r.get("priority") == "MEDIUM"),
        "low": sum(1 for r in final_recommendations if r.get("priority") == "LOW"),
    }

    status = "ok" if len(final_recommendations) > 0 else "no_recommendations"

    return {
        "status": status,
        "summary": summary,
        "recommendations": final_recommendations,
        "quick_wins": quick_wins,
    }
