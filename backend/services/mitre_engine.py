"""
MITRE ATT&CK Threat Mapping Engine Service for Cyber Risk Analyzer (Phase 13).
Provides deterministic, explainable MITRE ATT&CK Enterprise threat mappings
and technique/tactic aggregations without AI, embeddings, or runtime scraping.

All mappings connect back to Phase 4 Risk Engine and Phase 5 Financial Engine metrics.
"""

from typing import Any, Dict, List, Optional
from services.risk_engine import get_risk_level

MITRE_METADATA = {
    "framework": "MITRE ATT&CK Enterprise",
    "mapping_version": "1.0",
    "mapping_method": "deterministic_incident_category"
}

# Deterministic Mapping Catalog for Incident Categories
MITRE_MAPPING: Dict[str, List[Dict[str, str]]] = {
    "Ransomware": [
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Ransomware incidents directly involve data encryption for impact and extortion (T1486)."
        }
    ],
    "Server Compromise": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "Server compromise typically involves unauthorized command execution or scripting interpreter use (T1059)."
        }
    ],
    "Data Breach": [
        {
            "tactic_id": "TA0010",
            "tactic_name": "Exfiltration",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "Data breach incidents reflect unauthorized extraction of sensitive data from corporate systems (T1041)."
        }
    ],
    "Credential Theft": [
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Credential theft incident indicates extraction or dumping of system authentication credentials (T1003)."
        }
    ],
    "Account Takeover": [
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "Account takeover incidents typically result from credential stuffing or brute force credential attacks (T1110)."
        }
    ],
    "Defacement": [
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1491",
            "technique_name": "Defacement",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Defacement incidents directly correspond to ATT&CK Impact technique T1491."
        }
    ],
    "Supply Chain Injection": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1195",
            "technique_name": "Supply Chain Compromise",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Supply chain injection directly corresponds to ATT&CK Initial Access technique T1195."
        }
    ],
    "Source Code Leak": [
        {
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1213",
            "technique_name": "Data from Information Repositories",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "Source code leakage reflects unauthorized collection from code repositories or version control systems (T1213)."
        }
    ],
    "Domain Admin Compromise": [
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Domain admin compromise involves abusing privileged administrative domain accounts (T1078)."
        }
    ],
    "Backup Deletion Attack": [
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1490",
            "technique_name": "Inhibit System Recovery",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Backup deletion attacks directly correspond to ATT&CK technique T1490 (Inhibit System Recovery)."
        }
    ],
    "Data Exfiltration": [
        {
            "tactic_id": "TA0010",
            "tactic_name": "Exfiltration",
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Data exfiltration incidents indicate transfer of sensitive enterprise data outside network boundaries (T1048)."
        }
    ],
    "Phishing": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Phishing incidents directly map to ATT&CK Initial Access technique T1566."
        }
    ],
    "Phishing Credential Harvester": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Phishing credential harvester incidents map directly to ATT&CK Initial Access technique T1566."
        }
    ],
    "Business Email Compromise": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1566.002",
            "technique_name": "Phishing: Spearphishing Link",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Business email compromise uses targeted spearphishing messages to trick organization personnel (T1566.002)."
        }
    ],
    "Privilege Escalation": [
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Privilege escalation incidents directly correspond to ATT&CK technique T1068."
        }
    ],
    "Denial of Service": [
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "mapping_confidence": "HIGH",
            "mapping_basis": "Denial of service incidents map directly to ATT&CK Impact technique T1498."
        }
    ],
    "DDoS": [
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "mapping_confidence": "HIGH",
            "mapping_basis": "DDoS incidents map directly to ATT&CK Impact technique T1498."
        }
    ],
    "Insider Misuse": [
        {
            "tactic_id": "TA0008",
            "tactic_name": "Lateral Movement",
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "Insider misuse involves legitimate internal account privileges being abused beyond intended authorization (T1078.003)."
        }
    ],
    "PII Scraping": [
        {
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1119",
            "technique_name": "Automated Collection",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "PII scraping indicates automated harvesting of personally identifiable information from database/web endpoints (T1119)."
        }
    ],
    "Botnet Recruitment": [
        {
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "Botnet recruitment involves establishing C2 beaconing protocols on infected endpoints (T1071)."
        }
    ],
    "API Abuse": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "mapping_confidence": "MEDIUM",
            "mapping_basis": "API abuse targets exposed web application API endpoints for unauthorized data access (T1190)."
        }
    ]
}


def build_mitre_intelligence(
    processed_data: Optional[Dict[str, Any]] = None,
    risk_results: Optional[Dict[str, Any]] = None,
    financial_results: Optional[Dict[str, Any]] = None,
    threat_results: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Generate MITRE ATT&CK Threat Mapping Intelligence.

    Args:
        processed_data: Output of process_data() (Phase 3)
        risk_results: Output of calculate_risk() (Phase 4)
        financial_results: Output of calculate_financial_risk() (Phase 5)
        threat_results: Output of analyze_threats() (Phase 6)

    Returns:
        JSON-serializable dict containing metadata, summary, incident mappings,
        technique aggregations, and tactic aggregations.
    """
    # 1. Resolve raw incidents
    raw_incidents: List[Dict[str, Any]] = []
    if processed_data and isinstance(processed_data, dict):
        for a in processed_data.get("assets", []):
            aid = str(a.get("asset_id", ""))
            for inc in a.get("incidents", []):
                inc_copy = dict(inc)
                if not inc_copy.get("asset_id"):
                    inc_copy["asset_id"] = aid
                raw_incidents.append(inc_copy)

    if not raw_incidents and "incidents" in kwargs and isinstance(kwargs["incidents"], list):
        raw_incidents = kwargs["incidents"]

    if not raw_incidents and "kwargs" in kwargs and isinstance(kwargs["kwargs"], dict):
        raw_incidents = kwargs["kwargs"].get("incidents", [])

    # Fallback to threat_results if raw_incidents is empty
    if not raw_incidents and threat_results and isinstance(threat_results, dict):
        for t in threat_results.get("scenarios", []):
            for i_item in t.get("incidents", []):
                raw_incidents.append(i_item)

    # Asset Risk Map & Asset Info Map
    risk_map: Dict[str, Dict[str, Any]] = {}
    if risk_results and isinstance(risk_results, dict):
        for a in risk_results.get("assets", []):
            aid = str(a.get("asset_id", ""))
            r_obj = a.get("risk", {})
            risk_map[aid] = {
                "score": float(r_obj.get("score", 0.0)),
                "level": str(r_obj.get("level", get_risk_level(float(r_obj.get("score", 0.0))))),
            }

    asset_info_map: Dict[str, Dict[str, Any]] = {}
    if processed_data and isinstance(processed_data, dict):
        for a in processed_data.get("assets", []):
            aid = str(a.get("asset_id", ""))
            meta = a.get("asset", {})
            asset_info_map[aid] = {
                "asset_name": meta.get("asset_name") or a.get("asset_name") or aid,
                "business_value": float(meta.get("business_value", 0.0)),
            }

    # 2. Incident-Level Mapping
    mapped_incidents_list: List[Dict[str, Any]] = []
    mapped_count = 0
    unmapped_count = 0

    for idx, inc in enumerate(raw_incidents):
        iid = str(inc.get("incident_id", f"I{idx+1:03d}"))
        aid = str(inc.get("asset_id", ""))
        itype = str(inc.get("incident_type", "")).strip()

        freq = float(inc.get("frequency_per_year", 0.0))
        avg_loss = float(inc.get("average_loss", 0.0))
        downtime = float(inc.get("downtime_hours", 0.0))
        ann_loss = float(inc.get("annualized_loss", freq * avg_loss))

        mappings = MITRE_MAPPING.get(itype, [])

        if mappings:
            status = "MAPPED"
            mapped_count += 1
            mitre_info = mappings
            reason = None
        else:
            status = "UNMAPPED"
            unmapped_count += 1
            mitre_info = []
            reason = "No deterministic MITRE ATT&CK mapping is configured for this incident type."

        mapped_incidents_list.append({
            "incident_id": iid,
            "asset_id": aid,
            "incident_type": itype,
            "frequency_per_year": freq,
            "average_loss": avg_loss,
            "annualized_loss": ann_loss,
            "downtime_hours": downtime,
            "mapping_status": status,
            "mitre": mitre_info,
            "unmapped_reason": reason,
        })

    # 3. Technique-Level Aggregation
    technique_buckets: Dict[str, Dict[str, Any]] = {}

    for inc in mapped_incidents_list:
        if inc["mapping_status"] != "MAPPED":
            continue

        aid = inc["asset_id"]
        ann_loss = inc["annualized_loss"]
        downtime = inc["downtime_hours"]

        for m in inc["mitre"]:
            tid = m["technique_id"]
            if tid not in technique_buckets:
                technique_buckets[tid] = {
                    "technique_id": tid,
                    "technique_name": m["technique_name"],
                    "tactic_id": m["tactic_id"],
                    "tactic_name": m["tactic_name"],
                    "incident_ids": set(),
                    "affected_assets": set(),
                    "historical_annualized_loss": 0.0,
                    "total_downtime_hours": 0.0,
                    "mapping_confidence": m["mapping_confidence"],
                    "mapping_basis": m["mapping_basis"],
                }

            b = technique_buckets[tid]
            b["incident_ids"].add(inc["incident_id"])
            if aid:
                b["affected_assets"].add(aid)
            b["historical_annualized_loss"] += ann_loss
            b["total_downtime_hours"] += downtime

    techniques_list: List[Dict[str, Any]] = []
    for tid, b in technique_buckets.items():
        assets_sorted = sorted(list(b["affected_assets"]))
        total_bv = sum(asset_info_map.get(a, {}).get("business_value", 0.0) for a in assets_sorted)

        # Risk context: highest asset risk score
        highest_score = 0.0
        highest_level = "LOW"
        highest_asset_id = ""

        for a in assets_sorted:
            r_score = risk_map.get(a, {}).get("score", 0.0)
            if r_score >= highest_score:
                highest_score = r_score
                highest_level = risk_map.get(a, {}).get("level", get_risk_level(r_score))
                highest_asset_id = a

        techniques_list.append({
            "technique_id": tid,
            "technique_name": b["technique_name"],
            "tactic_id": b["tactic_id"],
            "tactic_name": b["tactic_name"],
            "incident_count": len(b["incident_ids"]),
            "affected_asset_count": len(assets_sorted),
            "affected_assets": assets_sorted,
            "affected_business_value": total_bv,
            "historical_annualized_loss": round(b["historical_annualized_loss"], 2),
            "total_downtime_hours": round(b["total_downtime_hours"], 2),
            "highest_asset_risk_score": highest_score,
            "highest_asset_risk_level": highest_level,
            "highest_risk_asset_id": highest_asset_id,
            "mapping_confidence": b["mapping_confidence"],
            "mapping_basis": b["mapping_basis"],
        })

    # Sort techniques deterministically by historical_annualized_loss DESC, then technique_id ASC
    techniques_list.sort(key=lambda t: (-t["historical_annualized_loss"], t["technique_id"]))

    # 4. Tactic-Level Aggregation
    tactic_buckets: Dict[str, Dict[str, Any]] = {}

    for t in techniques_list:
        tac_id = t["tactic_id"]
        if tac_id not in tactic_buckets:
            tactic_buckets[tac_id] = {
                "tactic_id": tac_id,
                "tactic_name": t["tactic_name"],
                "technique_ids": set(),
                "incident_ids": set(),
                "affected_assets": set(),
                "historical_annualized_loss": 0.0,
                "total_downtime_hours": 0.0,
                "highest_asset_risk_score": 0.0,
                "highest_asset_risk_level": "LOW",
            }

        tb = tactic_buckets[tac_id]
        tb["technique_ids"].add(t["technique_id"])
        for a in t["affected_assets"]:
            tb["affected_assets"].add(a)

    # Accumulate incidents and losses per tactic directly from mapped incidents
    for inc in mapped_incidents_list:
        if inc["mapping_status"] != "MAPPED":
            continue
        aid = inc["asset_id"]
        ann_loss = inc["annualized_loss"]
        downtime = inc["downtime_hours"]

        seen_tactics = set()
        for m in inc["mitre"]:
            tac_id = m["tactic_id"]
            if tac_id not in seen_tactics:
                seen_tactics.add(tac_id)
                if tac_id in tactic_buckets:
                    tactic_buckets[tac_id]["incident_ids"].add(inc["incident_id"])
                    tactic_buckets[tac_id]["historical_annualized_loss"] += ann_loss
                    tactic_buckets[tac_id]["total_downtime_hours"] += downtime

    tactics_list: List[Dict[str, Any]] = []
    for tac_id, tb in tactic_buckets.items():
        assets_sorted = sorted(list(tb["affected_assets"]))

        highest_score = 0.0
        highest_level = "LOW"
        for a in assets_sorted:
            r_score = risk_map.get(a, {}).get("score", 0.0)
            if r_score >= highest_score:
                highest_score = r_score
                highest_level = risk_map.get(a, {}).get("level", get_risk_level(r_score))

        tactics_list.append({
            "tactic_id": tac_id,
            "tactic_name": tb["tactic_name"],
            "technique_count": len(tb["technique_ids"]),
            "incident_count": len(tb["incident_ids"]),
            "affected_asset_count": len(assets_sorted),
            "affected_assets": assets_sorted,
            "historical_annualized_loss": round(tb["historical_annualized_loss"], 2),
            "total_downtime_hours": round(tb["total_downtime_hours"], 2),
            "highest_asset_risk_score": highest_score,
            "highest_asset_risk_level": highest_level,
        })

    # Sort tactics by historical_annualized_loss DESC, then tactic_id ASC
    tactics_list.sort(key=lambda tac: (-tac["historical_annualized_loss"], tac["tactic_id"]))

    # 5. Enterprise Summary & Coverage
    total_incidents = len(raw_incidents)
    coverage_pct = round((mapped_count / total_incidents * 100.0), 2) if total_incidents > 0 else 0.0

    summary = {
        "total_incidents": total_incidents,
        "mapped_incidents": mapped_count,
        "unmapped_incidents": unmapped_count,
        "mapping_coverage_percentage": coverage_pct,
        "unique_tactics": len(tactics_list),
        "unique_techniques": len(techniques_list),
    }

    return {
        "status": "success",
        "metadata": MITRE_METADATA,
        "summary": summary,
        "incidents": mapped_incidents_list,
        "techniques": techniques_list,
        "tactics": tactics_list,
    }
