"""
CRISE — Phase 14 Compliance & Security Framework Mapping Engine
================================================================
Deterministic, evidence-based compliance crosswalk engine translating
CRISE findings into NIST CSF 2.0, ISO/IEC 27001:2022, and CIS Controls v8.

CRITICAL PRINCIPLES:
1. Compliance mapping is NOT a new risk model and does NOT alter risk scores.
2. Output represents CRISE modeled framework coverage, NOT legal compliance or certification.
3. Every mapping item contains direct, non-probabilistic evidence extracted from CRISE data.
4. All status and priority determinations are evidence-driven and deterministic.
"""

from typing import Dict, List, Any, Optional

FRAMEWORK_METADATA = {
    "NIST_CSF": {
        "framework": "NIST Cybersecurity Framework",
        "version": "2.0 (2024)",
        "description": "NIST CSF 2.0 Functions: Govern, Identify, Protect, Detect, Respond, Recover"
    },
    "ISO_27001": {
        "framework": "ISO/IEC 27001",
        "version": "2022 (Annex A)",
        "description": "ISO/IEC 27001:2022 Annex A Information Security Controls"
    },
    "CIS_CONTROLS": {
        "framework": "CIS Critical Security Controls",
        "version": "v8 (2021)",
        "description": "Center for Internet Security (CIS) Controls v8"
    }
}

# Catalog mapping CRISE finding categories to standard framework categories & control IDs
COMPLIANCE_MAPPING = {
    "vulnerability_management": {
        "finding_title": "Vulnerability Risk Management",
        "mapping_basis": "Identifies unmitigated technical vulnerabilities on enterprise assets.",
        "mappings": {
            "NIST_CSF": {
                "function": "IDENTIFY / PROTECT",
                "category": "ID.RA (Risk Assessment) & PR.PS (Platform Security)",
                "control_id": "ID.RA-01 / PR.PS-02",
                "control_name": "Vulnerability Risk Assessment and Remediating Technical Flaws"
            },
            "ISO_27001": {
                "category": "Technological Controls",
                "control_id": "A.8.8",
                "control_name": "Management of technical vulnerabilities"
            },
            "CIS_CONTROLS": {
                "category": "Vulnerability Management",
                "control_id": "Control 7",
                "control_name": "Continuous Vulnerability Management"
            }
        }
    },
    "control_gap": {
        "finding_title": "Security Control Coverage Gap",
        "mapping_basis": "Identifies inactive, planned, or missing security controls on critical enterprise assets.",
        "mappings": {
            "NIST_CSF": {
                "function": "PROTECT",
                "category": "PR.AA (Identity & Access) & PR.PS (Protection Technology)",
                "control_id": "PR.AA-01 / PR.PS-01",
                "control_name": "Protective Security Control Implementation"
            },
            "ISO_27001": {
                "category": "Organizational & Technological Controls",
                "control_id": "A.5.15 / A.8.9",
                "control_name": "Access control & Configuration management"
            },
            "CIS_CONTROLS": {
                "category": "Secure Configuration & Access Control",
                "control_id": "Control 4 / Control 6",
                "control_name": "Secure Configuration of Enterprise Assets & Access Control Management"
            }
        }
    },
    "internet_exposure": {
        "finding_title": "External Network Perimeter Exposure",
        "mapping_basis": "Identifies assets exposed to the public internet requiring access and network perimeter protections.",
        "mappings": {
            "NIST_CSF": {
                "function": "PROTECT",
                "category": "PR.IR (Infrastructure Resilience) & PR.AA (Access Protection)",
                "control_id": "PR.IR-01 / PR.AA-05",
                "control_name": "Network Infrastructure & External Boundary Protection"
            },
            "ISO_27001": {
                "category": "Technological Controls",
                "control_id": "A.8.20 / A.8.21",
                "control_name": "Network security & Security of network services"
            },
            "CIS_CONTROLS": {
                "category": "Network Infrastructure Management",
                "control_id": "Control 12",
                "control_name": "Network Infrastructure Management"
            }
        }
    },
    "incident_response": {
        "finding_title": "Security Incident & Event Management",
        "mapping_basis": "Identifies historical security incident records requiring event analysis, response, and recovery controls.",
        "mappings": {
            "NIST_CSF": {
                "function": "DETECT / RESPOND",
                "category": "DE.AE (Adverse Event Analysis) & RS.MA (Incident Management)",
                "control_id": "DE.AE-02 / RS.MA-01",
                "control_name": "Adverse Event Analysis & Security Incident Response Management"
            },
            "ISO_27001": {
                "category": "Organizational Controls",
                "control_id": "A.5.24",
                "control_name": "Information security incident management planning and preparation"
            },
            "CIS_CONTROLS": {
                "category": "Incident Response Management",
                "control_id": "Control 17",
                "control_name": "Incident Response Management"
            }
        }
    },
    "asset_governance": {
        "finding_title": "Asset Inventory & Classification Governance",
        "mapping_basis": "Identifies high-criticality enterprise assets requiring continuous inventory tracking and asset ownership.",
        "mappings": {
            "NIST_CSF": {
                "function": "IDENTIFY",
                "category": "ID.AM (Asset Management)",
                "control_id": "ID.AM-01",
                "control_name": "Inventory of Physical and Software Assets"
            },
            "ISO_27001": {
                "category": "Organizational Controls",
                "control_id": "A.5.9",
                "control_name": "Inventory of information and other associated assets"
            },
            "CIS_CONTROLS": {
                "category": "Asset Inventory Management",
                "control_id": "Control 1",
                "control_name": "Inventory and Control of Enterprise Assets"
            }
        }
    }
}


def determine_priority(risk_score: float) -> str:
    """
    Derive priority strictly from existing Phase 4 asset risk score.
    CRITICAL: > 75
    HIGH: > 50
    MEDIUM: > 25
    LOW: <= 25
    """
    if risk_score > 75.0:
        return "CRITICAL"
    elif risk_score > 50.0:
        return "HIGH"
    elif risk_score > 25.0:
        return "MEDIUM"
    else:
        return "LOW"


def determine_status(has_active_controls: bool, control_effectiveness: float, has_high_exposure: bool, has_evidence: bool = True) -> str:
    """
    Determine deterministic status based on CRISE evidence:
    - ADDRESSED: Active control exists with high effectiveness (>=0.7) and no high exposure.
    - PARTIALLY_ADDRESSED: Active control exists but partial effectiveness (<0.7) or exposure remains.
    - GAP: Control inactive/missing and high exposure present.
    - NOT_ASSESSED: Insufficient evidence.
    """
    if not has_evidence:
        return "NOT_ASSESSED"
    if has_active_controls and control_effectiveness >= 0.7 and not has_high_exposure:
        return "ADDRESSED"
    elif has_active_controls:
        return "PARTIALLY_ADDRESSED"
    elif has_high_exposure:
        return "GAP"
    else:
        return "NOT_ASSESSED"


def calculate_coverage(addressed: int, partially_addressed: int, gap: int) -> float:
    """
    Calculate CRISE Modeled Coverage Percentage:
    (addressed + 0.5 * partially_addressed) / (total_assessed_items) * 100
    Note: NOT_ASSESSED items are excluded from denominator. Returns 0.0 if total_assessed == 0.
    """
    total_assessed = addressed + partially_addressed + gap
    if total_assessed == 0:
        return 0.0
    raw_coverage = ((addressed + (0.5 * partially_addressed)) / total_assessed) * 100.0
    return round(raw_coverage, 2)


def _get_control_status(c: Dict[str, Any]) -> str:
    """Helper to safely extract control status."""
    st = c.get("implementation_status") or c.get("status") or ""
    return str(st).strip().lower()


def extract_findings_from_crise(processed_data: Dict[str, Any], risk_results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Extract compliance findings directly from processed CRISE dataset without creating new risk scores.
    """
    assets = processed_data.get("assets", [])
    vulnerabilities = processed_data.get("vulnerabilities", [])
    controls = processed_data.get("controls", [])
    incidents = processed_data.get("incidents", [])

    # Map risk scores per asset if risk_results available
    asset_risk_lookup = {}
    if risk_results and "asset_risks" in risk_results:
        for ar in risk_results["asset_risks"]:
            aid = ar.get("asset_id")
            score = ar.get("risk_score", 0.0)
            if aid:
                asset_risk_lookup[aid] = float(score)

    findings = []

    for asset_entry in assets:
        aid = asset_entry.get("asset_id")
        a_info = asset_entry.get("asset", {})
        aname = a_info.get("asset_name") or asset_entry.get("asset_name", aid)
        is_exposed = bool(a_info.get("internet_exposed") if "internet_exposed" in a_info else asset_entry.get("internet_exposed", False))
        crit = float(a_info.get("criticality") if "criticality" in a_info else asset_entry.get("criticality", 0.0))
        bval = float(a_info.get("business_value") if "business_value" in a_info else asset_entry.get("business_value", 0.0))

        a_vulns = asset_entry.get("vulnerabilities", [])
        a_controls = asset_entry.get("controls", [])
        a_incidents = asset_entry.get("incidents", [])
        risk_score = asset_risk_lookup.get(aid, 0.0)

        active_controls = [c for c in a_controls if _get_control_status(c) == "active"]
        inactive_controls = [c for c in a_controls if _get_control_status(c) in ["inactive", "planned"]]

        # 1. Vulnerability Risk Management Findings
        if a_vulns:
            high_vulns = [v for v in a_vulns if float(v.get("severity", 0.0)) >= 7.0]
            has_active = len(active_controls) > 0
            max_eff = max([float(c.get("effectiveness", 0.0)) for c in active_controls], default=0.0)
            has_exposure = len(high_vulns) > 0 or not has_active

            evidence = [
                f"Asset {aid} ({aname}) has {len(a_vulns)} vulnerability record(s).",
                f"{len(high_vulns)} vulnerability record(s) have high/critical severity (>=7.0).",
                f"{len(active_controls)} active security control(s) deployed (Max effectiveness: {max_eff:.2f}).",
                f"Current asset modeled risk score is {risk_score:.1f}."
            ]

            status = determine_status(has_active, max_eff, has_exposure, True)
            priority = determine_priority(risk_score)
            rec_action = (
                f"Implement active vulnerability patching and remediation for asset {aid}."
                if status in ["GAP", "PARTIALLY_ADDRESSED"] else
                f"Maintain existing vulnerability monitoring on asset {aid}."
            )

            findings.append({
                "finding_id": f"CF-VULN-{aid}",
                "category": "vulnerability_management",
                "title": f"Vulnerability Management Exposure ({aid})",
                "affected_asset_id": aid,
                "asset_name": aname,
                "risk_score": risk_score,
                "priority": priority,
                "status": status,
                "evidence": evidence,
                "recommended_action": rec_action
            })

        # 2. Security Control Coverage Gap Findings
        if inactive_controls:
            max_active_eff = max([float(c.get("effectiveness", 0.0)) for c in active_controls], default=0.0)
            has_high_exposure = risk_score > 50.0 or len(active_controls) == 0

            evidence = [
                f"Asset {aid} has {len(inactive_controls)} inactive/planned security control(s): {', '.join([c.get('control_name', c.get('control_id')) for c in inactive_controls])}.",
                f"{len(active_controls)} active security control(s) currently operational.",
                f"Current asset modeled risk score is {risk_score:.1f}."
            ]

            status = determine_status(len(active_controls) > 0, max_active_eff, has_high_exposure, True)
            priority = determine_priority(risk_score)
            rec_action = f"Activate planned security controls on asset {aid} to close protection gaps."

            findings.append({
                "finding_id": f"CF-CTRL-{aid}",
                "category": "control_gap",
                "title": f"Inactive/Planned Control Gap ({aid})",
                "affected_asset_id": aid,
                "asset_name": aname,
                "risk_score": risk_score,
                "priority": priority,
                "status": status,
                "evidence": evidence,
                "recommended_action": rec_action
            })

        # 3. External Network Exposure Findings
        if is_exposed:
            max_eff = max([float(c.get("effectiveness", 0.0)) for c in active_controls], default=0.0)
            has_exposure = risk_score > 25.0 or max_eff < 0.7

            evidence = [
                f"Asset {aid} ({aname}) is directly exposed to the public internet.",
                f"{len(active_controls)} active security control(s) assigned to protect perimeter.",
                f"Current asset modeled risk score is {risk_score:.1f}."
            ]

            status = determine_status(len(active_controls) > 0, max_eff, has_exposure, True)
            priority = determine_priority(risk_score)
            rec_action = f"Enforce perimeter firewall rules, MFA, and access filtering on internet-exposed asset {aid}."

            findings.append({
                "finding_id": f"CF-NET-{aid}",
                "category": "internet_exposure",
                "title": f"Internet Perimeter Exposure ({aid})",
                "affected_asset_id": aid,
                "asset_name": aname,
                "risk_score": risk_score,
                "priority": priority,
                "status": status,
                "evidence": evidence,
                "recommended_action": rec_action
            })

        # 4. Incident Response & History Findings
        if a_incidents:
            total_loss = sum([float(i.get("average_loss", i.get("financial_impact", 0.0))) for i in a_incidents])
            evidence = [
                f"Asset {aid} has {len(a_incidents)} historical security incident record(s).",
                f"Cumulative recorded financial impact from incidents: ₹{total_loss:,.2f}.",
                f"Current asset modeled risk score is {risk_score:.1f}."
            ]

            has_active = len(active_controls) > 0
            max_eff = max([float(c.get("effectiveness", 0.0)) for c in active_controls], default=0.0)

            status = determine_status(has_active, max_eff, True, True)
            priority = determine_priority(risk_score)
            rec_action = f"Review incident lessons learned and verify incident response readiness for asset {aid}."

            findings.append({
                "finding_id": f"CF-INC-{aid}",
                "category": "incident_response",
                "title": f"Historical Incident Exposure ({aid})",
                "affected_asset_id": aid,
                "asset_name": aname,
                "risk_score": risk_score,
                "priority": priority,
                "status": status,
                "evidence": evidence,
                "recommended_action": rec_action
            })

        # 5. Asset Governance Findings (High criticality assets)
        if crit >= 8.0 or bval >= 1000000:
            evidence = [
                f"Asset {aid} is classified as high criticality ({crit:.1f}/10) or high business value.",
                f"Current asset modeled risk score is {risk_score:.1f}."
            ]
            has_active = len(active_controls) > 0
            max_eff = max([float(c.get("effectiveness", 0.0)) for c in active_controls], default=0.0)

            status = determine_status(has_active, max_eff, risk_score > 50.0, True)
            priority = determine_priority(risk_score)
            rec_action = f"Maintain continuous asset inventory tracking and governance for high-value asset {aid}."

            findings.append({
                "finding_id": f"CF-GOV-{aid}",
                "category": "asset_governance",
                "title": f"Critical Asset Governance ({aid})",
                "affected_asset_id": aid,
                "asset_name": aname,
                "risk_score": risk_score,
                "priority": priority,
                "status": status,
                "evidence": evidence,
                "recommended_action": rec_action
            })

    return findings


def build_compliance_assessment(processed_data: Dict[str, Any], risk_results: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    """
    Master compliance assessment entry point.
    Builds framework-specific aggregations, gaps list, crosswalk items, and enterprise summary.
    """
    # Extract base findings
    findings = extract_findings_from_crise(processed_data, risk_results)

    # If dataset has zero assets or zero findings, return clean empty state
    if not findings:
        return {
            "status": "success",
            "message": "No compliance-relevant findings detected in dataset.",
            "summary": {
                "framework_count": 3,
                "total_findings": 0,
                "total_gaps": 0,
                "highest_priority_gaps": [],
                "disclaimer": "CRISE modeled coverage is an internal analytical indicator and is not a legal, regulatory, audit, certification, or conformity assessment."
            },
            "frameworks": [
                {
                    "framework_id": fw_key,
                    "framework": fw_info["framework"],
                    "framework_version": fw_info["version"],
                    "total_items": 0,
                    "addressed": 0,
                    "partially_addressed": 0,
                    "gaps": 0,
                    "not_assessed": 0,
                    "modeled_coverage_percentage": 0.0
                } for fw_key, fw_info in FRAMEWORK_METADATA.items()
            ],
            "findings": [],
            "gaps": [],
            "crosswalk": []
        }

    # Map findings into framework items
    framework_items = {
        "NIST_CSF": [],
        "ISO_27001": [],
        "CIS_CONTROLS": []
    }

    crosswalk_list = []

    for f in findings:
        cat_key = f["category"]
        cat_meta = COMPLIANCE_MAPPING.get(cat_key, {})
        mappings = cat_meta.get("mappings", {})

        cw_entry = {
            "finding_id": f["finding_id"],
            "finding_title": f["title"],
            "affected_asset_id": f["affected_asset_id"],
            "risk_score": f["risk_score"],
            "priority": f["priority"],
            "status": f["status"],
            "evidence": f["evidence"],
            "recommended_action": f["recommended_action"],
            "mappings": {}
        }

        for fw_key in ["NIST_CSF", "ISO_27001", "CIS_CONTROLS"]:
            fw_map = mappings.get(fw_key, {})
            fw_info = FRAMEWORK_METADATA[fw_key]

            item = {
                "item_id": f"{f['finding_id']}-{fw_key}",
                "finding_id": f["finding_id"],
                "framework_id": fw_key,
                "framework": fw_info["framework"],
                "framework_version": fw_info["version"],
                "category": f["category"],
                "title": f["title"],
                "framework_function_or_category": fw_map.get("function") or fw_map.get("category", "General Security"),
                "control_id": fw_map.get("control_id", "N/A"),
                "control_name": fw_map.get("control_name", "Security Control"),
                "mapping_basis": cat_meta.get("mapping_basis", ""),
                "status": f["status"],
                "priority": f["priority"],
                "affected_asset_id": f["affected_asset_id"],
                "asset_name": f["asset_name"],
                "risk_score": f["risk_score"],
                "evidence": f["evidence"],
                "recommended_action": f["recommended_action"]
            }

            framework_items[fw_key].append(item)
            cw_entry["mappings"][fw_key] = {
                "framework": fw_info["framework"],
                "control_id": fw_map.get("control_id"),
                "control_name": fw_map.get("control_name")
            }

        crosswalk_list.append(cw_entry)

    # Build Framework Aggregations
    framework_summaries = []
    all_gaps = []

    for fw_key, fw_info in FRAMEWORK_METADATA.items():
        items = framework_items[fw_key]
        total_items = len(items)
        addressed = sum(1 for i in items if i["status"] == "ADDRESSED")
        partially = sum(1 for i in items if i["status"] == "PARTIALLY_ADDRESSED")
        gaps = sum(1 for i in items if i["status"] == "GAP")
        not_assessed = sum(1 for i in items if i["status"] == "NOT_ASSESSED")

        cov_pct = calculate_coverage(addressed, partially, gaps)

        framework_summaries.append({
            "framework_id": fw_key,
            "framework": fw_info["framework"],
            "framework_version": fw_info["version"],
            "total_items": total_items,
            "addressed": addressed,
            "partially_addressed": partially,
            "gaps": gaps,
            "not_assessed": not_assessed,
            "modeled_coverage_percentage": cov_pct
        })

    # Collect gaps across all frameworks
    for fw_key in ["NIST_CSF", "ISO_27001", "CIS_CONTROLS"]:
        for i in framework_items[fw_key]:
            if i["status"] in ["GAP", "PARTIALLY_ADDRESSED"]:
                all_gaps.append(i)

    # Sort gaps by risk_score descending
    priority_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    all_gaps.sort(key=lambda x: (priority_order.get(x["priority"], 0), x["risk_score"]), reverse=True)

    highest_priority_gaps = [
        {
            "finding_id": g["finding_id"],
            "framework": g["framework"],
            "control_id": g["control_id"],
            "control_name": g["control_name"],
            "priority": g["priority"],
            "status": g["status"],
            "affected_asset_id": g["affected_asset_id"],
            "risk_score": g["risk_score"],
            "recommended_action": g["recommended_action"]
        } for g in all_gaps[:10]
    ]

    total_gaps_count = len([f for f in findings if f["status"] == "GAP"])

    return {
        "status": "success",
        "summary": {
            "framework_count": 3,
            "total_findings": len(findings),
            "total_gaps": total_gaps_count,
            "highest_priority_gaps": highest_priority_gaps,
            "disclaimer": "CRISE modeled coverage is an internal analytical indicator and is not a legal, regulatory, audit, certification, or conformity assessment."
        },
        "frameworks": framework_summaries,
        "findings": findings,
        "gaps": all_gaps,
        "crosswalk": crosswalk_list
    }
