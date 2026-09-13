# MITRE ATT&CK Threat Mapping Model (Phase 13)

## Overview
The Phase 13 MITRE ATT&CK Threat Mapping service provides **deterministic, category-based mappings** connecting enterprise security incidents to the MITRE ATT&CK Enterprise framework.

> [!IMPORTANT]
> **SIH JUDGING DISCLAIMER**:
> MITRE mappings are **deterministic category-based associations** derived strictly from user-supplied incident types and Phase 4–6 risk results.
> They do **NOT** represent AI-inferred predictions or definitive forensic proof that a specific attacker technique was executed during an incident.
> Mapping confidence reflects **semantic category alignment**, not statistical probability.

---

## 1. Mapping Architecture & Data Flow

$$\text{incidents.csv} \longrightarrow \text{Phase 6 Threat Engine} \longrightarrow \text{Incident Category} \longrightarrow \text{MITRE Catalog} \longrightarrow \text{Tactics \& Techniques} \longrightarrow \text{Asset Risk Context}$$

The MITRE Threat Mapping layer acts strictly as an **intelligence enrichment layer**. It does NOT alter the Phase 4 deterministic risk score or Phase 5 financial loss formulas.

---

## 2. Mapping Catalog

The catalog is a versioned, transparent lookup dictionary (`MITRE_MAPPING`) matching incident types to actual MITRE ATT&CK Enterprise Tactic IDs (`TAxxxx`), Technique IDs (`Txxxx`), Tactic Names, Technique Names, Mapping Confidence, and Human-Readable Mapping Bases.

### Catalog Metadata
```json
{
  "framework": "MITRE ATT&CK Enterprise",
  "mapping_version": "1.0",
  "mapping_method": "deterministic_incident_category"
}
```

### Supported Mappings Table

| Incident Type | MITRE Tactic ID / Name | MITRE Technique ID / Name | Confidence | Mapping Basis |
| :--- | :--- | :--- | :---: | :--- |
| **`Ransomware`** | `TA0040` Impact | `T1486` Data Encrypted for Impact | `HIGH` | Directly involves data encryption for impact & extortion. |
| **`Phishing`** | `TA0001` Initial Access | `T1566` Phishing | `HIGH` | Direct correspondence to ATT&CK Initial Access Phishing. |
| **`Phishing Credential Harvester`** | `TA0001` Initial Access | `T1566` Phishing | `HIGH` | Direct correspondence to ATT&CK Initial Access Phishing. |
| **`Business Email Compromise`** | `TA0001` Initial Access | `T1566.002` Phishing: Spearphishing Link | `HIGH` | Uses targeted spearphishing messages to trick organization personnel. |
| **`Supply Chain Injection`** | `TA0001` Initial Access | `T1195` Supply Chain Compromise | `HIGH` | Direct correspondence to ATT&CK Initial Access Supply Chain Compromise. |
| **`API Abuse`** | `TA0001` Initial Access | `T1190` Exploit Public-Facing Application | `MEDIUM` | Targets exposed application API endpoints for unauthorized access. |
| **`Server Compromise`** | `TA0002` Execution | `T1059` Command and Scripting Interpreter | `MEDIUM` | Involves unauthorized command execution or remote scripting. |
| **`Privilege Escalation`** | `TA0004` Privilege Escalation | `T1068` Exploitation for Privilege Escalation | `HIGH` | Direct correspondence to ATT&CK Technique T1068. |
| **`Domain Admin Compromise`** | `TA0004` Privilege Escalation | `T1078` Valid Accounts | `HIGH` | Abuses elevated privileged domain accounts for administrative control. |
| **`Credential Theft`** | `TA0006` Credential Access | `T1003` OS Credential Dumping | `HIGH` | Indicates extraction or dumping of authentication credentials. |
| **`Account Takeover`** | `TA0006` Credential Access | `T1110` Brute Force | `MEDIUM` | Results from credential stuffing or brute force credential attacks. |
| **`Insider Misuse`** | `TA0008` Lateral Movement | `T1078.003` Valid Accounts: Local Accounts | `MEDIUM` | Involves internal account privileges being abused beyond authorization. |
| **`PII Scraping`** | `TA0009` Collection | `T1119` Automated Collection | `MEDIUM` | Automated harvesting of PII from database/web endpoints. |
| **`Source Code Leak`** | `TA0009` Collection | `T1213` Data from Information Repositories | `MEDIUM` | Unauthorized collection from code repositories or version control systems. |
| **`Data Exfiltration`** | `TA0010` Exfiltration | `T1048` Exfiltration Over Alternative Protocol | `HIGH` | Transfer of sensitive enterprise data outside network boundaries. |
| **`Data Breach`** | `TA0010` Exfiltration | `T1041` Exfiltration Over C2 Channel | `MEDIUM` | Unauthorized extraction of sensitive data from corporate systems. |
| **`Botnet Recruitment`** | `TA0011` Command and Control | `T1071` Application Layer Protocol | `MEDIUM` | Establishing C2 beaconing protocols on infected endpoints. |
| **`Defacement`** | `TA0040` Impact | `T1491` Defacement | `HIGH` | Direct correspondence to ATT&CK Impact technique T1491. |
| **`Backup Deletion Attack`** | `TA0040` Impact | `T1490` Inhibit System Recovery | `HIGH` | Direct correspondence to ATT&CK technique T1490. |
| **`Denial of Service` / `DDoS`** | `TA0040` Impact | `T1498` Network Denial of Service | `HIGH` | Direct correspondence to ATT&CK Impact technique T1498. |

---

## 3. Unmapped Incident Handling

If an `incident_type` has no defensible ATT&CK technique mapping (e.g. `Payment Fraud`, `Order Manipulation`), the engine **refuses to guess** or invent a technique:

```json
{
  "incident_id": "I006",
  "asset_id": "A006",
  "incident_type": "Payment Fraud",
  "mapping_status": "UNMAPPED",
  "mitre": [],
  "unmapped_reason": "No deterministic MITRE ATT&CK mapping is configured for this incident type."
}
```

### Enterprise Coverage Formula
$$\text{mapping\_coverage\_percentage} = \text{round}\left( \frac{\text{mapped\_incidents}}{\text{total\_incidents}} \times 100.0,\; 2 \right)$$

---

## 4. Technique & Tactic Aggregation

### Technique-Level Aggregation
Aggregates incident metrics for each unique technique:
- `incident_count`: Count of incidents mapped to this technique
- `affected_asset_count` & `affected_assets`: Unique asset IDs affected
- `affected_business_value`: Sum of business values of affected assets
- `historical_annualized_loss`: $\sum (\text{frequency\_per\_year} \times \text{average\_loss})$
- `total_downtime_hours`: Sum of downtime hours
- `highest_asset_risk_score` & `highest_asset_risk_level`: Peak Phase 4 risk score and corresponding level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) among affected assets.

### Tactic-Level Aggregation
Aggregates techniques under each ATT&CK tactic (e.g., `Initial Access`, `Impact`, `Exfiltration`):
- `technique_count`, `incident_count`, `affected_asset_count`, `historical_annualized_loss`, `total_downtime_hours`, `highest_asset_risk_score`.

---

## 5. API Response Schema

`POST /api/mitre` and top-level `"mitre"` object in `POST /api/analyze`:

```json
{
  "status": "success",
  "metadata": {
    "framework": "MITRE ATT&CK Enterprise",
    "mapping_version": "1.0",
    "mapping_method": "deterministic_incident_category"
  },
  "summary": {
    "total_incidents": 25,
    "mapped_incidents": 23,
    "unmapped_incidents": 2,
    "mapping_coverage_percentage": 92.0,
    "unique_tactics": 7,
    "unique_techniques": 15
  },
  "incidents": [...],
  "techniques": [...],
  "tactics": [...]
}
```
