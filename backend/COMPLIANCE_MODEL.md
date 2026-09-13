# CRISE Phase 14 — Compliance & Security Framework Mapping Model Reference

## 1. Purpose & Core Principles

The CRISE **Compliance & Security Framework Mapping Engine** translates quantitative risk, vulnerability, security control, and incident findings into standardized security framework control categories.

> [!IMPORTANT]
> **SIH Judging Disclaimer & Legal Non-Claim**:
> - **Modeled Coverage**: All percentage scores represent internal analytical indicators (*CRISE Modeled Coverage*) based on available platform evidence.
> - **No Legal Certification**: The engine does NOT claim legal compliance, regulatory compliance, ISO certification, or formal audit conformity.
> - **Deterministic & Evidence-Based**: Mappings use standard framework categories without using probabilistic models, machine learning, or speculative control scores.

---

## 2. Supported Frameworks & Versions

CRISE maps findings across three authoritative cybersecurity frameworks:

1. **NIST Cybersecurity Framework (CSF 2.0)**:
   - **Version**: 2.0 (2024 Release)
   - **Structure**: Functions (`GOVERN`, `IDENTIFY`, `PROTECT`, `DETECT`, `RESPOND`, `RECOVER`), Categories (`ID.AM`, `ID.RA`, `PR.AA`, `PR.DS`, `PR.PS`, `DE.AE`, `RS.MA`, `RC.RP`).
2. **ISO/IEC 27001:2022 (Annex A)**:
   - **Version**: 2022 Edition
   - **Control Areas**: Organizational & Technological Controls (`A.5.9` Asset Inventory, `A.5.15` Access Control, `A.5.24` Incident Management, `A.8.8` Technical Vulnerability Management, `A.8.9` Configuration Management, `A.8.20` Network Security).
3. **CIS Critical Security Controls**:
   - **Version**: v8 (2021 Release)
   - **Controls**: `Control 1` (Asset Inventory), `Control 4` (Secure Configuration), `Control 6` (Access Control Management), `Control 7` (Vulnerability Management), `Control 12` (Network Infrastructure Management), `Control 17` (Incident Response Management).

---

## 3. Finding Categories & Mapping Catalog

| CRISE Finding Category | NIST CSF 2.0 Category | ISO 27001:2022 Control | CIS Controls v8 |
|------------------------|-----------------------|-------------------------|-----------------|
| **Vulnerability Management** | `ID.RA` / `PR.PS` (Risk Assessment & Platform Security) | `A.8.8` (Technical Vulnerabilities) | `Control 7` (Vulnerability Management) |
| **Control Gap** | `PR.AA` / `PR.PS` (Access & Protection Technology) | `A.5.15` / `A.8.9` (Access & Configuration) | `Control 4` / `Control 6` (Secure Config & Access Control) |
| **Internet Exposure** | `PR.IR` / `PR.AA` (Network & Boundary Protection) | `A.8.20` / `A.8.21` (Network Security) | `Control 12` (Network Infrastructure) |
| **Incident Response** | `DE.AE` / `RS.MA` (Adverse Event & Incident Response) | `A.5.24` (Incident Management Planning) | `Control 17` (Incident Response) |
| **Asset Governance** | `ID.AM` (Asset Management) | `A.5.9` (Inventory of Assets) | `Control 1` (Asset Inventory) |

---

## 4. Status & Evidence Model

### Status Definitions:
- **`ADDRESSED`**: Active, highly effective controls ($\ge 0.7$) are deployed with no unmitigated critical exposure.
- **`PARTIALLY_ADDRESSED`**: Active control coverage exists, but effectiveness is limited ($< 0.7$) or residual vulnerability exposure remains.
- **`GAP`**: Security controls are inactive, planned, or missing, and significant risk or vulnerability exposure exists.
- **`NOT_ASSESSED`**: Insufficient dataset evidence is available to determine coverage status.

### Traceable Evidence Array:
Every framework item contains a non-empty `evidence` list directly referencing CRISE asset IDs, vulnerability severities, active/inactive control names, incident financial impacts, and Phase 4 risk scores.

---

## 5. Priority Derivation

Priority is mapped deterministically from the asset's Phase 4 modeled risk score:
- **`CRITICAL`**: Asset Risk Score $> 75.0$
- **`HIGH`**: Asset Risk Score $> 50.0$
- **`MEDIUM`**: Asset Risk Score $> 25.0$
- **`LOW`**: Asset Risk Score $\le 25.0$

---

## 6. CRISE Modeled Coverage Formula

For each framework, Modeled Coverage Percentage is computed as:

$$\text{CRISE Modeled Coverage \%} = \frac{\text{addressed\_items} + 0.5 \times \text{partially\_addressed\_items}}{\text{addressed\_items} + \text{partially\_addressed\_items} + \text{gap\_items}} \times 100$$

*Note: Items with `NOT_ASSESSED` status are excluded from the denominator. If assessable items equal zero, coverage returns `0.0%`.*
