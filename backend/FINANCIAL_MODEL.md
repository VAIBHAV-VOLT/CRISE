# CRISE Modeled Financial Risk — Model Specification

## 1. Overview and Purpose

The CRISE Financial Risk Engine translates cybersecurity exposures and empirical incident experience into transparent, explainable financial risk estimates for individual assets and the enterprise.

> [!IMPORTANT]
> **Model Disclaimer**
> Financial outputs are **modeled estimates** derived from user-supplied business value, incident history, and cybersecurity risk scores. They are **not** guaranteed losses, financial forecasts, actuarial valuations, or predictions of future incidents. The prototype avoids false precision and does not claim that an organization "will lose ₹X".

---

## 2. Core Conceptual Metrics

To provide defensible financial insight without over-promising mathematical precision, the model maintains a clear separation between **empirical historical loss** and **forward-looking modeled business exposure**:

1. **Historical Annualized Incident Loss**: The annualized empirical loss observed in historical incident records.
2. **Risk-Based Business Exposure**: The portion of asset business value associated with cybersecurity exposure.
3. **Modeled Expected Annual Loss (EAL)**: The primary forward-looking baseline anchored on empirical incident history.
4. **Weighted Annual Downtime**: Annualized operational disruption in hours derived from incident frequencies and downtimes.

---

## 3. Mathematical Formulation

### 3.1 Per-Incident Annualized Loss
For each incident $i$ assigned to an asset:
$$\text{annualized\_loss}_i = \text{frequency\_per\_year}_i \times \text{average\_loss}_i$$

Example:
- Frequency: $0.30$ events/year
- Average Loss: ₹5,000,000
- Annualized Loss: $0.30 \times 5,000,000 = \text{₹}1,500,000$

### 3.2 Asset Historical Annualized Loss
Sum of annualized losses across all incidents associated with the asset:
$$\text{historical\_annualized\_loss}_a = \sum_{i \in I_a} \text{annualized\_loss}_i$$

If an asset has no recorded incidents ($I_a = \emptyset$):
$$\text{historical\_annualized\_loss}_a = 0.0$$

### 3.3 Asset Operational Downtime
For each asset:
- **Total Historical Downtime**:
  $$\text{total\_historical\_downtime\_hours}_a = \sum_{i \in I_a} \text{downtime\_hours}_i$$
- **Weighted Annual Downtime**:
  $$\text{weighted\_annual\_downtime\_hours}_a = \sum_{i \in I_a} (\text{frequency\_per\_year}_i \times \text{downtime\_hours}_i)$$

### 3.4 Risk-Based Business Exposure
A forward-looking metric estimating how much business value is exposed to cybersecurity risk:
$$\text{risk\_factor}_a = \frac{\text{risk\_score}_a}{100.0}$$
$$\text{risk\_based\_business\_exposure}_a = \text{business\_value}_a \times \text{risk\_factor}_a$$

*Crucial Distinction*: This represents the gross business value exposed to cyber risk, **not** an expected dollar loss.

### 3.5 Modeled Expected Annual Loss (EAL)
To avoid treating the Phase 4 cybersecurity risk score as a literal attack probability, the prototype uses the empirical incident baseline as the primary expected annual loss:
$$\text{modeled\_eal}_a = \text{historical\_annualized\_loss}_a$$

The dashboard concurrently presents both:
- **Historical Annualized Loss**: ₹X (empirical baseline)
- **Risk-Based Business Exposure**: ₹Y (modeled value-at-risk)

---

## 4. Financial Risk Categorization

Financial metrics inherit the four cybersecurity risk levels from Phase 4 based on the asset's modeled risk score:
- **LOW** ($0.0 \le \text{Score} \le 25.0$)
- **MEDIUM** ($25.0 < \text{Score} \le 50.0$)
- **HIGH** ($50.0 < \text{Score} \le 75.0$)
- **CRITICAL** ($75.0 < \text{Score} \le 100.0$)

---

## 5. Enterprise Financial Aggregation

Enterprise metrics sum asset-level totals directly from verified data:
$$\text{total\_business\_value} = \sum_{a \in A} \text{business\_value}_a$$
$$\text{historical\_annualized\_loss} = \sum_{a \in A} \text{historical\_annualized\_loss}_a$$
$$\text{risk\_based\_business\_exposure} = \sum_{a \in A} \text{risk\_based\_business\_exposure}_a$$
$$\text{total\_incident\_count} = \sum_{a \in A} \text{incident\_count}_a$$
$$\text{total\_historical\_downtime\_hours} = \sum_{a \in A} \text{total\_historical\_downtime\_hours}_a$$
$$\text{total\_weighted\_annual\_downtime\_hours} = \sum_{a \in A} \text{weighted\_annual\_downtime\_hours}_a$$

### Exposure by Risk Level
Assets are grouped into the four risk levels (`critical`, `high`, `medium`, `low`), summing:
- `asset_count`
- `business_value`
- `historical_annualized_loss`
- `risk_based_business_exposure`

---

## 6. Zero-Incident Handling & Data Quality

When an asset has no recorded incidents:
- $\text{historical\_annualized\_loss} = 0.0$
- $\text{incident\_count} = 0$
- $\text{weighted\_annual\_downtime\_hours} = 0.0$
- $\text{historical\_data\_available} = \text{false}$
- $\text{financial\_data\_quality} = \text{"no\_historical\_incidents"}$

> [!NOTE]
> **Absence of Evidence is Not Evidence of Absence**
> The model does **not** state that "expected loss is zero". Instead, it explicitly states: *"Asset has no historical incidents in the supplied dataset, so historical annualized loss cannot be inferred from incident history."* Meanwhile, $\text{risk\_based\_business\_exposure}$ remains active based on the asset's business value and cyber exposure.

At the enterprise level:
- If incidents are present: `financial_data_quality = "historical incident data available"`
- If no incidents exist: `financial_data_quality = "no historical incident data available"`
