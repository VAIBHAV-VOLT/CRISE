# Monte Carlo / Uncertainty Risk Simulation Model (Phase 12)

## Overview
The Phase 12 Monte Carlo service adds a **probabilistic input uncertainty layer** over the Phase 4 deterministic Cyber Risk Engine.

> [!IMPORTANT]
> **DISCLAIMER & PURPOSE**:
> Monte Carlo simulation results represent **parameter uncertainty** within continuous modeled risk inputs.
> They MUST NOT be interpreted as real-world probabilities of a cyberattack occurring (e.g. "70% chance of breach").
> The Phase 4 deterministic risk engine remains the single mathematical source of truth for baseline enterprise risk.

---

## 1. Uncertainty Model

Uncertainty is modeled **only** around continuous numerical inputs existing in user-supplied CSV datasets.

Bounded triangular distributions are constructed around each baseline value $x$:
$$\text{low} = x \times 0.90, \quad \text{mode} = x, \quad \text{high} = x \times 1.10$$

This represents a $\pm 10\%$ input parameter uncertainty band.

### Domain Constraints & Sampling Bounds

| Input Attribute | Domain | Sampling Distribution | Clamping Bounds |
| :--- | :--- | :--- | :--- |
| **Vulnerability Severity** | $[0.0, 10.0]$ | Bounded Triangular ($\pm 10\%$) | $[0.0, 10.0]$ |
| **Vulnerability Exploitability** | $[0.0, 1.0]$ | Bounded Triangular ($\pm 10\%$) | $[0.0, 1.0]$ |
| **Control Effectiveness** | $[0.0, 1.0]$ | Bounded Triangular ($\pm 10\%$) | $[0.0, 1.0]$ |
| **Asset Criticality** | $[0.0, 5.0]$ | Bounded Triangular ($\pm 10\%$) | $[0.0, 5.0]$ |
| **Data Sensitivity** | $[0.0, 5.0]$ | Bounded Triangular ($\pm 10\%$) | $[0.0, 5.0]$ |

### Fixed (Unmodified) Attributes
Categorical and discrete attributes are **NEVER** randomly varied or sampled:
- Asset IDs, vulnerability IDs, control IDs, incident IDs
- Relationships and asset mapping
- `internet_exposed` (categorical boolean)
- Business values ($\text{₹}$)
- Control annual costs ($\text{₹}$)
- Historical incident frequencies and losses

---

## 2. Risk Calculation Reuse

For each sampled iteration $i \in \{1, \dots, N\}$:

1. **Vulnerability Exposure**:
   $$\text{vulnerability\_exposure}_{i} = \text{clamp}\left(\frac{\text{severity}_{i}}{10.0} \times \text{exploitability}_{i},\; 0.0,\; 1.0\right)$$
   $$\text{combined\_vulnerability\_exposure}_{i} = 1 - \prod \big(1 - \text{vulnerability\_exposure}_{i}\big)$$

2. **Control Effectiveness**:
   $$\text{combined\_control\_effectiveness}_{i} = 1 - \prod \big(1 - \text{effectiveness}_{i}\big) \quad \text{(Active controls only)}$$
   $$\text{remaining\_exposure}_{i} = 1 - \text{combined\_control\_effectiveness}_{i}$$

3. **Base Exposure**:
   $$\text{base\_exposure}_{i} = 0.50 \times \text{combined\_vulnerability\_exposure}_{i} + 0.20 \times \frac{\text{criticality}_{i}}{5.0} + 0.15 \times \frac{\text{data\_sensitivity}_{i}}{5.0} + 0.15 \times \text{internet\_factor}$$

4. **Asset Risk Score**:
   $$\text{risk\_score}_{i} = \text{clamp}\big(\text{base\_exposure}_{i} \times \text{remaining\_exposure}_{i} \times 100.0,\; 0.0,\; 100.0\big)$$

5. **Enterprise Risk Aggregation**:
   $$\text{enterprise\_risk}_{i} = \frac{\sum_{a} \big(\text{risk\_score}_{i, a} \times \text{business\_value}_{a}\big)}{\sum_{a} \text{business\_value}_{a}}$$
   *(Uses arithmetic average if total business value $= 0$)*.

---

## 3. Statistical Analysis & Metrics

The vector of $N$ simulated scores yields:
- **`mean`**: $\frac{1}{N} \sum S_i$
- **`median`**: 50th percentile ($P_{50}$)
- **`std_dev`**: Standard deviation
- **`min` / `max`**: Minimum and maximum simulated scores
- **`p5` / `p25` / `p75` / `p95`**: Actual simulated percentiles

### Risk Level Distribution
Simulated scores are categorized into standard Phase 4 thresholds:
- **`LOW`**: $0.0 \le S \le 25.0$
- **`MEDIUM`**: $25.0 < S \le 50.0$
- **`HIGH`**: $50.0 < S \le 75.0$
- **`CRITICAL`**: $75.0 < S \le 100.0$

Counts and percentages ($\frac{\text{count}}{N} \times 100\%$) are provided for all four levels.

### Uncertainty Band Classification
Defined deterministically from the 90% confidence interval range ($P_{95} - P_{5}$):
- **`LOW`**: $P_{95} - P_{5} < 10.0$
- **`MODERATE`**: $10.0 \le P_{95} - P_{5} < 25.0$
- **`HIGH`**: $P_{95} - P_{5} \ge 25.0$

---

## 4. Reproducibility & API Usage

Endpoint: `POST /api/monte-carlo`

- **Parameters**:
  - `iterations`: Integer ($100 \le N \le 20000$, default $5000$).
  - `seed`: Integer for pseudo-random generator (default $42$).
  - `asset_id`: Optional string to simulate single asset.

Providing the same CSV files, `seed`, and `iterations` guarantees **identical** outputs.

### Example API Output (Enterprise Scope)

```json
{
  "scope": "enterprise",
  "iterations": 5000,
  "seed": 42,
  "baseline": {
    "risk_score": 24.37,
    "risk_level": "LOW"
  },
  "simulation": {
    "mean": 24.81,
    "median": 24.81,
    "std_dev": 2.1,
    "min": 18.2,
    "max": 32.4,
    "p5": 20.1,
    "p25": 23.0,
    "p75": 26.5,
    "p95": 29.75
  },
  "risk_level_distribution": {
    "LOW": { "count": 4210, "percentage": 84.2 },
    "MEDIUM": { "count": 790, "percentage": 15.8 },
    "HIGH": { "count": 0, "percentage": 0.0 },
    "CRITICAL": { "count": 0, "percentage": 0.0 }
  },
  "uncertainty_band": "LOW",
  "explanation": "The baseline enterprise risk is 24.37 (LOW). Under the modeled ±10% uncertainty in continuous risk inputs, the median simulated risk is 24.81 and the 5th–95th percentile range is 20.10–29.75. This indicates low variation around the baseline rather than a prediction of attack probability."
}
```
