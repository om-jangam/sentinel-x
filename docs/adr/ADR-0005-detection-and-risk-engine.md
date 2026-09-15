# ADR-0005 · Sigma detection + owned correlation/risk engine

**Status:** Accepted · **Date:** 2026-07

## Context

Two decisions bundle here because they're intertwined: *how we express detections* and *how we alert
without drowning analysts*. The market data is stark — ~2,992 alerts/day with 63% unaddressed, 46%
false positives. Sigma is the de-facto detection lingua franca, but its v2 correlation spec has
**patchy backend support** (many targets can't express temporal correlation). Splunk RBA,
SentinelOne Storyline, and XSIAM stitching all show the winning answer to alert fatigue is
*aggregation/risk accumulation*, not per-signal alerting.

## Decision

1. **Detection-as-code with Sigma**: SigmaHQ corpus + custom rules, compiled via **pySigma** to
   OpenSearch, with a draft→test→promote lifecycle; augmented by OpenSearch Security Analytics
   (2,200+ rules) and scoped RCF anomaly detectors.
2. **Own the correlation engine**: temporal/multi-event correlation runs in-platform over normalised
   OCSF events (not via Sigma backends).
3. **Risk-Based Alerting as the primary alerting model**: detections/correlations contribute *scored
   risk* to entities; risk decays over time; **incidents open only when accumulated risk crosses a
   threshold.** Per-alert notifications become secondary.

## Alternatives considered

- **Rely on Sigma-correlation backends** — rejected: patchy/lossy; temporal logic must be reliable.
- **Per-alert notification (the brief's default)** — rejected: it *is* the alert-fatigue problem.
- **Black-box ML detection only** — rejected: opaque, untunable, un-auditable; loses the
  transparency buyers reward.

## Consequences

- Readable, versioned, MITRE-mapped detections analysts can tune.
- We maintain a correlation engine (scope kept narrow, unit-tested).
- Alert volume attacked at the source; risk-weight tuning becomes a first-class (eval-gated) concern.
