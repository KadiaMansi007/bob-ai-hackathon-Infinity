# Problem Statement

## Background

Modern cyber-physical organisations — defence agencies, critical infrastructure operators, financial institutions, and large enterprises — rely on Security Operations Centres (SOCs) to maintain situational awareness across networks, sensors, and intelligence channels. These environments generate threat intelligence from multiple heterogeneous sources simultaneously: Security Information and Event Management (SIEM) platforms, cyber intrusion detection sensors, satellite telemetry feeds, and human-produced intelligence reports. Each source uses a different schema, severity scale, confidence rating, and vocabulary.

The D2 problem domain — Threat Intelligence Correlation & Alert Prioritisation — sits at the intersection of information overload and decision urgency. Analysts must determine, in near-real-time, whether a collection of signals constitutes a coordinated attack or a cluster of coincidental noise.

---

## The Problem

A mid-to-large SOC receives between 500 and 10,000 raw alerts per day across its monitoring systems. Studies indicate that between 45% and 70% of all alerts are false positives — either benign system behaviour misclassified by detection rules, or duplicated signals from overlapping sensors covering the same event.

The core problem is threefold:

1. **Volume and fragmentation:** Alerts arrive across at minimum four distinct feed types (SIEM events, cyber sensor alerts, satellite anomaly reports, and intelligence advisories), each with its own data model. No single tool normalises and correlates them in real time.

2. **Lack of correlated context:** Individual alerts are evaluated in isolation. A low-severity SIEM event, a satellite anomaly over the same geographic region, and an intelligence report mentioning the same threat actor are each weak signals alone. Together they constitute strong evidence of a coordinated intrusion — but a human analyst must manually assemble that correlation, which takes 30–90 minutes per incident.

3. **Alert fatigue and triage delay:** Analysts faced with hundreds of uncorrelated, unranked alerts per shift adopt a defensive posture: they raise thresholds, dismiss borderline signals, and defer review of medium-priority items. In doing so, genuine multi-vector threats are regularly downgraded or missed entirely. IBM's own research suggests that the median time-to-detect for sophisticated intrusions where alert correlation is manual exceeds four hours.

---

## Analyst Persona

**Primary user: Tier-2 SOC Analyst**

A Tier-2 analyst is responsible for reviewing incidents escalated by automated detectors or Tier-1 staff, determining whether they represent genuine threats, and deciding whether to escalate to incident response. They typically manage 20–40 open incident reviews per shift, across 3–6 monitoring tools with no unified view.

Pain points:
- Switching between 4+ tools to assemble a picture of a single suspected incident
- No explanation of *why* an alert was scored the way it was — just a number
- No indication of which MITRE ATT&CK technique is suspected, so escalation context is thin
- Alerts that fire repeatedly for the same underlying event create the illusion of high volume without increasing real signal
- When AI-based tools do classify an alert, no justification is provided, making it impossible to challenge or learn from the decision

**Secondary user: SOC Manager / Incident Commander**

A SOC manager needs concise BLUF (Bottom Line Up Front) summaries to brief leadership when incidents are escalating. They have no time to read raw alert streams and need a single structured paragraph per incident.

---

## Why It Matters

**Operational risk:** A missed GENUINE_THREAT that results in a successful intrusion can cost an organisation between $4M and $9M per incident (IBM Cost of a Data Breach Report, 2024 baseline). For critical infrastructure operators, the cost is potentially lives and service continuity.

**Analyst burnout:** Alert fatigue is cited as the leading cause of SOC analyst attrition. Analysts who spend most of their shift triaging noise cannot invest time in high-value threat hunting. Staff turnover compounds the problem.

**Compliance exposure:** Regulated industries (financial services, healthcare, defence) face regulatory penalties when incidents that were detectable are not identified within mandated timeframes. A 30–90 minute manual triage cycle regularly exceeds those windows.

**False positive cost:** Each false positive that an analyst investigates consumes approximately 15–20 minutes of skilled analyst time. At 200 false positives per day, that is 50–67 analyst-hours per day spent on noise.

---

## Why Existing SIEM Tools Are Insufficient

Current SIEM platforms (Splunk, IBM QRadar, Microsoft Sentinel) were designed to aggregate and search log data. They have rule-based alerting but significant limitations in the D2 context:

| Limitation | Detail |
|---|---|
| **Single-source view** | SIEM tools ingest one or a few log sources well but do not natively join satellite feeds, human intelligence reports, and sensor data under a unified model |
| **Threshold-only prioritisation** | Priorities are set by static rule thresholds. There is no dynamic risk scoring that accounts for recency, source reliability, or cross-source convergence |
| **No correlated narrative** | SIEMs show individual matched rules but do not construct a natural-language explanation of why a collection of alerts represents an attack pattern |
| **No MITRE alignment at alert level** | While some SIEMs have MITRE mappings, they are not applied at correlation time with confidence scores and technique-level specificity |
| **AI is opaque** | When SIEMs use ML-based anomaly detection, the output is a score with no human-readable justification, making analyst review and override impossible to ground in evidence |
| **No false-positive/genuine-threat classification** | SIEMs escalate alerts; they do not produce a first-class GENUINE_THREAT vs FALSE_POSITIVE verdict with a stated reason that persists in the record |

The Infinity platform addresses all of these gaps through a purpose-built pipeline architecture augmented by IBM Bob as an evidence-grounded AI reasoning layer.
