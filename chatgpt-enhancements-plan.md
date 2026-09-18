# ChatGPT Suggestions Infusion Plan (Full — All 21 Points)
## Status: [ ] pending

## Top-Level Overview

Infuse all actionable suggestions from the ChatGPT conversation (`gpt.txt/gpt`) into the existing Infinity website.
- **Zero structural changes** — no routing changes except adding one new `/commander` page
- All data comes from existing API responses — no new backend endpoints needed
- Changes are additive only — nothing existing is removed or replaced

---

## Sub-Task 1 — Sidebar & Header Identity Copy (Points 1, 4, 15, 17)
### Intent
Update the sidebar to clearly state who the user is and what Infinity does. Adds a one-line role label and a tagline beneath the logo.
### Expected Outcomes
- Sidebar shows: "Security Operations Centre" as role subtitle
- Sidebar tagline changes from "Powered by IBM Bob" to "Correlation · Prioritisation · BLUF"
- No layout changes
### Todo List
- [ ] In `Layout.tsx`, update the sidebar brand section: add "Security Operations Centre" under "Infinity Threat Platform"
- [ ] Change the bottom tagline to "Correlation · Prioritisation · BLUF"
### Relevant Context
- File: `src/frontend/src/components/Layout.tsx` lines 19–25 and 46–51
### Status: [ ] pending

---

## Sub-Task 2 — Dashboard "About Infinity" Panel (Points 5, 17, 18)
### Intent
Add a compact info banner at the bottom of the Dashboard that explains in one sentence WHY Infinity exists (the hospital analogy made simple), so judges/mentors see it immediately.
### Expected Outcomes
- A muted info card at the bottom of Dashboard reads:
  "Infinity sits between raw sensor alerts and the analyst. Like a doctor combining vital signs, it correlates events from SIEM, Cyber Sensors, Satellites and Intel Reports — filtering noise, scoring risk, mapping MITRE ATT&CK tactics, and generating a BLUF for every incident."
### Todo List
- [ ] In `Dashboard.tsx`, after the pipeline strip (Sub-Task 4), add an `<Card>` with this explanation text
### Relevant Context
- File: `src/frontend/src/pages/Dashboard.tsx`
### Status: [ ] pending

---

## Sub-Task 3 — "Signal vs Noise" Stats on Dashboard (Points 8, 10)
### Intent
Add two new stat tiles to the dashboard stats bar: "False Positives Filtered" and "Genuine Threats". Makes the "signal vs noise" concept visible at a glance.
### Expected Outcomes
- Stats bar shows 6 tiles instead of 4: add `False Positives` (value: `s.false_positive_count`) and `Genuine Threats` (value: `s.genuine_threat_count`)
- Colors: false_positive_count in emerald, genuine_threat_count in red
### Todo List
- [ ] In `Dashboard.tsx`, extend the stats array with two more tiles using existing `s.false_positive_count` and `s.genuine_threat_count`
### Relevant Context
- File: `src/frontend/src/pages/Dashboard.tsx` — `s` already has `false_positive_count` and `genuine_threat_count`
- Change `grid-cols-2 md:grid-cols-4` to `grid-cols-2 md:grid-cols-6` (or keep 4 and wrap — use `md:grid-cols-3 lg:grid-cols-6`)
### Status: [ ] pending

---

## Sub-Task 4 — Source Pipeline Strip on Dashboard (Point 14)
### Intent
Add a horizontal visual pipeline strip at the bottom of the Dashboard showing the full data flow the conversation describes.
### Expected Outcomes
- Strip shows: `SIEM` → `CYBER SENSOR` → `SATELLITE` → `INTEL` → `INFINITY` → `CORRELATION` → `FP FILTER` → `RISK SCORE` → `MITRE` → `IBM BOB` → `BLUF`
- Purely visual/static — no data needed
### Todo List
- [ ] In `Dashboard.tsx`, after Recent Incidents card, add the pipeline strip inline
### Relevant Context
- File: `src/frontend/src/pages/Dashboard.tsx`
### Status: [ ] pending

---

## Sub-Task 5 — Attack Sequence Timeline on Incident Detail (Point 6)
### Intent
Point 6 describes how 5 separate alerts (failed login → successful login → privilege escalation → lateral movement → data exfiltration) form ONE attack sequence. Add a chronological timeline of member alerts on the Incident Detail page showing them in time order with arrows between them — making the attack story visible.
### Expected Outcomes
- New card "Attack Sequence Timeline" on Incident Detail page
- Shows member alerts sorted by timestamp, each as a timeline node: time · alert_type · target_asset · severity
- Arrows (→) between nodes to show sequence
- Only shows when there are 2+ member alerts
### Todo List
- [ ] In `IncidentDetail.tsx`, after the Member Alerts card, add an "Attack Sequence Timeline" card
- [ ] Sort `inc.member_alerts` by timestamp, render as a horizontal/vertical timeline
### Relevant Context
- File: `src/frontend/src/pages/IncidentDetail.tsx`
- `inc.member_alerts[*].timestamp`, `alert_type`, `target_asset`, `severity` — all available
### Status: [ ] pending

---

## Sub-Task 6 — Analyst Workflow Steps on Incident Detail (Point 11)
### Intent
Point 11 describes the analyst's mental workflow: Is this real? → What caused it? → Are other alerts related? → Who/what is affected? → How serious? → What attacker behavior? → What to investigate? → Report findings. Show this as a progress tracker on Incident Detail, with steps checked off based on what the system has already done.
### Expected Outcomes
- New card "Analyst Workflow" on Incident Detail page
- 7 checklist steps, auto-checked based on incident state:
  - ✓ "Is this real?" — checked if `auto_classification !== 'UNCLASSIFIED'`
  - ✓ "What caused it?" — checked if `fired_correlation_rule` exists
  - ✓ "Are other alerts related?" — checked if `member_alerts.length > 1`
  - ✓ "Who/what is affected?" — checked if any `target_asset` present
  - ✓ "How serious is it?" — checked if `risk_score` exists
  - ✓ "What attacker behavior?" — checked if `mitre_summary.mappings.length > 0`
  - ✓ "What to investigate?" — checked if `bob_analysis` exists
  - ○ "Report findings (BLUF)" — links to BLUF page
### Todo List
- [ ] In `IncidentDetail.tsx`, add the Analyst Workflow card near the top (after the header, before Threat Classification)
- [ ] Build the 7-step checklist with auto-check logic from incident data
### Relevant Context
- File: `src/frontend/src/pages/IncidentDetail.tsx`
### Status: [ ] pending

---

## Sub-Task 7 — "Show Me Why" Panel on Incident Detail (Point 19)
### Intent
After Bob analysis, show a checklist panel explaining exactly WHY the incident was flagged.
### Expected Outcomes
- Card "WHY WE FLAGGED THIS INCIDENT" — only when `bob_analysis` exists
- Checklist: alert count, source types, MITRE tactic chain (with arrows), Bob confidence %
- Green ✓ for each signal present
### Todo List
- [ ] In `IncidentDetail.tsx`, after Threat Classification card, add the "Show Me Why" card (only when `ba` is not null)
- [ ] Build checklist from `member_alerts.length`, `source_types_involved`, `mitre_summary.mappings` tactic names, `ba.bob_confidence`
### Relevant Context
- File: `src/frontend/src/pages/IncidentDetail.tsx`
### Status: [ ] pending

---

## Sub-Task 8 — Investigation Checklist on Incident Detail (Point 20)
### Intent
After Risk Score, show an ordered list of "What should I investigate next?" steps derived from MITRE tactics and affected assets.
### Expected Outcomes
- Card "What Should I Investigate Next?" — only when `ba` is not null
- Numbered steps from MITRE tactic → investigation action mapping
- Disclaimer: "Suggestions generated by IBM Bob AI — analyst judgment required"
### Todo List
- [ ] In `IncidentDetail.tsx`, after Risk Score card, add Investigation Suggestions card
- [ ] Static tactic→step lookup: Credential Access, Privilege Escalation, Lateral Movement, Exfiltration, Persistence, Discovery, C2, Execution
### Relevant Context
- File: `src/frontend/src/pages/IncidentDetail.tsx`
### Status: [ ] pending

---

## Sub-Task 9 — Commander Dashboard Page (Points 12, 13)
### Intent
Points 12–13 explicitly recommend a separate Commander view showing only: HIGH PRIORITY INCIDENT, What happened, Why it matters, What is affected, Confidence, What needs attention. Add a new `/commander` route and nav link.
### Expected Outcomes
- New page `src/frontend/src/pages/CommanderDashboard.tsx`
- Shows only P1/CRITICAL incidents as large cards with: classification badge, BLUF line (if exists), risk score, affected assets count, Bob confidence
- "Commander View" nav link added to sidebar
- Each incident card links to the BLUF page (not the technical detail page)
- New route added to `App.tsx`
### Todo List
- [ ] Create `src/frontend/src/pages/CommanderDashboard.tsx` — fetches incidents filtered to CRITICAL severity, shows each as a command card
- [ ] Add route `/commander` in `App.tsx`
- [ ] Add "Commander View" nav item in `Layout.tsx`
### Relevant Context
- Files: `src/frontend/src/App.tsx`, `src/frontend/src/components/Layout.tsx`
- API: `getIncidents({ severity: 'CRITICAL', page_size: 20 })` — already exists
- API: `getBluf(id)` — already exists, use `bluf_line` field
### Status: [ ] pending

---

## Implementation Order
1. Sub-Task 1 (Sidebar copy) — Layout.tsx
2. Sub-Task 3 (Signal vs Noise stats) — Dashboard.tsx
3. Sub-Task 4 (Pipeline strip) — Dashboard.tsx
4. Sub-Task 2 (About panel) — Dashboard.tsx
5. Sub-Task 6 (Analyst Workflow steps) — IncidentDetail.tsx
6. Sub-Task 5 (Attack Timeline) — IncidentDetail.tsx
7. Sub-Task 7 (Show Me Why) — IncidentDetail.tsx
8. Sub-Task 8 (Investigation Checklist) — IncidentDetail.tsx
9. Sub-Task 9 (Commander Dashboard) — new page + App.tsx + Layout.tsx
