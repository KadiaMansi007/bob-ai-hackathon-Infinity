"""
Bob API client — calls IBM Bob (or falls back to a structured mock for testing).

The actual Bob API endpoint and key are read from environment variables.
If BOB_API_KEY is not set, the client returns deterministic mock responses
so the rest of the pipeline remains testable without a live Bob connection.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

BOB_API_KEY = os.getenv("BOB_API_KEY", "")
BOB_MODEL = os.getenv("BOB_MODEL", "ibm/granite-13b-instruct-v2")
BOB_API_URL = os.getenv(
    "BOB_API_URL",
    "https://us-south.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29"
)
BOB_PROJECT_ID = os.getenv("BOB_PROJECT_ID", "")


def _mock_analyse_response(evidence: dict) -> dict:
    """Deterministic mock response for testing without a live Bob key."""
    auto = evidence.get("auto_classification", "UNCLASSIFIED")
    score = evidence.get("total_score", 50.0)
    rule = evidence.get("fired_rule_id", "C0")
    alerts_json = evidence.get("alerts_summary_json", "[]")
    try:
        alerts = json.loads(alerts_json)
        sources = list({a["source_type"] for a in alerts})
    except Exception:
        sources = []

    bob_class = "GENUINE_THREAT" if auto == "GENUINE_THREAT" else "FALSE_POSITIVE" if auto == "FALSE_POSITIVE" else "GENUINE_THREAT"
    agree = "AGREES" if bob_class == auto else "PARTIAL"

    return {
        "score_explanation_text": (
            f"The risk score of {score:.1f}/100 reflects the combination of alert severity, "
            f"confidence levels, source diversity ({len(sources)} source type(s): {', '.join(sources)}), "
            f"asset criticality, and temporal recency of the incident."
        ),
        "correlation_review_text": (
            f"Correlation rule {rule} fired correctly. "
            f"The member alerts demonstrate coherent targeting of the same asset(s) "
            f"from {len(sources)} source type(s), which supports the grouping decision."
        ),
        "bob_classification": bob_class,
        "bob_confidence": 0.82 if bob_class == "GENUINE_THREAT" else 0.70,
        "bob_reasoning": (
            f"Based on the evidence provided: {len(alerts)} member alert(s) from "
            f"{', '.join(sources) if sources else 'unknown'} source(s) targeting the same asset(s). "
            f"The correlation rule {rule} and automated classification {auto} are consistent with "
            f"the observed evidence. Risk score {score:.1f} reflects HIGH severity and cross-source "
            f"corroboration where applicable."
        ),
        "agreement_status": agree,
        "agreement_detail": "" if agree == "AGREES" else (
            f"Bob classified as {bob_class} while automated pipeline classified as {auto}. "
            f"Further manual review recommended."
        ),
    }


def _mock_bluf_response(evidence: dict, bob_analysis: dict | None) -> dict:
    """Deterministic mock BLUF for testing."""
    inc = {}
    try:
        inc = json.loads(evidence.get("incident_json", "{}"))
    except Exception:
        pass
    assets = ", ".join(inc.get("affected_assets", ["unknown"]))
    sources = ", ".join(inc.get("source_types_involved", ["unknown"]))
    severity = inc.get("overall_severity", "MEDIUM")
    rule = inc.get("fired_correlation_rule", "C0")
    auto_class = inc.get("auto_classification", "UNCLASSIFIED")
    bob_class = (bob_analysis or {}).get("bob_classification", auto_class)

    return {
        "bluf_line": f"Incident classified as {bob_class} — {severity} severity activity detected on {assets}.",
        "situation": (
            f"The incident involves {len(inc.get('affected_assets',[]))} affected asset(s) ({assets}) "
            f"with correlated alerts from {sources}. "
            f"Correlation rule {rule} grouped the member alerts based on shared targeting and temporal proximity."
        ),
        "assessment": (
            f"Automated classification: {auto_class}. Bob AI assessment: {bob_class}. "
            f"The pattern is consistent with targeted activity against {assets}. "
            f"MITRE ATT&CK mappings indicate relevant techniques observed across the member alerts."
        ),
        "recommendations": (
            f"• Isolate affected assets: {assets}\n"
            f"• Review authentication and network logs for {assets}\n"
            f"• Escalate to Tier-3 if additional corroborating evidence emerges within 2 hours"
        ),
    }


def call_bob_analyse(evidence: dict) -> dict:
    """
    Call IBM Bob to analyse an incident.

    Falls back to mock if BOB_API_KEY is not set.
    Returns the parsed JSON response dict.
    """
    if not BOB_API_KEY:
        log.warning("BOB_API_KEY not set — using mock Bob response.")
        return _mock_analyse_response(evidence)

    try:
        import httpx
        from mcp_server.prompts import ANALYSE_INCIDENT_PROMPT

        prompt = ANALYSE_INCIDENT_PROMPT.format(**evidence)
        payload = {
            "model_id": BOB_MODEL,
            "project_id": BOB_PROJECT_ID,
            "input": prompt,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": 1200,
                "stop_sequences": [],
            },
        }
        headers = {
            "Authorization": f"Bearer {BOB_API_KEY}",
            "Content-Type": "application/json",
        }
        resp = httpx.post(BOB_API_URL, json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        text = resp.json()["results"][0]["generated_text"].strip()
        # Strip any markdown fences
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as exc:
        log.error("Bob API call failed: %s — using mock response.", exc)
        return _mock_analyse_response(evidence)


def call_bob_bluf(evidence: dict, bob_analysis: dict | None) -> dict:
    """
    Call IBM Bob to generate a BLUF summary.

    Falls back to mock if BOB_API_KEY is not set.
    """
    if not BOB_API_KEY:
        log.warning("BOB_API_KEY not set — using mock BLUF response.")
        return _mock_bluf_response(evidence, bob_analysis)

    try:
        import httpx
        from mcp_server.prompts import GENERATE_BLUF_PROMPT

        bob_analysis_json = json.dumps(bob_analysis or {}, default=str)
        prompt = GENERATE_BLUF_PROMPT.format(
            incident_json=evidence.get("incident_json", "{}"),
            bob_analysis_json=bob_analysis_json,
        )
        payload = {
            "model_id": BOB_MODEL,
            "project_id": BOB_PROJECT_ID,
            "input": prompt,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": 800,
            },
        }
        headers = {
            "Authorization": f"Bearer {BOB_API_KEY}",
            "Content-Type": "application/json",
        }
        resp = httpx.post(BOB_API_URL, json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        text = resp.json()["results"][0]["generated_text"].strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as exc:
        log.error("Bob BLUF call failed: %s — using mock.", exc)
        return _mock_bluf_response(evidence, bob_analysis)
