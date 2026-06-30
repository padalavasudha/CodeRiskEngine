# stage2.py
import json
from pathlib import Path

import requests

from stage1 import normalize_file_input, is_excluded_path

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.1"


def extract_text(path: Path, max_chars: int = 12000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return text[:max_chars]
    except Exception:
        return ""


def build_prompt(file_name: str, code: str, stage1_hits=None) -> str:
    stage1_hits = stage1_hits or []
    return f"""
You are a secure code reviewer.

Analyze the following source code for UNKNOWN vulnerabilities that may not be caught by simple pattern matching.
Focus on logic flaws, authorization mistakes, insecure state transitions, unsafe assumptions, and misuse of sensitive actions.

Return ONLY valid JSON in this exact schema:
{{
  "findings": [
    {{
      "line_no": 0,
      "title": "",
      "category": "",
      "severity": "HIGH|MEDIUM|LOW",
      "confidence": 0.0,
      "code": "",
      "explanation": "",
      "mitigation": ""
    }}
  ]
}}

Rules:
- Use line numbers when possible.
- If no issue exists, return: {{"findings":[]}}
- Do not add markdown.
- Do not add extra text.
- Do not wrap JSON in code fences.

File: {file_name}

Stage 1 hints:
{json.dumps(stage1_hits, indent=2)}

Code:
{code}
""".strip()


def call_llm(prompt: str) -> dict:
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=120)
    response.raise_for_status()
    data = response.json()

    raw = data.get("response", "").strip()
    if not raw:
        return {"findings": []}

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                return {"findings": []}
        return {"findings": []}


def run_stage2(file_list, stage1_results=None):
    stage1_map = {}
    if stage1_results:
        for f in stage1_results.get("files", []):
            stage1_map[f["file_name"]] = f

    results = {
        "files": [],
        "summary": {
            "total_files": 0,
            "total_findings": 0,
            "findings": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
    }

    total_findings = 0

    for file_item in file_list:
        file_path, display_name = normalize_file_input(file_item)

        if is_excluded_path(file_path):
            continue

        if not file_path.exists() or not file_path.is_file():
            continue

        code = extract_text(file_path)
        if not code.strip():
            continue

        stage1_hits = []
        if stage1_results:
            stage1_file = stage1_map.get(display_name, {})
            for vuln in stage1_file.get("vulnerabilities", []):
                stage1_hits.append(
                    {
                        "line_no": vuln.get("line_no"),
                        "type": vuln.get("type"),
                        "severity": vuln.get("severity"),
                        "code": vuln.get("code"),
                    }
                )

        prompt = build_prompt(display_name, code, stage1_hits)

        try:
            llm_result = call_llm(prompt)
        except Exception:
            llm_result = {"findings": []}

        findings = llm_result.get("findings", [])
        cleaned_findings = []

        for finding in findings:
            severity = str(finding.get("severity", "LOW")).upper()
            if severity not in {"HIGH", "MEDIUM", "LOW"}:
                severity = "LOW"

            cleaned = {
                "line_no": int(finding.get("line_no", 0) or 0),
                "title": finding.get("title", "Unknown issue"),
                "category": finding.get("category", "Unknown"),
                "severity": severity,
                "confidence": float(finding.get("confidence", 0.0) or 0.0),
                "code": finding.get("code", ""),
                "explanation": finding.get("explanation", ""),
                "mitigation": finding.get("mitigation", ""),
            }
            cleaned_findings.append(cleaned)

            total_findings += 1
            results["summary"][severity.lower()] += 1

        file_total = len(cleaned_findings)
        results["files"].append(
            {
                "file_name": display_name,
                "source_path": str(file_path),
                "summary": {
                    "total_findings": file_total,
                    "findings": file_total,
                    "high": sum(1 for f in cleaned_findings if f["severity"] == "HIGH"),
                    "medium": sum(1 for f in cleaned_findings if f["severity"] == "MEDIUM"),
                    "low": sum(1 for f in cleaned_findings if f["severity"] == "LOW"),
                },
                "findings": cleaned_findings,
            }
        )

    results["summary"]["total_files"] = len(results["files"])
    results["summary"]["total_findings"] = total_findings
    results["summary"]["findings"] = total_findings

    return results