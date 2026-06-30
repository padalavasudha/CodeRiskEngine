# stage3.py
from pathlib import Path

from stage1 import normalize_file_input, is_excluded_path

RISK_KEYWORDS = {
    "login": 8,
    "auth": 10,
    "admin": 14,
    "user": 6,
    "payment": 12,
    "checkout": 12,
    "profile": 5,
    "account": 8,
    "delete": 10,
    "update": 7,
    "transfer": 14,
    "refund": 12,
    "reset": 10,
}


def _keyword_bonus(name: str) -> int:
    lower = name.lower()
    bonus = 0
    for key, val in RISK_KEYWORDS.items():
        if key in lower:
            bonus += val
    return bonus


def _predict_risk(stage1_summary, file_name):
    high = stage1_summary.get("high", 0)
    medium = stage1_summary.get("medium", 0)
    low = stage1_summary.get("low", 0)
    findings = stage1_summary.get("findings", 0)

    base = high * 22 + medium * 12 + low * 5 + findings * 3
    base += _keyword_bonus(file_name)

    return max(0, min(100, int(base)))


def run_stage3(file_list, stage1_results=None):
    stage1_map = {}
    if stage1_results:
        for f in stage1_results.get("files", []):
            stage1_map[f["file_name"]] = f

    results = {
        "files": [],
        "summary": {
            "overall_risk": 0,
        },
    }

    total_risk = 0
    count = 0

    for file_item in file_list:
        file_path, display_name = normalize_file_input(file_item)

        if is_excluded_path(file_path):
            continue

        if not file_path.exists() or not file_path.is_file():
            continue

        s1_file = stage1_map.get(display_name, {})
        s1_summary = s1_file.get("summary", {})

        risk_score = _predict_risk(s1_summary, display_name)

        if risk_score >= 80:
            trend = "rising"
        elif risk_score >= 50:
            trend = "watch"
        else:
            trend = "stable"

        results["files"].append({
            "file_name": display_name,
            "risk_score": risk_score,
            "trend": trend,
            "forecast": "High risk likely in near-term changes" if risk_score >= 80 else "No immediate risk spike predicted",
        })

        total_risk += risk_score
        count += 1

    results["summary"]["overall_risk"] = round(total_risk / count, 1) if count else 0
    return results