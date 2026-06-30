import json
import re
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report

BASE_DIR = Path(__file__).resolve().parent

# ---------------- LOAD MODEL ----------------
model = joblib.load(BASE_DIR / "model.pkl")
vectorizer = joblib.load(BASE_DIR / "vectorizer.pkl")

# ---------------- SEVERITY ORDER ----------------
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ---------------- INPUT NORMALIZATION ----------------
def normalize_file_input(item):
    """
    Accepts:
      - {"path": "...", "display_name": "..."}
      - ("path", "display_name")
      - "path"
    Returns: (Path, display_name)
    """
    if isinstance(item, dict):
        path = Path(item["path"])
        display_name = item.get("display_name") or path.name
        return path, display_name

    if isinstance(item, (tuple, list)) and len(item) >= 1:
        path = Path(item[0])
        display_name = item[1] if len(item) > 1 else path.name
        return path, display_name

    path = Path(item)
    return path, path.name


def is_excluded_path(path: Path) -> bool:
    excluded_parts = {"__pycache__", ".venv", "venv", "reports", ".git"}
    return any(part in excluded_parts for part in path.parts)


# ---------------- SAFE FILTER ----------------
def is_obviously_safe(line):
    safe_patterns = ["print(", "input(", "render_template", "json.loads", "str("]
    return any(p in line for p in safe_patterns)


def is_safe_sql_query(line):
    return (
        ("SELECT" in line or "INSERT" in line or "UPDATE" in line or "DELETE" in line)
        and ("?" in line or "%s" in line)
        and "+" not in line
        and 'f"' not in line
    )


# ---------------- SQL RULE ----------------
def detect_sql_injection_pattern(line):
    return (
        (("SELECT" in line or "DELETE" in line) and "+" in line)
        or ("%s" in line and "SELECT" in line)
        or ('f"' in line and "SELECT" in line)
        or ('f"' in line and "DELETE" in line)
        or ('f"' in line and "UPDATE" in line)
        or ('f"' in line and "INSERT" in line)
    )


# ---------------- SEVERITY ----------------
def get_severity(confidence):
    if confidence >= 0.85:
        return "HIGH"
    elif confidence >= 0.65:
        return "MEDIUM"
    else:
        return "LOW"


# ---------------- QUERY TYPE ----------------
def detect_query_type(line):
    if "SELECT" in line:
        return "SELECT"
    elif "DELETE" in line:
        return "DELETE"
    elif "INSERT" in line:
        return "INSERT"
    elif "UPDATE" in line:
        return "UPDATE"
    return "QUERY"


# ---------------- DYNAMIC FIX ----------------
def generate_rule_fix(line):
    variables = re.findall(r"\+\s*(\w+)\s*\+", line)
    last_var = re.findall(r"\+\s*(\w+)\s*$", line)
    variables.extend(last_var)
    variables = list(set(variables))

    if not variables:
        return "Use parameterized queries."

    conditions = " AND ".join([f"{v} = ?" for v in variables])
    params = ", ".join(variables)

    query_type = detect_query_type(line)

    if query_type == "SELECT":
        return f'cursor.execute("SELECT * FROM users WHERE {conditions}", ({params},))'
    elif query_type == "DELETE":
        return f'cursor.execute("DELETE FROM users WHERE {conditions}", ({params},))'
    elif query_type == "UPDATE":
        return f'cursor.execute("UPDATE users SET column = ? WHERE {conditions}", ({params},))'
    elif query_type == "INSERT":
        return f'cursor.execute("INSERT INTO users VALUES (?)", ({params},))'
    else:
        return f'cursor.execute("QUERY WHERE {conditions}", ({params},))'


# ---------------- DASHBOARD HELPERS ----------------
def build_sparkline(values, width=100, height=30):
    """
    Build SVG polyline + filled area strings from a list of confidence values.
    Values should be in [0, 1]. Returns a dict with `points` and `fill`.
    """
    if not values:
        values = [0.0]

    values = [max(0.0, min(1.0, float(v))) for v in values]

    n = 6
    if len(values) == 1:
        sample = values * n
    elif len(values) < n:
        sample = values + [values[-1]] * (n - len(values))
    else:
        step = (len(values) - 1) / (n - 1)
        sample = [values[round(i * step)] for i in range(n)]

    points = []
    for i, v in enumerate(sample):
        x = i * (width / (n - 1))
        y = height - 4 - (v * (height - 8))
        points.append(f"{x:.1f},{y:.1f}")

    fill = f"0,{height - 2} " + " ".join(points) + f" {width},{height - 2}"
    return {"points": " ".join(points), "fill": fill}


def build_file_summary(vulnerabilities):
    counts = Counter(v["severity"] for v in vulnerabilities)
    avg_confidence = (
        round(sum(v["confidence"] for v in vulnerabilities) / len(vulnerabilities), 2)
        if vulnerabilities
        else 0.0
    )

    top_severity = "NONE"
    if vulnerabilities:
        top_severity = min(
            (v["severity"] for v in vulnerabilities),
            key=lambda s: SEVERITY_ORDER.get(s, 99),
        )

    spark = build_sparkline([v["confidence"] for v in vulnerabilities])

    return {
        "findings": len(vulnerabilities),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "avg_confidence": avg_confidence,
        "top_severity": top_severity,
        "spark_points": spark["points"],
        "spark_fill": spark["fill"],
    }


def sort_results(results):
    def file_sort_key(file_result):
        s = file_result.get("summary", {})
        severity_rank = SEVERITY_ORDER.get(s.get("top_severity", "NONE"), 99)
        return (
            severity_rank,
            -s.get("findings", 0),
            -s.get("avg_confidence", 0),
            file_result.get("file_name", ""),
        )

    for file_result in results["files"]:
        file_result["vulnerabilities"].sort(
            key=lambda v: (
                SEVERITY_ORDER.get(v["severity"], 99),
                -v["confidence"],
                v["line_no"],
            )
        )

    results["files"].sort(key=file_sort_key)
    return results


# ---------------- MAIN SCAN ----------------
def run_stage1(file_list, output_path=None):
    results = {
        "files": [],
        "summary": {
            "total_files": 0,
            "total_vulnerabilities": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "high_pct": 0.0,
            "medium_pct": 0.0,
            "low_pct": 0.0,
        },
    }

    total_vulns = 0

    for file_item in file_list:
        file_path, display_name = normalize_file_input(file_item)

        if is_excluded_path(file_path):
            continue

        if not file_path.exists() or not file_path.is_file():
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            lines = []

        vulnerabilities = []

        for i, line in enumerate(lines):
            line_clean = line.strip()
            if not line_clean:
                continue

            if is_obviously_safe(line_clean):
                continue

            if is_safe_sql_query(line_clean):
                continue

            X = vectorizer.transform([line_clean])
            prediction = model.predict(X)[0]
            probability = model.predict_proba(X)[0][prediction]

            is_sql = detect_sql_injection_pattern(line_clean)

            if is_sql or prediction == 1:
                severity = get_severity(probability)

                vuln = {
                    "line_no": i + 1,
                    "code": line_clean,
                    "confidence": round(float(probability), 2),
                    "type": "SQL Injection",
                    "severity": severity,
                    "suggested_fix": "Use parameterized queries instead of string concatenation.",
                    "dynamic_fix": generate_rule_fix(line_clean),
                }

                vulnerabilities.append(vuln)
                total_vulns += 1
                results["summary"][severity.lower()] += 1

        file_result = {
            "file_name": display_name,
            "source_path": str(file_path),
            "summary": build_file_summary(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }
        results["files"].append(file_result)

    results["summary"]["total_files"] = len(results["files"])
    results["summary"]["total_vulnerabilities"] = total_vulns

    if total_vulns:
        results["summary"]["high_pct"] = round(results["summary"]["high"] / total_vulns * 100, 1)
        results["summary"]["medium_pct"] = round(results["summary"]["medium"] / total_vulns * 100, 1)
        results["summary"]["low_pct"] = round(results["summary"]["low"] / total_vulns * 100, 1)

    results = sort_results(results)

    if output_path:
        output_path = Path(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)

    return results


# ---------------- MODEL PERFORMANCE ----------------
def draw_bar(label, value, width=30):
    filled = int(value * width)
    bar = "█" * filled + "-" * (width - filled)
    print(f"{label:15}: [{bar}] {value:.2f}")


def evaluate_model(csv_path=None):
    csv_file = Path(csv_path) if csv_path else (BASE_DIR / "real_test.csv")
    if not csv_file.exists():
        print("\nreal_test.csv not found. Skipping model evaluation.")
        return

    df = pd.read_csv(csv_file)

    X = vectorizer.transform(df["code"])
    y_true = df["label"]
    y_pred = model.predict(X)

    report = classification_report(y_true, y_pred, output_dict=True)

    print("\n========== MODEL PERFORMANCE ==========")
    print("\n--- Vulnerable Class ---")
    draw_bar("Precision", report["1"]["precision"])
    draw_bar("Recall", report["1"]["recall"])
    draw_bar("F1-score", report["1"]["f1-score"])

    print("\n--- Overall ---")
    draw_bar("Accuracy", report["accuracy"])


def has_high_severity(results):
    return any(
        vuln["severity"] == "HIGH"
        for file_result in results["files"]
        for vuln in file_result["vulnerabilities"]
    )


# ---------------- OPTIONAL CLI ENTRY ----------------
if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    files = []

    for arg in args:
        p = Path(arg)
        if p.is_dir():
            files.extend([str(x) for x in p.rglob("*.py") if not is_excluded_path(x)])
        elif p.exists():
            files.append(str(p))

    if not files:
        files = [
            str(p)
            for p in Path(".").rglob("*.py")
            if p.name not in {"analyzer.py", "app.py"} and not is_excluded_path(p)
        ]

    results = run_stage1(files, output_path=BASE_DIR / "scan_results.json")

    if has_high_severity(results):
        print("\n[CI/CD] HIGH severity vulnerabilities detected.")
        raise SystemExit(1)

    print("\n[CI/CD] No blocking vulnerabilities found.")
    raise SystemExit(0)