# aggregator.py
def aggregate_results(stage1, stage2, stage3):
    stage2_map = {f["file_name"]: f for f in stage2.get("files", [])}
    stage3_map = {f["file_name"]: f for f in stage3.get("files", [])}

    merged_files = []
    overall_risk = 0

    for f1 in stage1.get("files", []):
        file_name = f1["file_name"]
        s2 = stage2_map.get(file_name, {})
        s3 = stage3_map.get(file_name, {})

        findings = f1["summary"]["findings"]
        high = f1["summary"]["high"]
        medium = f1["summary"]["medium"]
        low = f1["summary"]["low"]
        avg_confidence = f1["summary"]["avg_confidence"]

        risk_score = min(100, int(high * 20 + medium * 10 + low * 5 + avg_confidence * 20))
        overall_risk += risk_score

        merged_files.append({
            "file_name": file_name,
            "summary": {
                "findings": findings,
                "high": high,
                "medium": medium,
                "low": low,
                "avg_confidence": avg_confidence,
                "risk_score": risk_score,
                "top_severity": f1["summary"]["top_severity"],
                "spark_points": f1["summary"]["spark_points"],
                "spark_fill": f1["summary"]["spark_fill"],
            },
            "stage1": f1,
            "stage2": s2,
            "stage3": s3,
            "vulnerabilities": f1["vulnerabilities"],
        })

    merged_files.sort(
        key=lambda x: (
            -x["summary"]["risk_score"],
            -x["summary"]["findings"],
            x["file_name"],
        )
    )

    total_files = len(merged_files)
    total_findings = stage1.get("summary", {}).get("total_vulnerabilities", 0)

    return {
        "summary": {
            "total_files": total_files,
            "total_findings": total_findings,
            "high": stage1["summary"]["high"],
            "medium": stage1["summary"]["medium"],
            "low": stage1["summary"]["low"],
            "overall_risk": round(overall_risk / total_files, 1) if total_files else 0,
        },
        "files": merged_files
    }