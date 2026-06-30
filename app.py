import json
import uuid
from threading import Thread
from pathlib import Path

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from stage1 import run_stage1
from stage2 import run_stage2
from stage3 import run_stage3
from aggregator import aggregate_results

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
LATEST_REPORT = REPORT_DIR / "latest_scan_results.json"

ALLOWED_EXTENSIONS = {"py", "txt", "js", "ts", "java", "php", "c", "cpp", "html", "css", "json"}

SCAN_JOBS = {}

app = Flask(__name__)
app.secret_key = "code-risk-engine-secret"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def update_job(job_id, stage=None, progress=None, done=None, results=None, error=None):
    job = SCAN_JOBS.setdefault(
        job_id,
        {
            "stage": "Queued",
            "progress": 0,
            "done": False,
        },
    )
    if stage is not None:
        job["stage"] = stage
    if progress is not None:
        job["progress"] = progress
    if done is not None:
        job["done"] = done
    if results is not None:
        job["results"] = results
    if error is not None:
        job["error"] = error


def run_pipeline(job_id, saved_files):
    try:
        update_job(job_id, stage="ML Scanning", progress=10)
        stage1 = run_stage1(saved_files)

        update_job(job_id, stage="Threat Screening", progress=45)
        stage2 = run_stage2(saved_files, stage1)

        update_job(job_id, stage="Future Risk", progress=75)
        stage3 = run_stage3(saved_files, stage1)

        update_job(job_id, stage="Finalizing", progress=95)
        results = aggregate_results(stage1, stage2, stage3)

        summary = results.setdefault("summary", {})
        summary["ml_findings"] = stage1.get("summary", {}).get("total_vulnerabilities", 0)
        summary["threat_matches"] = stage2.get("summary", {}).get("total_findings", 0)
        summary["forecast_risk"] = stage3.get("summary", {}).get("overall_risk", 0)
        summary["overall_risk"] = summary.get("overall_risk", 0)

        with open(LATEST_REPORT, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)

        update_job(job_id, stage="Done", progress=100, done=True, results=results)
    except Exception as exc:
        update_job(job_id, stage="Error", progress=100, done=True, error=str(exc))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        project_name="CodeRisk Engine",
        project_subtitle="Machine-learned vulnerability detection and risk assessment for source code.",
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    uploaded_files = request.files.getlist("files")
    saved_files = []

    for f in uploaded_files:
        if f and allowed_file(f.filename):
            safe_name = secure_filename(f.filename)
            unique_name = f"{uuid.uuid4().hex}_{safe_name}"
            save_path = UPLOAD_DIR / unique_name
            f.save(save_path)

            saved_files.append(
                {
                    "path": str(save_path),
                    "display_name": safe_name,
                }
            )

    if not saved_files:
        return jsonify({"error": "Upload files."}), 400

    job_id = uuid.uuid4().hex
    SCAN_JOBS[job_id] = {
        "stage": "Queued",
        "progress": 0,
        "done": False,
    }

    Thread(target=run_pipeline, args=(job_id, saved_files), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def status(job_id):
    return jsonify(
        SCAN_JOBS.get(
            job_id,
            {
                "stage": "Unknown",
                "progress": 0,
                "done": False,
            },
        )
    )


@app.route("/results/<job_id>")
def results(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        flash("Scan job not found.")
        return redirect(url_for("index"))

    if not job.get("done") or not job.get("results"):
        return render_template("loading.html", job_id=job_id)

    return render_template("results.html", results=job["results"], job_id=job_id)


@app.route("/download-report")
def download_report():
    if not LATEST_REPORT.exists():
        flash("No report available yet.")
        return redirect(url_for("index"))
    return send_file(LATEST_REPORT, as_attachment=True, download_name="scan_results.json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False, threaded=True)