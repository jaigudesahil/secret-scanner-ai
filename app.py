import os
import time
import json
import hashlib
from flask import Flask, render_template, request, jsonify, abort
from werkzeug.utils import secure_filename
from scanner import scan_file, get_scan_summary

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
RATE_LIMIT_SECONDS = 5
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml",
    ".txt", ".sh", ".bash", ".conf", ".cfg", ".ini", ".toml",
    ".rb", ".php", ".go", ".rs", ".java", ".cs", ".cpp", ".c",
    ".tf", ".hcl", ".dockerfile", ".xml", ".properties"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE_BYTES

_last_request_time = {}

def allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS or ext == ""

def rate_limit_check(ip: str) -> bool:
    now = time.time()
    last = _last_request_time.get(ip, 0)
    if now - last < RATE_LIMIT_SECONDS:
        return False
    _last_request_time[ip] = now
    return True

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    client_ip = request.remote_addr

    if not rate_limit_check(client_ip):
        return jsonify({
            "error": f"Rate limit: please wait {RATE_LIMIT_SECONDS}s between scans."
        }), 429

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Empty filename."}), 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        ext = os.path.splitext(filename)[1]
        return jsonify({
            "error": f"File type '{ext}' is not supported. Please upload source code or config files."
        }), 415

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)
        file_size = os.path.getsize(filepath)

        findings = scan_file(filepath)
        summary = get_scan_summary(findings)

        risk_score = (
            summary["critical"] * 40 +
            summary["high"] * 20 +
            summary["medium"] * 10 +
            summary["low"] * 2
        )
        risk_level = (
            "critical" if risk_score >= 40 else
            "high" if risk_score >= 20 else
            "medium" if risk_score >= 10 else
            "low" if risk_score > 0 else
            "clean"
        )

        return jsonify({
            "filename": filename,
            "file_size": file_size,
            "findings": [f.to_dict() for f in findings],
            "summary": summary,
            "risk_score": min(risk_score, 100),
            "risk_level": risk_level,
            "scan_time": round(time.time() - _last_request_time.get(client_ip, time.time()), 3),
        })

    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    finally:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except OSError:
            pass

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large. Maximum size is {MAX_FILE_SIZE_MB}MB."}), 413

if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
