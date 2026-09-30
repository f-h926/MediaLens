from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

from utils.validators import validate_url
from analysis.url_analyser import analyse_url
from analysis.risk_engine import (calculate_risk, calculate_combined_risk)
from services.virustotal import check_url_reputation
from services.urlhaus import check_urlhaus

import os

print(
    "VirusTotal key loaded:",
    bool(os.getenv("VIRUSTOTAL_API_KEY"))
)

app = Flask(__name__)

CORS(app, origins=["http://localhost:5173"])


@app.get("/api/health")
def health_check():
    return jsonify({
        "status": "success",
        "message": "MediaLens API is running"
    })


@app.post("/api/scan")
def scan_url():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Request must contain JSON data."
        }), 400

    url = data.get("url")

    if not isinstance(url, str):
        return jsonify({
            "error": "A valid URL must be provided."
        }), 400

    # validate URL
    is_valid, normalised_url, error = validate_url(url)

    if not is_valid:
        return jsonify({
            "error": error
        }), 400

    # analyse URL
    analysis = analyse_url(normalised_url)

    local_risk = calculate_risk(analysis)

    virustotal = check_url_reputation(normalised_url)

    urlhaus = check_urlhaus(normalised_url)

    combined_risk = calculate_combined_risk(local_risk, virustotal, urlhaus)

    return jsonify({
        "status": "success",
        "analysis": analysis,
        "risk": combined_risk,
        "local_risk": local_risk,
        "threat_intelligence": {
            "virustotal": virustotal,
            "urlhaus": urlhaus
        }
    }), 200

if __name__ == "__main__":
    app.run(debug=True)