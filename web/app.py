from flask import Flask, render_template, request, jsonify

from llm_sentinel.scanner import scan_text, risk_score, risk_level


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    text = data.get("text", "")

    if not isinstance(text, str):
        return jsonify({"error": "Input must be text."}), 400

    if not text.strip():
        return jsonify({"error": "Please provide text to scan."}), 400

    findings = scan_text(text)
    score = risk_score(findings)
    level = risk_level(score)

    return jsonify({
        "risk_score": score,
        "risk_level": level,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings]
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )

