"""PhishGuard web app. Run: python app.py  then open http://127.0.0.1:5000"""
from flask import Flask, jsonify, redirect, render_template, request, url_for

import database
from analyzer import analyze

app = Flask(__name__)
MAX_URL_LENGTH = 2000


def clean_url(raw):
    """Basic input validation: strip spaces, reject empty or huge input."""
    url = (raw or "").strip()
    if not url or len(url) > MAX_URL_LENGTH or " " in url:
        return None
    return url


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    if request.method == "POST":
        url = clean_url(request.form.get("url"))
        if url is None:
            error = "Please enter a valid URL (no spaces, max 2000 characters)."
        else:
            result = analyze(url)
            database.save_scan(result)
    return render_template("index.html", result=result, error=error)


@app.route("/bulk", methods=["POST"])
def bulk():
    lines = request.form.get("urls", "").splitlines()
    results = []
    for line in lines[:50]:  # limit to 50 URLs per request
        url = clean_url(line)
        if url:
            r = analyze(url)
            database.save_scan(r)
            results.append(r)
    return render_template("bulk.html", results=results)


@app.route("/history")
def history():
    verdict = request.args.get("verdict")
    if verdict not in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        verdict = None
    return render_template("history.html", scans=database.get_history(verdict=verdict),
                           selected=verdict)


@app.route("/stats")
def stats():
    return render_template("stats.html", stats=database.get_stats())


@app.route("/clear", methods=["POST"])
def clear():
    database.clear_history()
    return redirect(url_for("history"))


@app.route("/api/check")
def api_check():
    """JSON API: /api/check?url=http://example.com"""
    url = clean_url(request.args.get("url"))
    if url is None:
        return jsonify({"error": "missing or invalid 'url' parameter"}), 400
    return jsonify(analyze(url))


if __name__ == "__main__":
    database.init_db()
    app.run(debug=True)
