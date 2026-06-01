"""Dashboard web léger — visualisation base IOC honeypot."""

from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
IOC_DIR = Path(os.getenv("IOC_DATA_DIR", "/data/ioc"))


def load_data() -> dict:
    path = IOC_DIR / "iocs.json"
    if not path.exists():
        return {"meta": {}, "stats": {}, "iocs": []}
    return json.loads(path.read_text(encoding="utf-8"))


@app.route("/")
def index():
    data = load_data()
    return render_template(
        "index.html",
        stats=data.get("stats", {}),
        iocs=data.get("iocs", [])[:200],
        meta=data.get("meta", {}),
    )


@app.route("/api/stats")
def api_stats():
    return jsonify(load_data().get("stats", {}))


@app.route("/api/iocs")
def api_iocs():
    data = load_data()
    ioc_type = request.args.get("type")
    iocs = data.get("iocs", [])
    if ioc_type:
        iocs = [i for i in iocs if i.get("type") == ioc_type]
    return jsonify(iocs)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
