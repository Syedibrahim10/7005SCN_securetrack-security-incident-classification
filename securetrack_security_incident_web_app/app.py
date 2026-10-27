import os
import json
import sqlite3
from datetime import datetime
from functools import wraps

import joblib
import pandas as pd
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, g, abort
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "security_incidents.db")
MODEL_PATH = os.path.join(APP_DIR, "best_security_event_classifier.pkl")
FEATURES_PATH = os.path.join(APP_DIR, "security_model_features.pkl")
METADATA_PATH = os.path.join(APP_DIR, "security_model_metadata.pkl")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")

# Load the exported sklearn pipeline and expected feature list.
model = None
model_features = []
model_metadata = {}

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

if os.path.exists(FEATURES_PATH):
    model_features = joblib.load(FEATURES_PATH)

if os.path.exists(METADATA_PATH):
    model_metadata = joblib.load(METADATA_PATH)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        reporter TEXT NOT NULL,
        event_timestamp TEXT NOT NULL,
        activity TEXT NOT NULL,
        description TEXT NOT NULL,
        anomaly_probability REAL,
        predicted_label INTEGER,
        status TEXT NOT NULL DEFAULT 'Open',
        severity TEXT NOT NULL DEFAULT 'Medium',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        threat_name TEXT NOT NULL,
        source TEXT,
        confidence INTEGER NOT NULL DEFAULT 50,
        notes TEXT,
        created_at TEXT NOT NULL
    );
    """)
    db.commit()
    db.close()


def model_ready():
    return model is not None and bool(model_features)


def build_model_input(activity, timestamp):
    """Create the same input columns used when training the exported pipeline."""
    parsed = pd.to_datetime(timestamp, errors="coerce")
    if pd.isna(parsed):
        raise ValueError("Please provide a valid date and time.")

    values = {
        "activity": str(activity).strip(),
        "event_hour": int(parsed.hour),
        "event_day": int(parsed.day),
        "event_month": int(parsed.month),
        "event_weekday": int(parsed.dayofweek),
        "is_weekend": int(parsed.dayofweek >= 5),
        "is_outside_working_hours": int(parsed.hour < 8 or parsed.hour >= 18),
    }

    # Ensure the form input exactly matches the model's trained feature schema.
    row = {feature: values.get(feature, None) for feature in model_features}
    return pd.DataFrame([row], columns=model_features)


def predict_event(activity, timestamp):
    if not model_ready():
        raise RuntimeError(
            "Model files are missing. Put the exported .pkl model and feature "
            "files beside app.py, then restart the app."
        )

    model_input = build_model_input(activity, timestamp)
    probability = float(model.predict_proba(model_input)[0][1])
    label = int(probability >= 0.5)
    return probability, label


@app.route("/")
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    open_count = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE status = 'Open'"
    ).fetchone()[0]
    flagged = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE predicted_label = 1"
    ).fetchone()[0]
    intel_count = db.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
    recent = db.execute(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT 6"
    ).fetchall()
    return render_template(
        "dashboard.html",
        total=total, open_count=open_count, flagged=flagged,
        intel_count=intel_count, recent=recent,
        model_ready=model_ready()
    )


@app.route("/incidents")
def incidents():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM incidents ORDER BY id DESC"
    ).fetchall()
    return render_template("incidents.html", incidents=rows)


@app.route("/incidents/new", methods=["GET", "POST"])
def new_incident():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        reporter = request.form.get("reporter", "").strip()
        event_timestamp = request.form.get("event_timestamp", "").strip()
        activity = request.form.get("activity", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Medium").strip()

        if not all([title, reporter, event_timestamp, activity, description]):
            flash("Please complete all required fields.", "error")
            return render_template("new_incident.html", form=request.form)

        try:
            probability, label = predict_event(activity, event_timestamp)
        except Exception as exc:
            flash(str(exc), "error")
            return render_template("new_incident.html", form=request.form)

        db = get_db()
        db.execute("""
            INSERT INTO incidents
            (title, reporter, event_timestamp, activity, description,
             anomaly_probability, predicted_label, status, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
        """, (
            title, reporter, event_timestamp, activity, description,
            probability, label, severity, datetime.now().isoformat(timespec="seconds")
        ))
        db.commit()
        flash(
            "Incident report saved. Model classified it as " +
            ("Anomalous" if label == 1 else "Normal") +
            f" (estimated anomaly probability: {probability:.1%}).",
            "success"
        )
        return redirect(url_for("incidents"))

    return render_template("new_incident.html", form={})


@app.route("/incidents/<int:incident_id>", methods=["GET", "POST"])
def incident_detail(incident_id):
    db = get_db()
    incident = db.execute(
        "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    ).fetchone()
    if incident is None:
        abort(404)

    if request.method == "POST":
        status = request.form.get("status", "Open")
        if status not in ["Open", "In Progress", "Resolved"]:
            flash("Invalid status selection.", "error")
        else:
            db.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (status, incident_id)
            )
            db.commit()
            flash("Incident status updated.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    return render_template("incident_detail.html", incident=incident)


@app.route("/threat-intel", methods=["GET", "POST"])
def threat_intel():
    db = get_db()
    if request.method == "POST":
        indicator = request.form.get("indicator", "").strip()
        indicator_type = request.form.get("indicator_type", "").strip()
        threat_name = request.form.get("threat_name", "").strip()
        source = request.form.get("source", "").strip()
        notes = request.form.get("notes", "").strip()
        try:
            confidence = int(request.form.get("confidence", "50"))
        except ValueError:
            confidence = 50

        if not indicator or not indicator_type or not threat_name:
            flash("Indicator, type and threat name are required.", "error")
        elif confidence < 0 or confidence > 100:
            flash("Confidence must be between 0 and 100.", "error")
        else:
            db.execute("""
                INSERT INTO threat_intel
                (indicator, indicator_type, threat_name, source,
                 confidence, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator, indicator_type, threat_name, source,
                confidence, notes, datetime.now().isoformat(timespec="seconds")
            ))
            db.commit()
            flash("Threat intelligence entry added.", "success")
            return redirect(url_for("threat_intel"))

    rows = db.execute(
        "SELECT * FROM threat_intel ORDER BY id DESC"
    ).fetchall()
    return render_template("threat_intel.html", indicators=rows)


@app.route("/threat-intel/<int:item_id>/delete", methods=["POST"])
def delete_threat_intel(item_id):
    db = get_db()
    db.execute("DELETE FROM threat_intel WHERE id = ?", (item_id,))
    db.commit()
    flash("Threat intelligence entry deleted.", "success")
    return redirect(url_for("threat_intel"))


@app.route("/health")
def health():
    return {
        "app": "running",
        "model_loaded": model_ready(),
        "model_name": model_metadata.get("selected_model", "Not available")
    }


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
