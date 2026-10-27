# SecureTrack: AI-Assisted Incident Reporting & Threat Intelligence

A local Flask prototype that integrates the trained CERT event classifier with:
- Incident submission and model-assisted triage
- Incident listing, detail view, and response-status updates
- Threat-intelligence indicator creation, listing, and deletion
- A dashboard with basic operational counts
- SQLite storage for demonstration and coursework

## 1. Add the trained model artifacts

Copy these exported files from your Colab session into this project folder (beside `app.py`):
- `best_security_event_classifier.pkl`
- `security_model_features.pkl`
- `security_model_metadata.pkl`

The app expects a scikit-learn Pipeline saved with `joblib`, and a feature list containing the model's exact training columns.

## 2. Install and run

Use Python 3.10+ (same or compatible versions of scikit-learn, pandas and XGBoost as used to train the model are recommended).

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

The database `security_incidents.db` is created automatically on first run.

## 3. Important model limitations

The app's prediction is a model estimate, not a confirmed security incident. The trained model currently uses the activity field and timestamp-derived features; it does not analyse the submitted narrative, validate threat indicators against external feeds, or perform live network monitoring. The saved model uses a fixed 0.50 threshold unless you explicitly update the app to use a separately validated threshold.

The app is a coursework prototype, not a production security platform. Before production use, add authentication and role-based access, CSRF protection, input auditing, secure secret management, database backups, and analyst review workflows. Do not expose the development server publicly.
