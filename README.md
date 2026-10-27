# SecureTrack: AI-Assisted Security Incident Reporting and Threat Intelligence

SecureTrack is a local Flask web application prototype for recording security incidents, reviewing machine-learning-assisted event classifications, tracking incident response status, and maintaining threat-intelligence indicators. The machine-learning workflow is documented in `CERT_Security_Incident_Classification.ipynb` and uses the supplied CERT-style event data in `cert_preprocessed_ml_comparison.csv`.



## Contents

- [Features](#features)
- [Project structure](#project-structure)
- [Dataset and notebook](#dataset-and-notebook)
- [Machine-learning workflow](#machine-learning-workflow)
- [Model evaluation](#model-evaluation)
- [Requirements](#requirements)
- [Installation and setup](#installation-and-setup)
- [Running the application](#running-the-application)
- [Using SecureTrack](#using-securetrack)
- [Application routes](#application-routes)
- [Model artifacts](#model-artifacts)
- [Limitations and security notes](#limitations-and-security-notes)
- [Troubleshooting](#troubleshooting)

## Features

- **Operations dashboard:** shows the number of incidents, open incidents, anomalous events flagged by the model, and stored threat-intelligence indicators.
- **Incident reporting:** records an incident title, reporter, event time, activity, description, and reported severity.
- **Model-assisted triage:** scores a submitted event and stores its estimated anomaly probability and predicted class.
- **Incident management:** lists reports, displays individual report details, and allows a report status to be changed to `Open`, `In Progress`, or `Resolved`.
- **Threat-intelligence register:** adds, lists, and deletes indicators such as IP addresses, domains, URLs, file hashes, and email addresses, with a threat/campaign name, source, confidence, and notes.
- **Health endpoint:** reports whether the application is running and whether the model artifacts have loaded.
- **Local persistence:** stores incident and threat-intelligence records in SQLite.

## Project structure

The ZIP archive contains the following application files:

```text
securetrack_security_incident_web_app/
├── app.py
├── best_security_event_classifier.pkl
├── security_model_features.pkl
├── security_model_metadata.pkl
├── security_incidents.db
├── requirements.txt
├── README.md
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── dashboard.html
    ├── incidents.html
    ├── incident_detail.html
    ├── new_incident.html
    └── threat_intel.html
```

The analysis files supplied separately are:

```text
CERT_Security_Incident_Classification.ipynb
cert_preprocessed_ml_comparison.csv
```

- `app.py` defines the Flask routes, SQLite tables, feature construction, and prediction logic.
- `templates/` contains the HTML pages rendered by Flask.
- `static/style.css` provides the application's styling and responsive layout.
- `best_security_event_classifier.pkl` contains the fitted scikit-learn pipeline.
- `security_model_features.pkl` contains the feature-column list expected by the saved pipeline.
- `security_model_metadata.pkl` records the selected model and training metadata.
- `security_incidents.db` is the SQLite database included in the archive. The application also creates the database and tables on startup if needed.

## Dataset and notebook

The supplied CSV has **4,615 rows and 8 data columns** after removing its automatically generated index column. Its column names are:

- `file`
- `id`
- `timestamp`
- `user`
- `pc`
- `activity`
- `resource`
- `case id;Cattivi`

The final column contains a combined case identifier and binary target label, separated by a semicolon. The notebook identifies two different row layouts in the file: 1,274 rows in the original layout and 3,341 rows with shifted/missing fields. It reconstructs the shifted rows before modeling and extracts `case_id` and `Cattivi`.

The target used by the notebook is `Cattivi`:

- `0` = Normal
- `1` = Anomalous

The notebook checks missing values and duplicates, examines the target and case-label distribution, extracts time-derived features, excludes direct identifiers, and prepares the model features. The original `file` column is excluded because it is not consistently available across the two row layouts.

### Notebook environment

The notebook includes a Google Colab upload step (`files.upload()`) and installs/uses XGBoost. It is designed to be run in Google Colab. In a local environment, replace the Colab upload/download calls with local file paths and remove the `google.colab` dependency.

## Machine-learning workflow

The notebook performs the following steps:

1. **Load and inspect data:** read the CSV, remove generated index columns, and inspect the schema.
2. **Reconstruct row layouts:** restore shifted records and recover the case identifier and binary label.
3. **Data-quality checks:** inspect data types, missing values, duplicate records, and labels within each case.
4. **Feature engineering:** parse timestamps and derive `event_hour`, `event_day`, `event_month`, `event_weekday`, `is_weekend`, and `is_outside_working_hours`.
5. **Feature selection:** use the target `Cattivi`; exclude identifier-like fields including `id`, `case_id`, `user`, `pc`, `resource`, and `file` where present; remove constant or all-missing features.
6. **Grouped validation:** use `StratifiedGroupKFold` with `case_id` as the group so that records from the same case are not split between training and validation/test partitions.
7. **Preprocessing:** impute numeric missing values with the median and scale numeric features; impute categorical missing values with the most frequent value and one-hot encode categorical features.
8. **Model comparison:** train and compare Random Forest and XGBoost classifiers.
9. **Evaluation:** calculate accuracy, precision, recall, F1-score, ROC-AUC, and PR-AUC; produce confusion matrices, ROC curves, precision-recall curves, and feature-importance output for the selected model where supported.
10. **Export:** save the selected fitted pipeline, feature list, metadata, and evaluation tables for reuse by the web application.

The notebook chooses the model with the highest mean grouped cross-validation PR-AUC. In the saved notebook run, this selected **XGBoost**.

## Model evaluation

The saved notebook output reports the following grouped cross-validation and held-out test results:

### Grouped cross-validation PR-AUC

| Model | Mean CV PR-AUC | Standard deviation |
|---|---:|---:|
| Random Forest | 0.4888 | 0.1298 |
| XGBoost | 0.5686 | 0.1354 |

### Held-out test set

| Model | Accuracy | Precision | Recall | F1-score | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.5915 | 0.4000 | 0.0837 | 0.1384 | 0.5782 | 0.4483 |
| XGBoost | 0.5889 | 0.3333 | 0.0485 | 0.0846 | 0.4851 | 0.3829 |

The held-out test set contains 1,158 records: 704 normal and 454 anomalous. Although XGBoost achieved the higher mean grouped cross-validation PR-AUC, its held-out test recall for the anomalous class was low (0.0485). Random Forest's anomalous-class recall was also low (0.0837). These results indicate that the models, at the saved default decision settings, miss many anomalous records. **Do not interpret the accuracy score alone as evidence that the classifier is effective for incident detection.** Further validation, threshold analysis, and improvement of anomalous-event recall are needed before operational use.

Results can vary if the dataset, library versions, split, parameters, or saved artifacts change.

## Requirements

- Python 3.10 or later is recommended for the web application.
- Flask
- pandas
- NumPy
- scikit-learn
- XGBoost
- joblib

The application's `requirements.txt` lists these dependencies. Compatible package versions with those used to train the saved model are recommended, particularly for scikit-learn and XGBoost.

## Installation and setup

1. Extract `securetrack_security_incident_web_app.zip`.
2. Open a terminal in the extracted `securetrack_security_incident_web_app` directory.
3. Create and activate a virtual environment.

**Windows (Command Prompt):**

```bat
python -m venv .venv
.venv\Scripts\activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

4. Install the dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

5. Check that the three model artifacts are present beside `app.py`:

```text
best_security_event_classifier.pkl
security_model_features.pkl
security_model_metadata.pkl
```

The supplied ZIP archive already includes these artifacts. If you retrain the model, replace them with the matching files exported by the notebook.

## Running the application

From the application directory, run:

```bash
python app.py
```

Open this address in a browser:

```text
http://127.0.0.1:5000
```

The app initializes its SQLite tables when run as a script. Keep the development server local; do not expose it directly to the public internet.

To stop the server, press `Ctrl+C` in the terminal.

## Using SecureTrack

1. **Dashboard:** review the current incident and threat-indicator counts.
2. **Report Incident:** enter the required title, reporter, event date/time, activity, and description. Choose the reported severity and submit the form.
3. **Review classification:** the app stores the model's predicted class and estimated anomaly probability with the incident.
4. **Incident Reports:** browse saved reports and open a report to view its details.
5. **Update status:** change the response status to `Open`, `In Progress`, or `Resolved`.
6. **Threat Intelligence:** add an indicator with its type and threat/campaign name. Source, confidence, and notes can also be recorded. Existing entries can be deleted.
7. **Health check:** visit `http://127.0.0.1:5000/health`. The JSON response includes the application status, whether the model is loaded, and the model name recorded in its metadata.

## Application routes

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard |
| `/incidents` | GET | List incident reports |
| `/incidents/new` | GET, POST | Display and submit an incident report |
| `/incidents/<incident_id>` | GET, POST | View an incident and update its response status |
| `/threat-intel` | GET, POST | List and add threat-intelligence entries |
| `/threat-intel/<item_id>/delete` | POST | Delete a threat-intelligence entry |
| `/health` | GET | Return application/model status as JSON |

## Model artifacts

The notebook exports these model files:

- `best_security_event_classifier.pkl`
- `security_model_features.pkl`
- `security_model_metadata.pkl`

It also exports evaluation files such as:

- `model_comparison_results.csv`
- `cross_validation_results.csv`
- `best_model_feature_importance.csv` (when feature importance is available)

The supplied `cert_preprocessed_ml_comparison.csv` is the input dataset, not the model-comparison output CSV. Keep the input data, notebook outputs, and exported model artifacts clearly distinguished.

The Flask application constructs model input from the submitted **activity** and event timestamp. It derives the same six time-related fields described above and aligns the row to the feature names stored in `security_model_features.pkl`. The saved pipeline includes preprocessing, so the application passes the raw feature row to that pipeline.

