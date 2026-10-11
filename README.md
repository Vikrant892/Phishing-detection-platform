---
title: Phishing Detection Platform
emoji: 🎣
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 7860
pinned: false
short_description: Email phishing analysis (Flask + SQLite + ML rules)
---

# Phishing Detection Platform

A Flask application for inspecting email headers, HTML content, links, and suspicious patterns. Upload sample email files or submit text for analysis, then inspect the findings in the dashboard.

## Current demo architecture

The Docker demo uses Flask, SQLite, pandas, and scikit-learn. `python/simple_app.py` is the application entry point and `python/database_schema.py` manages the current SQLite database. Older implementations are retained separately.

[Hugging Face Space](https://huggingface.co/spaces/vikrant892/phishing-detection-platform). The demo is currently paused under the account's free hosting quota; source and local setup remain available.

The hosted SQLite database is ephemeral unless persistent storage is configured. Do not rely on a public demo to retain analysis records.

## Run locally

Use Python 3.11, matching the Docker image.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r python/requirements.txt
cd python
python simple_app.py
```

Open http://localhost:5000. The application creates its SQLite database when it starts; PostgreSQL is not required for this entry point. Set `SQLITE_PATH` to select the database location.

## Run with Docker

```bash
docker build -t phishing-detection-platform .
docker run --rm -p 7860:7860 phishing-detection-platform
```

Open http://localhost:7860.

## Documentation and samples

- [Original technical documentation](README.original.md): describes the earlier PostgreSQL implementation. Its PostgreSQL setup instructions do not apply to the current SQLite demo.
- `test_phishing_email.eml`, `test_safe_email.eml`, and `test_enhanced_phishing_email.eml`: sample inputs
- `python/email_html_analyzer.py`: email content analysis
- `python/database_schema.py`: current database layer
- `Dockerfile`: current demo runtime

Use sample messages when trying the public demo; uploaded email can contain personal or sensitive information.

## License

The current repository is licensed under [MIT](LICENSE). The original README is retained as historical documentation.
