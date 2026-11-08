# CyberShield — Intelligent Integrated Cyber Defense System

A defensive security analytics MVP built with Python and Streamlit.

## Features
- Built-in sample security events or CSV upload
- Explainable rules for failed logins, outbound data volume, and selected destination ports
- Low / Medium / High risk classification and 0–100 prioritisation score
- Dashboard, event inspection, and downloadable CSV report

## Run locally
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Create a public GitHub repository named `cybershield`.
2. Upload `app.py`, `requirements.txt`, and `README.md` to its root.
3. Go to https://share.streamlit.io/ and sign in with GitHub.
4. Choose New app, repository, branch `main`, and main file `app.py`.
5. Deploy.

## CSV format
Required: `timestamp`, `source_ip`, `event_type`
Optional numeric: `failed_logins`, `bytes_out`, `destination_port`

## Safety and limitations
This is an educational defensive prototype. It analyses supplied records only; it does not perform live network monitoring, scanning, blocking, or automated response. Thresholds are illustrative and must be validated. A risk score is not proof of malicious activity.
