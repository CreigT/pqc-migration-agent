# pqc-migration-agent

A simple full-stack Post-Quantum Cryptography migration dashboard. Upload a text-based PDF, run analysis, and download JSON, Markdown, or HTML reports generated from the extracted document text.

## Install and run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app:app --reload
```

On macOS or Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000 in your browser.

## Command-line use

```bash
python pqc_agent.py --input sample.pdf
```

Reports are written to `reports/` by default.

## How it works

- FastAPI serves the dashboard and accepts PDF uploads at `POST /analyze`.
- Uploaded PDFs are saved temporarily in `uploads/`.
- `pqc_agent.py` extracts text with `pypdf`, scans for known cryptographic algorithms, scores quantum migration risk, and writes reports to `reports/`.
- The frontend starts empty and only renders gauges, tables, recommendations, and download links after real backend analysis succeeds.

## Limitations and next improvements

- Scanned image PDFs are not OCR processed. If no readable text is extracted, the app returns a clear error.
- Download routes serve the latest report generated during the current server process.
- This is keyword-based analysis, not a full cryptographic bill-of-materials parser.
- A future version could add OCR, per-session report IDs, richer context extraction, and certificate or source-code scanning.
