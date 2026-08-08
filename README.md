# PQC Migration Agent

A local Python agent and web interface for post-quantum cryptography migration
discovery. It scans PDF, DOCX, and TXT files, extracts real document text,
detects vulnerable or migration-relevant cryptography references, and writes JSON
and Markdown reports.

The agent does not use mock data, fake scores, or synthetic findings. Reported
findings come from parsed document content and explicit detection rules.

## Capabilities

- Modern cybersecurity-themed landing page and document analyzer UI
- Drag-and-drop upload for PDF, DOCX, and TXT documents
- Parse PDF files with `pdfplumber`
- Parse Word `.docx` files with `python-docx`
- Parse text files with built-in Python file handling
- Detect RSA, DSA, ECC, ECDSA, ECDH, weak Diffie-Hellman, SHA-1, MD5, DES, 3DES, and RC4
- Detect weak key-size references such as RSA-1024 and RSA-1536
- Display summary cards, risk levels, locations, evidence excerpts, and detailed findings
- Download machine-readable JSON reports and Markdown migration summaries
- Keep the original CLI workflow available for batch or CI use

## Project Structure

```text
app.py                 FastAPI web application
requirements.txt      Python dependencies for the web app and analyzer
src/main.py           Core PQC detection engine and CLI
web/index.html        Landing page and analyzer interface
web/static/app.js     Browser-side upload, analysis, and download behavior
web/static/styles.css Cybersecurity-themed responsive styling
```

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS or Linux, activate the environment with:

```bash
source .venv/bin/activate
```

## Run the Web App

```bash
python app.py
```

Open:

```text
http://127.0.0.1:8000
```

Use the analyzer section to upload a `.pdf`, `.docx`, or `.txt` document. The web
app sends the file to `/analyze`, runs the existing Python migration agent, and
returns real JSON and Markdown report content for download.

## Deploy to Vercel

This repository includes `vercel.json` for the FastAPI entrypoint:

```text
app.py
```

Vercel will install `requirements.txt` and route traffic to the Python function.
Connect the public GitHub repository to Vercel, keep the project root set to the
repository root, and deploy the `main` branch.

Hosted uploads are capped at 4 MB because Vercel Functions enforce request body
limits. For larger document inventories, run the CLI locally or split documents
before uploading them through the hosted analyzer.

You can also deploy from the command line:

```bash
npm install -g vercel
vercel --prod
```

## API

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Analyze a document:

```bash
curl -X POST http://127.0.0.1:8000/analyze ^
  -F "file=@path/to/document.pdf"
```

The `/analyze` endpoint returns:

- `report`: structured JSON report object
- `markdown`: Markdown migration summary

## CLI Usage

Scan one file:

```bash
python src/main.py path/to/document.pdf --output-dir reports
```

Scan a directory recursively:

```bash
python src/main.py path/to/documents --recursive --output-dir reports
```

Fail when findings are present:

```bash
python src/main.py path/to/documents --recursive --output-dir reports --fail-on-findings
```

Print the Markdown summary to stdout:

```bash
python src/main.py path/to/document.txt --print-summary
```

## Output

The CLI writes:

- `<target>.pqc_report.json`
- `<target>.pqc_summary.md`

The web UI provides download buttons for the same report formats.

The JSON report includes:

- Agent metadata
- Target and processing status
- Real file SHA-256 hashes
- File sizes and modified timestamps
- Parsed block counts
- Finding counts by risk
- Per-document findings
- Evidence excerpts and document locations
- Recommendations for migration or replacement

## Evidence Policy

This agent reports only findings produced from parsed document text and explicit
rules. It does not create confidence scores, synthetic assets, fake inventory, or
mock outputs. Validate findings against source systems, libraries, certificates,
HSM configuration, and runtime configuration before production remediation.
