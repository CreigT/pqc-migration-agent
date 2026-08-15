# PQC Migration Agent

A local Python agent and web interface for **post-quantum cryptography migration discovery**. It scans PDF, DOCX, and TXT files, extracts real document text, detects vulnerable or migration-relevant cryptography references, and produces JSON and Markdown reports.

The project is designed around evidence rather than simulated findings: reported results come from parsed document content and explicit detection rules.

## Why It Matters

Organizations preparing for post-quantum cryptography need to understand where legacy cryptographic algorithms and weak key sizes appear in documentation, inventories, standards, and migration plans. This agent provides an initial discovery layer that can help identify material requiring deeper technical validation.

## Capabilities

- Cybersecurity-themed document analyzer UI
- Drag-and-drop PDF, DOCX, and TXT uploads
- PDF parsing with `pdfplumber`
- Word document parsing with `python-docx`
- Plain-text parsing
- Detection of RSA, DSA, ECC, ECDSA, ECDH, weak Diffie-Hellman, SHA-1, MD5, DES, 3DES, and RC4 references
- Detection of weak key-size references such as RSA-1024 and RSA-1536
- Risk levels, evidence excerpts, locations, and detailed findings
- JSON report downloads
- Markdown migration summaries
- CLI workflow for batch or CI-oriented scanning
- SHA-256 file hashing in generated reports

## Project Structure

```text
app.py                 FastAPI web application
requirements.txt       Python dependencies
src/main.py            Core PQC detection engine and CLI
web/index.html         Landing page and analyzer interface
web/static/app.js      Browser upload, analysis, and download behavior
web/static/styles.css  Responsive cybersecurity-themed styling
```

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

## Run the Web App

```bash
python app.py
```

Open `http://127.0.0.1:8000` and upload a supported document. The application sends the file to `/analyze`, runs the detection engine, and returns JSON and Markdown report content.

## Deploy to Vercel

The repository includes `vercel.json` for the FastAPI entrypoint `app.py`.

Connect the repository to Vercel, keep the project root at the repository root, and deploy the `main` branch.

Hosted uploads are capped at 4 MB due to the deployment model. For larger inventories, use the local CLI or divide the source material into smaller documents.

Command-line deployment is also possible:

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

The endpoint returns a structured report object and Markdown migration summary.

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

Print the Markdown summary:

```bash
python src/main.py path/to/document.txt --print-summary
```

## Output

The CLI writes:

- `<target>.pqc_report.json`
- `<target>.pqc_summary.md`

Reports can include:

- Agent metadata
- Target and processing status
- SHA-256 file hashes
- File sizes and modified timestamps
- Parsed block counts
- Finding counts by risk
- Per-document findings
- Evidence excerpts and document locations
- Migration or replacement recommendations

## Evidence and Validation Policy

This agent reports findings produced from parsed document text and explicit rules. It does not create synthetic asset inventories or pretend that document references prove the configuration of a live production system.

Findings must be validated against authoritative source systems such as application code, cryptographic libraries, certificates, HSM configuration, network devices, infrastructure configuration, and runtime environments before remediation decisions are made.

## Security and Privacy

Documents may contain sensitive technical or organizational information. Prefer local execution for confidential material unless the hosted deployment and its data-handling characteristics have been reviewed and approved for that material.

Do not commit uploaded documents, generated confidential reports, API credentials, or production secrets to the repository.

## Project Status

**Active cybersecurity / AI portfolio project.**

This project demonstrates document analysis, evidence-based security discovery, migration planning, FastAPI development, and responsible handling of AI/security findings.

---

**Sponsored by CREIGNIFICENT LLC.**
