import argparse
import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pypdf import PdfReader
from pypdf.errors import PdfReadError


VULNERABLE_FAMILIES = {"RSA", "ECC", "DSA", "DH"}
LEGACY_INSECURE = {"MD5", "3DES", "RC4"}
BRANDING_LINES = [
    "Sponsored by CREIGNIFICENT LLC",
    "Terrence (Tc.) Creig",
    "AI Engineer | Cybersecurity Student | AI Agent Architect | Founder, CREIGNIFICENT LLC",
    "© 2026 CREIGNIFICENT LLC. All Rights Reserved.",
]

ALGORITHM_PATTERNS: dict[str, list[str]] = {
    "RSA": [r"\bRSA\b", r"\bRSASSA\b", r"\bRSA[-\s]?PSS\b", r"\bRSA[-\s]?OAEP\b"],
    "ECC": [r"\bECC\b", r"\belliptic\s+curve\b", r"\bECIES\b"],
    "ECDSA": [r"\bECDSA\b"],
    "ECDH": [r"\bECDH\b"],
    "Curve25519": [r"\bCurve25519\b", r"\bX25519\b"],
    "secp256r1": [r"\bsecp256r1\b", r"\bprime256v1\b", r"\bP-256\b"],
    "secp384r1": [r"\bsecp384r1\b", r"\bP-384\b"],
    "DSA": [r"\bDSA\b", r"\bDSS\b"],
    "Diffie-Hellman / DH": [r"\bDiffie[-\s]?Hellman\b", r"\bDH\b"],
    "AES": [r"\bAES\b", r"\bAES[-\s]?(128|192|256)\b"],
    "SHA": [r"\bSHA\b", r"\bSHA[-\s]?(1|2|224|256|384|512|3)\b"],
    "MD5": [r"\bMD5\b"],
    "3DES": [r"\b3DES\b", r"\bTriple\s+DES\b", r"\bTDEA\b"],
    "RC4": [r"\bRC4\b", r"\bARC4\b"],
}

QUANTUM_VULNERABLE_ALGORITHMS = {
    "RSA",
    "ECC",
    "ECDSA",
    "ECDH",
    "Curve25519",
    "secp256r1",
    "secp384r1",
    "DSA",
    "Diffie-Hellman / DH",
}

NOTES = {
    "RSA": "Public-key algorithm vulnerable to cryptographically relevant quantum computers via Shor's algorithm.",
    "ECC": "Elliptic-curve cryptography is quantum-vulnerable and should be migrated to PQC or hybrid designs.",
    "ECDSA": "Elliptic-curve signature scheme; prioritize migration to ML-DSA or SLH-DSA based designs.",
    "ECDH": "Elliptic-curve key agreement; prioritize migration to ML-KEM or hybrid key establishment.",
    "Curve25519": "Curve-based key agreement/signature usage is quantum-vulnerable.",
    "secp256r1": "NIST P-256 curve usage is quantum-vulnerable.",
    "secp384r1": "NIST P-384 curve usage is quantum-vulnerable.",
    "DSA": "Discrete-log signature scheme vulnerable to quantum attacks.",
    "Diffie-Hellman / DH": "Finite-field Diffie-Hellman is quantum-vulnerable and should be migrated.",
    "AES": "Symmetric encryption is not directly broken by Shor's algorithm; review key sizes and prefer AES-256 for long-lived confidentiality.",
    "SHA": "Hash functions are not directly broken by Shor's algorithm; review digest lengths and collision resistance requirements.",
    "MD5": "Legacy insecure hash function; replace immediately.",
    "3DES": "Legacy block cipher; replace immediately with modern authenticated encryption.",
    "RC4": "Legacy stream cipher with known weaknesses; replace immediately.",
}


def extract_text_from_pdf(pdf_path: Path) -> str:
    try:
        reader = PdfReader(str(pdf_path))
    except PdfReadError as exc:
        raise ValueError("The PDF could not be read. Please upload a valid, unencrypted PDF.") from exc

    if reader.is_encrypted:
        raise ValueError("Encrypted PDFs are not supported. Please upload an unencrypted text-based PDF.")

    pages = []
    for page in reader.pages:
        pages.append(page.extract_text() or "")
    return "\n".join(pages).strip()


def _count_algorithm_occurrences(text: str) -> Counter:
    counts: Counter[str] = Counter()
    for algorithm, patterns in ALGORITHM_PATTERNS.items():
        matched_spans = []
        for pattern in patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                matched_spans.append(match.span())

        unique_spans = []
        for start, end in sorted(matched_spans, key=lambda span: (span[0], -(span[1] - span[0]))):
            if any(start >= kept_start and end <= kept_end for kept_start, kept_end in unique_spans):
                continue
            unique_spans.append((start, end))

        if unique_spans:
            counts[algorithm] = len(unique_spans)
    return counts


def _risk_for_algorithm(algorithm: str) -> str:
    if algorithm in QUANTUM_VULNERABLE_ALGORITHMS:
        return "Critical"
    if algorithm in LEGACY_INSECURE:
        return "High"
    return "Moderate"


def _score_findings(counts: Counter) -> tuple[int, int]:
    score = 0
    for algorithm, occurrences in counts.items():
        capped_occurrences = min(occurrences, 10)
        if algorithm in QUANTUM_VULNERABLE_ALGORITHMS:
            score += 18 + capped_occurrences * 3
        elif algorithm in LEGACY_INSECURE:
            score += 12 + capped_occurrences * 2
        elif algorithm == "AES":
            score += 3
        elif algorithm == "SHA":
            score += 4
    risk_score = min(score, 100)
    quantum_readiness = max(0, 100 - risk_score)
    return risk_score, quantum_readiness


def generate_recommendations(counts: Counter) -> list[str]:
    recommendations = [
        "Inventory all cryptographic assets, protocols, certificates, libraries, and key-management dependencies.",
        "Review NIST PQC standards and migration guidance, including FIPS 203, FIPS 204, and FIPS 205.",
    ]

    if any(algorithm in QUANTUM_VULNERABLE_ALGORITHMS for algorithm in counts):
        recommendations.extend(
            [
                "Prioritize RSA, ECC, DH, and DSA migration for systems protecting long-lived or sensitive data.",
                "Test hybrid PQC deployment for key establishment and signatures before production cutover.",
            ]
        )

    if any(algorithm in LEGACY_INSECURE for algorithm in counts):
        recommendations.append("Replace MD5, RC4, and 3DES immediately wherever they are found.")

    if "AES" in counts:
        recommendations.append("Validate symmetric encryption strength and prefer AES-256 for long-term confidentiality.")

    if "SHA" in counts:
        recommendations.append("Review SHA usage and phase out SHA-1 in favor of SHA-256, SHA-384, SHA-512, or SHA-3 as appropriate.")

    if not counts:
        recommendations.append("No tracked cryptographic algorithms were found in the extracted text; verify the document scope and scan related architecture artifacts.")

    return recommendations


def analyze_text(text: str, document_name: str) -> dict[str, Any]:
    counts = _count_algorithm_occurrences(text)
    risk_score, quantum_readiness = _score_findings(counts)

    detailed_findings = [
        {
            "algorithm": algorithm,
            "occurrences": occurrences,
            "quantum_risk": _risk_for_algorithm(algorithm),
            "notes": NOTES[algorithm],
        }
        for algorithm, occurrences in sorted(counts.items())
    ]

    vulnerable_algorithms = [
        algorithm for algorithm in counts if algorithm in QUANTUM_VULNERABLE_ALGORITHMS
    ]

    return {
        "document_name": document_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "quantum_readiness": quantum_readiness,
        "total_findings": sum(counts.values()),
        "critical_findings": sum(
            occurrences
            for algorithm, occurrences in counts.items()
            if algorithm in QUANTUM_VULNERABLE_ALGORITHMS
        ),
        "vulnerable_algorithms": sorted(vulnerable_algorithms),
        "detailed_findings": detailed_findings,
        "recommendations": generate_recommendations(counts),
    }


def analyze_pdf(
    pdf_path: str | Path,
    report_dir: str | Path = "reports",
    document_name: str | None = None,
) -> dict[str, Any]:
    pdf_path = Path(pdf_path)
    report_dir = Path(report_dir)
    report_dir.mkdir(exist_ok=True)

    text = extract_text_from_pdf(pdf_path)
    if not text:
        raise ValueError(
            "No readable text could be extracted from this PDF. Please upload a text-based PDF, not a scanned image PDF."
        )

    result = analyze_text(text, document_name or pdf_path.name)
    report_paths = export_reports(result, report_dir)
    return {**result, "report_paths": report_paths}


def export_reports(result: dict[str, Any], report_dir: Path) -> dict[str, str]:
    stem = f"{Path(result['document_name']).stem}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    json_path = report_dir / f"{stem}.json"
    markdown_path = report_dir / f"{stem}.md"
    html_path = report_dir / f"{stem}.html"

    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(result), encoding="utf-8")
    html_path.write_text(render_html_report(result), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(markdown_path),
        "html": str(html_path),
    }


def render_markdown_report(result: dict[str, Any]) -> str:
    findings = "\n".join(
        f"| {item['algorithm']} | {item['occurrences']} | {item['quantum_risk']} | {item['notes']} |"
        for item in result["detailed_findings"]
    ) or "| None found | 0 | None | No tracked cryptographic algorithms were found. |"

    recommendations = "\n".join(f"- {item}" for item in result["recommendations"])

    return f"""# PQC Migration Assessment Report

Date: {result['timestamp']}

Document name: {result['document_name']}

Risk score: {result['risk_score']}/100

Quantum readiness: {result['quantum_readiness']}%

Critical findings: {result['critical_findings']}

## Algorithm Findings

| Algorithm | Occurrences | Quantum Risk | Notes |
| --- | ---: | --- | --- |
{findings}

## Recommendations

{recommendations}

---

**{BRANDING_LINES[0]}**  
**{BRANDING_LINES[1]}**  
**{BRANDING_LINES[2]}**  
**{BRANDING_LINES[3]}**
"""


def render_html_report(result: dict[str, Any]) -> str:
    rows = "\n".join(
        f"<tr><td>{html.escape(item['algorithm'])}</td><td>{item['occurrences']}</td><td>{html.escape(item['quantum_risk'])}</td><td>{html.escape(item['notes'])}</td></tr>"
        for item in result["detailed_findings"]
    ) or "<tr><td>None found</td><td>0</td><td>None</td><td>No tracked cryptographic algorithms were found.</td></tr>"

    recommendations = "\n".join(
        f"<li>{html.escape(item)}</li>" for item in result["recommendations"]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PQC Migration Assessment Report</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding-bottom: 112px; font-family: Arial, sans-serif; color: #eaf7ff; background: radial-gradient(circle at 18% 8%, rgba(120,247,255,.13), transparent 25rem), radial-gradient(circle at 88% 0%, rgba(140,108,255,.14), transparent 26rem), #080b18; }}
    main {{ max-width: 1040px; margin: 0 auto; padding: 40px 20px; }}
    h1, h2 {{ color: #78f7ff; letter-spacing: 0; }}
    h1 {{ margin: 0 0 18px; font-size: clamp(32px, 6vw, 56px); line-height: 1; }}
    .panel {{ border: 1px solid rgba(120, 247, 255, .24); background: rgba(255,255,255,.06); border-radius: 8px; padding: 22px; margin: 18px 0; box-shadow: 0 0 36px rgba(120, 80, 255, .16); }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
    .metric {{ background: rgba(9, 17, 36, .86); border-left: 3px solid #8c6cff; padding: 16px; }}
    .value {{ font-size: 30px; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; border-bottom: 1px solid rgba(255,255,255,.12); padding: 12px; vertical-align: top; }}
    th {{ color: #9ffcff; }}
    li {{ margin: 10px 0; }}
    .brand-footer {{ position: fixed; right: 0; bottom: 0; left: 0; display: grid; gap: 3px; padding: 12px 18px; border-top: 1px solid rgba(120,247,255,.18); background: rgba(5, 7, 17, .94); color: rgba(234,247,255,.78); font-size: 12px; line-height: 1.25; text-align: center; }}
    .brand-footer strong {{ color: rgba(120,247,255,.92); }}
    @media print {{
      body {{ padding-bottom: 120px; background: #080b18 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      main {{ padding: 28px 16px; }}
      .panel {{ box-shadow: none; break-inside: avoid; }}
      .brand-footer {{ position: fixed; bottom: 0; }}
    }}
    @media (max-width: 680px) {{
      body {{ padding-bottom: 150px; }}
      main {{ padding: 28px 14px; }}
      th, td {{ padding: 10px 8px; }}
    }}
  </style>
</head>
<body>
<main>
  <h1>PQC Migration Assessment Report</h1>
  <section class="panel metrics">
    <div class="metric"><div>Document</div><div class="value">{html.escape(result['document_name'])}</div></div>
    <div class="metric"><div>Risk Score</div><div class="value">{result['risk_score']}/100</div></div>
    <div class="metric"><div>Quantum Readiness</div><div class="value">{result['quantum_readiness']}%</div></div>
    <div class="metric"><div>Critical Findings</div><div class="value">{result['critical_findings']}</div></div>
  </section>
  <section class="panel">
    <h2>Algorithm Findings</h2>
    <table>
      <thead><tr><th>Algorithm</th><th>Occurrences</th><th>Quantum Risk</th><th>Notes</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <section class="panel">
    <h2>Recommendations</h2>
    <ul>{recommendations}</ul>
  </section>
  <p>Generated {html.escape(result['timestamp'])}</p>
</main>
<footer class="brand-footer">
  <strong>{html.escape(BRANDING_LINES[0])}</strong>
  <span>{html.escape(BRANDING_LINES[1])}</span>
  <span>{html.escape(BRANDING_LINES[2])}</span>
  <span>{html.escape(BRANDING_LINES[3])}</span>
</footer>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a PDF for post-quantum cryptography migration risk.")
    parser.add_argument("--input", required=True, help="Path to the PDF document to analyze.")
    parser.add_argument("--reports", default="reports", help="Directory where reports should be written.")
    args = parser.parse_args()

    result = analyze_pdf(args.input, args.reports)
    print(json.dumps({key: value for key, value in result.items() if key != "report_paths"}, indent=2))
    print("\nReports:")
    for report_type, path in result["report_paths"].items():
        print(f"- {report_type}: {path}")


if __name__ == "__main__":
    main()
