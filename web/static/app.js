const fileInput = document.querySelector("#fileInput");
const chooseFileButton = document.querySelector("#chooseFileButton");
const uploadZone = document.querySelector("#uploadForm");
const selectedFile = document.querySelector("#selectedFile");
const analyzeButton = document.querySelector("#analyzeButton");
const statusMessage = document.querySelector("#statusMessage");
const resultsPanel = document.querySelector("#resultsPanel");
const resultFileName = document.querySelector("#resultFileName");
const summaryGrid = document.querySelector("#summaryGrid");
const findingsBody = document.querySelector("#findingsBody");
const downloadJson = document.querySelector("#downloadJson");
const downloadMarkdown = document.querySelector("#downloadMarkdown");

let activeFile = null;
let latestJson = "";
let latestMarkdown = "";

const supportedExtensions = [".pdf", ".docx", ".txt"];

function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.classList.toggle("error", isError);
}

function fileExtension(fileName) {
  const index = fileName.lastIndexOf(".");
  return index >= 0 ? fileName.slice(index).toLowerCase() : "";
}

function setActiveFile(file) {
  if (!file) {
    activeFile = null;
    selectedFile.textContent = "No file selected";
    analyzeButton.disabled = true;
    return;
  }

  const extension = fileExtension(file.name);
  if (!supportedExtensions.includes(extension)) {
    setStatus("Unsupported file type. Choose a PDF, DOCX, or TXT document.", true);
    setActiveFile(null);
    return;
  }

  activeFile = file;
  selectedFile.textContent = `${file.name} (${formatBytes(file.size)})`;
  analyzeButton.disabled = false;
  setStatus("Ready to analyze.");
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function locationLabel(location) {
  const parts = [location.source_type || "document"];
  ["page", "line", "paragraph", "table", "row", "cell"].forEach((key) => {
    if (location[key] !== undefined) {
      parts.push(`${key} ${location[key]}`);
    }
  });
  return parts.join(", ");
}

function riskClass(risk) {
  return `risk-pill risk-${risk || "low"}`;
}

function makeCard(label, value, className = "") {
  const card = document.createElement("div");
  card.className = `summary-card ${className}`.trim();
  card.innerHTML = `<span class="summary-value">${value}</span><span class="summary-label">${label}</span>`;
  return card;
}

function renderResults(payload) {
  const report = payload.report;
  const summary = report.summary;
  const documentReport = report.documents[0];
  const findings = documentReport ? documentReport.findings : [];
  const counts = summary.risk_counts || {};

  latestJson = payload.json;
  latestMarkdown = payload.markdown;
  resultFileName.textContent = documentReport?.input?.file_name || activeFile?.name || "Document analysis";

  summaryGrid.replaceChildren(
    makeCard("Total findings", summary.total_findings || 0),
    makeCard("Critical", counts.critical || 0, "critical"),
    makeCard("High", counts.high || 0, "high"),
    makeCard("PQC relevant", summary.post_quantum_relevant_findings || 0, "pq")
  );

  findingsBody.replaceChildren();
  if (!findings.length) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="4" class="empty-row">No vulnerable or migration-relevant cryptography references were detected.</td>`;
    findingsBody.appendChild(row);
  } else {
    findings.forEach((finding) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><strong>${escapeHtml(finding.algorithm)}</strong><br><span class="muted">${escapeHtml(finding.category)}</span></td>
        <td><span class="${riskClass(finding.risk)}">${escapeHtml(finding.risk)}</span></td>
        <td>${escapeHtml(locationLabel(finding.location || {}))}</td>
        <td>${escapeHtml(finding.excerpt || "")}</td>
      `;
      findingsBody.appendChild(row);
    });
  }

  resultsPanel.hidden = false;
  resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function analyzeActiveFile() {
  if (!activeFile) return;

  const formData = new FormData();
  formData.append("file", activeFile);

  analyzeButton.disabled = true;
  setStatus("Analyzing document with the PQC migration engine...");

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      body: formData,
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Analysis failed.");
    }
    renderResults(data);
    setStatus("Analysis complete.");
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    analyzeButton.disabled = false;
  }
}

function downloadText(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

chooseFileButton.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => setActiveFile(fileInput.files[0]));
analyzeButton.addEventListener("click", analyzeActiveFile);

uploadZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  uploadZone.classList.add("is-dragging");
});

uploadZone.addEventListener("dragleave", () => {
  uploadZone.classList.remove("is-dragging");
});

uploadZone.addEventListener("drop", (event) => {
  event.preventDefault();
  uploadZone.classList.remove("is-dragging");
  setActiveFile(event.dataTransfer.files[0]);
});

downloadJson.addEventListener("click", () => {
  const baseName = activeFile ? activeFile.name.replace(/\.[^.]+$/, "") : "pqc-report";
  downloadText(`${baseName}.pqc_report.json`, latestJson, "application/json");
});

downloadMarkdown.addEventListener("click", () => {
  const baseName = activeFile ? activeFile.name.replace(/\.[^.]+$/, "") : "pqc-summary";
  downloadText(`${baseName}.pqc_summary.md`, latestMarkdown, "text/markdown");
});
