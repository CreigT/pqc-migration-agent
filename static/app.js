const form = document.querySelector("#analysis-form");
const fileInput = document.querySelector("#pdf-file");
const fileLabel = document.querySelector("#file-label");
const dropZone = document.querySelector("#drop-zone");
const loading = document.querySelector("#loading");
const loadingText = document.querySelector("#loading-text");
const errorBox = document.querySelector("#error-box");
const results = document.querySelector("#results");
const riskGauge = document.querySelector("#risk-gauge");
const riskScore = document.querySelector("#risk-score");
const riskLabel = document.querySelector("#risk-label");
const readinessGauge = document.querySelector("#readiness-gauge");
const readinessScore = document.querySelector("#readiness-score");
const summaryGrid = document.querySelector("#summary-grid");
const findingsBody = document.querySelector("#findings-body");
const recommendations = document.querySelector("#recommendations");

const loadingSteps = [
  "Extracting PDF text...",
  "Scanning cryptographic algorithms...",
  "Calculating quantum readiness...",
  "Generating migration report..."
];

let loadingTimer;

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError() {
  errorBox.textContent = "";
  errorBox.hidden = true;
}

function setLoading(isLoading) {
  loading.hidden = !isLoading;
  form.querySelector("button").disabled = isLoading;

  if (!isLoading) {
    clearInterval(loadingTimer);
    loadingText.textContent = loadingSteps[0];
    return;
  }

  let index = 0;
  loadingText.textContent = loadingSteps[index];
  loadingTimer = setInterval(() => {
    index = (index + 1) % loadingSteps.length;
    loadingText.textContent = loadingSteps[index];
  }, 1200);
}

function riskMeta(score) {
  if (score >= 70) {
    return { label: "High", color: "var(--danger)" };
  }
  if (score >= 40) {
    return { label: "Medium", color: "var(--medium)" };
  }
  return { label: "Low", color: "var(--low)" };
}

function renderSummary(data) {
  const vulnerable = data.vulnerable_algorithms.length
    ? data.vulnerable_algorithms.join(", ")
    : "None found";

  const cards = [
    ["Document name", data.document_name],
    ["Total findings", data.total_findings],
    ["Critical findings", data.critical_findings],
    ["Vulnerable algorithms", vulnerable],
    ["Timestamp", new Date(data.timestamp).toLocaleString()]
  ];

  summaryGrid.innerHTML = cards.map(([label, value]) => `
    <article class="glass summary-card">
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(value)}</strong>
    </article>
  `).join("");
}

function renderFindings(findings) {
  findingsBody.innerHTML = findings.length
    ? findings.map((item) => `
      <tr>
        <td>${escapeHTML(item.algorithm)}</td>
        <td>${escapeHTML(item.occurrences)}</td>
        <td>${escapeHTML(item.quantum_risk)}</td>
        <td>${escapeHTML(item.notes)}</td>
      </tr>
    `).join("")
    : `<tr>
        <td>None found</td>
        <td>0</td>
        <td>None</td>
        <td>No tracked cryptographic algorithms were found in the extracted text.</td>
      </tr>`;
}

function renderRecommendations(items) {
  recommendations.innerHTML = items.map((item) => `<li>${escapeHTML(item)}</li>`).join("");
}

function renderDownloads(links) {
  document.querySelector("#download-json").href = links.json;
  document.querySelector("#download-markdown").href = links.markdown;
  document.querySelector("#download-html").href = links.html;
}

function renderResults(data) {
  const meta = riskMeta(data.risk_score);

  riskGauge.style.setProperty("--value", data.risk_score);
  riskGauge.style.setProperty("--gauge-color", meta.color);
  riskScore.textContent = data.risk_score;
  riskLabel.textContent = meta.label;

  readinessGauge.style.setProperty("--value", data.quantum_readiness);
  readinessGauge.style.setProperty("--gauge-color", "var(--cyan)");
  readinessScore.textContent = `${data.quantum_readiness}%`;

  renderSummary(data);
  renderFindings(data.detailed_findings);
  renderRecommendations(data.recommendations);
  renderDownloads(data.download_links);
  results.hidden = false;
}

function updateFileLabel() {
  const file = fileInput.files[0];
  fileLabel.textContent = file ? file.name : "Drop a PDF here or choose a file";
}

fileInput.addEventListener("change", updateFileLabel);

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
});

dropZone.addEventListener("drop", (event) => {
  const file = event.dataTransfer.files[0];
  if (file) {
    fileInput.files = event.dataTransfer.files;
    updateFileLabel();
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  const file = fileInput.files[0];
  if (!file) {
    showError("Please upload a PDF file before running analysis.");
    return;
  }

  if (!file.name.toLowerCase().endsWith(".pdf")) {
    showError("Only PDF uploads are supported.");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  setLoading(true);

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      body: formData
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.detail || "Analysis failed.");
    }

    renderResults(payload);
  } catch (error) {
    results.hidden = true;
    showError(error.message);
  } finally {
    setLoading(false);
  }
});
