const analyzeButton = document.querySelector("#analyze");
const exportButton = document.querySelector("#export");
const statusMessage = document.querySelector("#status");
const resultSection = document.querySelector("#result");
const riskHeading = document.querySelector("#risk");
const reasonsList = document.querySelector("#reasons");
const suggestionsList = document.querySelector("#suggestions");
const limitationsList = document.querySelector("#limitations");
const linksList = document.querySelector("#links");

let latestReport;

analyzeButton.addEventListener("click", async () => {
  analyzeButton.disabled = true;
  exportButton.disabled = true;
  statusMessage.textContent = "Analyzing the selected message…";
  resultSection.hidden = true;
  latestReport = undefined;

  try {
    const response = await chrome.runtime.sendMessage({ type: "ANALYZE_SELECTION" });
    if (!response?.ok) {
      throw new Error(response?.error || "Analysis could not be completed.");
    }

    latestReport = {
      schemaVersion: 1,
      platform: response.result.platform,
      analyzedAt: new Date().toISOString(),
      messageText: response.result.messageText,
      ...response.result.result,
    };

    renderList(reasonsList, latestReport.reasons);
    renderList(suggestionsList, latestReport.suggestions);
    renderList(limitationsList, latestReport.limitations);
    renderLinks(linksList, latestReport.links);
    riskHeading.textContent = `${latestReport.riskLevel} risk`;
    riskHeading.dataset.level = latestReport.riskLevel;
    resultSection.hidden = false;
    statusMessage.textContent = "";
    exportButton.disabled = false;
  } catch (error) {
    statusMessage.textContent = error instanceof Error
      ? error.message
      : "Analysis could not be completed.";
  } finally {
    analyzeButton.disabled = false;
  }
});

exportButton.addEventListener("click", () => {
  if (!latestReport) {
    return;
  }

  const report = new Blob([JSON.stringify(latestReport, null, 2)], {
    type: "application/json",
  });
  const downloadUrl = URL.createObjectURL(report);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = `phishshield-report-${new Date().toISOString().replaceAll(":", "-")}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(downloadUrl), 1_000);
});

function renderList(list, items) {
  list.replaceChildren();
  for (const item of items) {
    const entry = document.createElement("li");
    entry.textContent = typeof item === "string" ? item : item.message;
    list.append(entry);
  }
}

function renderLinks(list, links) {
  list.replaceChildren();
  for (const link of links) {
    const entry = document.createElement("li");
    const signals = link.signals.map(describeLinkSignal);
    entry.textContent = signals.length
      ? `${link.host}: ${signals.join("; ")}`
      : `${link.host}: no URL-format warning detected; this does not mean the site is safe.`;
    list.append(entry);
  }
  list.hidden = links.length === 0;
}

function describeLinkSignal(signal) {
  const descriptions = {
    embedded_credentials: "text before the host may obscure the destination",
    punycode_hostname: "encoded internationalized hostname",
    ip_address_host: "numeric IP address used as the host",
    unencrypted_http: "unencrypted HTTP connection",
  };
  return descriptions[signal] || "unrecognized URL signal";
}
