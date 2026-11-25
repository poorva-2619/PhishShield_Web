const API_URL = "http://127.0.0.1:8000/api/v1/analyze";
const MAX_MESSAGE_LENGTH = 10_000;
const REQUEST_TIMEOUT_MS = 15_000;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "ANALYZE_SELECTION") {
    return false;
  }

  analyzeSelection()
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => {
      sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : "Analysis could not be completed.",
      });
    });

  return true;
});

async function analyzeSelection() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const platform = getSupportedPlatform(tab?.url);
  if (!tab?.id || !platform) {
    throw new Error("Open WhatsApp Web, Telegram Web, Gmail, or Outlook on the web and select text before analyzing.");
  }

  let selection;
  try {
    selection = await chrome.tabs.sendMessage(tab.id, { type: "GET_SELECTED_MESSAGE" });
  } catch {
    throw new Error("Could not read the selection. Reload the current web page and try again.");
  }

  const messageText = selection?.messageText;
  if (typeof messageText !== "string" || messageText.length === 0) {
    throw new Error("Select the text of one message or email first.");
  }
  if (messageText.length > MAX_MESSAGE_LENGTH) {
    throw new Error("The selected text is too long. Select a single message of at most 10,000 characters.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaVersion: 1,
        platform,
        messageText,
      }),
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("Analysis timed out. Check that the local PhishShield backend is running.");
    }
    throw new Error("Could not reach the PhishShield backend. Check that it is running locally.");
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    if (response.status === 413 || response.status === 422) {
      throw new Error("The backend rejected the selected message. Select a shorter message and try again.");
    }
    throw new Error("The backend could not analyze this message. Try again later.");
  }

  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error("The backend returned an invalid response.");
  }

  if (
    !["low", "medium", "high"].includes(result?.riskLevel)
    || !Array.isArray(result?.reasons)
    || !Array.isArray(result?.suggestions)
    || !Array.isArray(result?.limitations)
    || !Array.isArray(result?.links)
  ) {
    throw new Error("The backend returned an invalid response.");
  }

  return { platform, messageText, result };
}

function getSupportedPlatform(tabUrl) {
  if (typeof tabUrl !== "string") {
    return undefined;
  }

  let hostname;
  try {
    hostname = new URL(tabUrl).hostname.toLowerCase();
  } catch {
    return undefined;
  }

  if (hostname === "web.whatsapp.com") {
    return "whatsapp_web";
  }
  if (hostname === "web.telegram.org") {
    return "telegram_web";
  }
  if (hostname === "mail.google.com") {
    return "gmail_web";
  }
  if (
    hostname === "outlook.live.com"
    || hostname === "outlook.office.com"
    || hostname === "outlook.office365.com"
  ) {
    return "outlook_web";
  }

  return undefined;
}
