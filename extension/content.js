chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "GET_SELECTED_MESSAGE") {
    return false;
  }

  const messageText = window.getSelection()?.toString().trim() ?? "";
  sendResponse({ messageText });
  return false;
});
