// Background service worker for PhishGuard AI

chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard AI installed');
});

// Listen for tab updates to potentially warn users
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // You can add automatic scanning logic here if needed
    // For now, scanning happens on-demand when user clicks extension
  }
});

// Handle messages from content script or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeUrl') {
    // This can be used for background analysis
    sendResponse({ success: true });
  }
  return true;
});