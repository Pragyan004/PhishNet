// Content script for PhishGuard AI
// This runs on every webpage and can be used for real-time monitoring

// Get current page URL
const currentUrl = window.location.href;

// Listen for messages from popup or background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getPageInfo') {
    sendResponse({
      url: currentUrl,
      title: document.title,
      hasLoginForm: checkForLoginForm()
    });
  }
  return true;
});

// Check if page has login forms (indicator of phishing)
function checkForLoginForm() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const emailInputs = document.querySelectorAll('input[type="email"]');
  return passwordInputs.length > 0 || emailInputs.length > 0;
}

// Optional: Add visual indicator on page if dangerous
function addWarningBanner(message) {
  // Create warning banner
  const banner = document.createElement('div');
  banner.id = 'phishguard-warning';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: linear-gradient(135deg, #ef4444, #dc2626);
    color: white;
    padding: 15px;
    text-align: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    font-weight: 600;
    z-index: 999999;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
  `;
  banner.innerHTML = `
    🚨 ${message}
    <button id="phishguard-dismiss" style="
      margin-left: 15px;
      padding: 5px 12px;
      background: white;
      color: #ef4444;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 600;
    ">Dismiss</button>
  `;
  
  document.body.insertBefore(banner, document.body.firstChild);
  
  // Add dismiss functionality
  document.getElementById('phishguard-dismiss').addEventListener('click', () => {
    banner.remove();
  });
}

// Example: Listen for potential phishing warnings from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showWarning') {
    addWarningBanner(request.message);
  }
});