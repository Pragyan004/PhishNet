// === URL Feature Extractor === //
class URLFeatureExtractor {
  extractFeatures(url) {
    let f = {};
    try {
      const u = new URL(url);
      const domain = u.hostname;
      const path = u.pathname;

      f.url_length = url.length;
      f.domain_length = domain.length;
      f.path_length = path.length;
      f.num_dots = (url.match(/\./g) || []).length;
      f.num_slashes = (url.match(/\//g) || []).length;
      f.num_question = (url.match(/\?/g) || []).length;
      f.num_equal = (url.match(/=/g) || []).length;
      f.num_hyphens = (url.match(/-/g) || []).length;
      f.num_at = (url.match(/@/g) || []).length;
      f.num_and = (url.match(/&/g) || []).length;
      f.num_hash = (url.match(/#/g) || []).length;
      f.num_percent = (url.match(/%/g) || []).length;
      f.num_digits_url = (url.match(/\d/g) || []).length;
      f.num_letters_url = (url.match(/[a-zA-Z]/g) || []).length;

      f.https = u.protocol === "https:" ? 1 : 0;
      f.has_ip = /\d+\.\d+\.\d+\.\d+/.test(domain) ? 1 : 0;
      f.num_subdomains = Math.max(0, domain.split(".").length - 2);

      const suspiciousWords = ["login", "account", "secure", "update", "verify"];
      f.has_suspicious_words = suspiciousWords.some(w =>
        url.toLowerCase().includes(w)
      ) ? 1 : 0;

      const shortening = ["bit.ly", "goo.gl", "tinyurl", "t.co"];
      f.has_shortening = shortening.some(s =>
        domain.includes(s)
      ) ? 1 : 0;

      f.digit_ratio = url.length ? f.num_digits_url / url.length : 0;
      f.special_char_ratio = url.length
        ? (f.num_dots + f.num_hyphens + f.num_at) / url.length
        : 0;

    } catch (err) {
      console.error("Feature Extraction Failed:", err);
      return this.empty();
    }
    return f;
  }

  empty() {
    return {
      url_length: 0, domain_length: 0, path_length: 0,
      num_dots: 0, num_slashes: 0, num_question: 0,
      num_equal: 0, num_hyphens: 0, num_at: 0, num_and: 0,
      num_hash: 0, num_percent: 0, num_digits_url: 0,
      num_letters_url: 0, https: 0, has_ip: 0,
      num_subdomains: 0, has_suspicious_words: 0,
      has_shortening: 0, digit_ratio: 0, special_char_ratio: 0
    };
  }
}

// === Reputation / Heuristic Config === //
const TRUSTED_DOMAINS = [
  "google.com",
  "drive.google.com",
  "gmail.com",
  "youtube.com",
  "microsoft.com",
  "office.com",
  "live.com",
  "outlook.com",
  "github.com",
  "amazon.com",
  "flipkart.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
];

const SUSPICIOUS_TLDS = [
  "xyz", "top", "gq", "tk", "ml", "cf", "buzz",
  "click", "support", "loan", "cam", "rest"
];

const SHORTENER_DOMAINS = [
  "bit.ly",
  "goo.gl",
  "tinyurl.com",
  "t.co"
];


// === ONNX Phishing Detector === //
class PhishingDetector {
  constructor() {
    this.session = null;
    this.scaler = null;
    this.extractor = new URLFeatureExtractor();
    this.topDomains = new Set();
  }

  async initialize() {
    await this.loadScaler();
    await this.loadTopDomains();
    await this.loadModel();
  }

  async loadScaler() {
    const res = await fetch(chrome.runtime.getURL("model/scaler.json"));
    this.scaler = await res.json();
  }

  async loadTopDomains() {
    try {
      const res = await fetch(
        chrome.runtime.getURL("data/top_domains_small.json")
      );
      const arr = await res.json();
      this.topDomains = new Set(arr.map(d => d.toLowerCase()));
      console.log("Loaded top domains:", this.topDomains.size);
    } catch (e) {
      console.warn("Top domains JSON not found or failed to load:", e);
      this.topDomains = new Set();
    }
  }

  async loadModel() {
    this.session = await ort.InferenceSession.create(
      chrome.runtime.getURL("model/model.onnx"),
      { executionProviders: ['wasm'] }
    );
  }

  getDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  getTld(domain) {
    const parts = domain.split(".");
    return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
  }

  isSuspiciousTld(domain) {
    const tld = this.getTld(domain);
    return SUSPICIOUS_TLDS.includes(tld);
  }

  isTrustedDomain(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
  
    if (TRUSTED_DOMAINS.some(base => d === base || d.endsWith("." + base))) {
      return true;
    }
  
    for (const top of this.topDomains) {
      if (d === top || d.endsWith("." + top)) {
        return true;
      }
    }
  
    return false;
  }

  estimateDomainAgeScore(domain) {
    return this.topDomains.has(domain.toLowerCase()) ? 1.0 : 0.3;
  }

  scaleFeatures(f) {
    return this.scaler.feature_names.map(
      (key, i) => (f[key] - this.scaler.mean[i]) / this.scaler.scale[i]
    );
  }

  async predict(url) {
    const domain = this.getDomain(url);
    const features = this.extractor.extractFeatures(url);
    const scaled = this.scaleFeatures(features);

    const inputTensor = new ort.Tensor("float32", scaled, [1, scaled.length]);
    const output = await this.session.run({ input: inputTensor });

    let score = output.output.data[0];
    const baseScore = score;

    const https = url.startsWith("https");
    const suspiciousTld = this.isSuspiciousTld(domain);
    let trustedDomain = this.isTrustedDomain(domain);

    const isShortener = SHORTENER_DOMAINS.some(
      s => domain === s || domain.endsWith("." + s)
    );
    if (isShortener) {
      trustedDomain = false;
    }

    const ageScore = this.estimateDomainAgeScore(domain);

    if (trustedDomain) {
      score = Math.min(score, 0.15);
    } else {
      if (!https) score = Math.min(1, score + 0.08);
      if (suspiciousTld) score = Math.min(1, score + 0.10);
      if (ageScore < 0.5) score = Math.min(1, score + 0.05);
    }

    let isPhishing = !trustedDomain && score >= 0.7;

    if (isShortener && !trustedDomain) {
      isPhishing = true;
      score = Math.max(score, 0.85);
    }

    const confidence = Math.abs(score - 0.5) * 2;

    return {
      score,
      baseScore,
      isPhishing,
      confidence,
      features,
      domain,
      trustedDomain,
      suspiciousTld,
      https,
      ageScore,
      isShortener,
    };
  }
}


// === UI Handling === //
class PopupUI {
  constructor() {
    this.detector = new PhishingDetector();
    this.detailsVisible = false;
    this.currentUrl = "";
    this.currentResult = null;
  }

  async init() {
    try {
      document.getElementById("loading").classList.remove("hidden");
      document.getElementById("result").classList.add("hidden");
      document.getElementById("error").classList.add("hidden");

      await this.detector.initialize();
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentUrl = tabs[0].url;

      this.currentResult = await this.detector.predict(this.currentUrl);
      this.displayResult(this.currentResult, this.currentUrl);
      this.setupEventListeners();
    } catch (error) {
      this.showError(error.message);
    }
  }

  setupEventListeners() {
    // Toggle details button
    const toggleBtn = document.getElementById("toggle-details");
    toggleBtn.addEventListener("click", () => this.toggleDetails());

    // Scan again button
    const scanBtn = document.getElementById("scan-again");
    scanBtn.addEventListener("click", () => this.scanAgain());

    // Copy URL button
    const copyBtn = document.getElementById("copy-url");
    copyBtn.addEventListener("click", () => this.copyUrl());
  }

  toggleDetails() {
    this.detailsVisible = !this.detailsVisible;
    const features = document.getElementById("features");
    const toggleBtn = document.getElementById("toggle-details");
    const svg = toggleBtn.querySelector("svg polyline");

    if (this.detailsVisible) {
      features.classList.remove("hidden");
      toggleBtn.querySelector("span").textContent = "Hide Details";
      svg.setAttribute("points", "6 15 12 9 18 15"); // Arrow up
    } else {
      features.classList.add("hidden");
      toggleBtn.querySelector("span").textContent = "Show Details";
      svg.setAttribute("points", "6 9 12 15 18 9"); // Arrow down
    }
  }

  async scanAgain() {
    this.detailsVisible = false;
    await this.init();
  }

  copyUrl() {
    navigator.clipboard.writeText(this.currentUrl).then(() => {
      const copyBtn = document.getElementById("copy-url");
      const originalHTML = copyBtn.innerHTML;
      
      // Show success feedback
      copyBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="16" height="16">
          <polyline points="20 6 9 17 4 12" stroke="#10b981" stroke-width="2" fill="none"/>
        </svg>
      `;
      copyBtn.style.background = "rgba(16, 185, 129, 0.3)";
      
      setTimeout(() => {
        copyBtn.innerHTML = originalHTML;
        copyBtn.style.background = "";
      }, 1500);
    }).catch(err => {
      console.error("Failed to copy:", err);
    });
  }

  displayResult(res, url) {
    document.getElementById("loading").classList.add("hidden");
    document.getElementById("result").classList.remove("hidden");

    let status = "safe",
        msg = "Safe Website",
        desc = "Nothing suspicious detected.";

    if (res.trustedDomain) {
      status = "safe";
      msg = "Trusted Website";
      desc = "Recognized as a popular, reputable domain.";
    } else if (res.isPhishing) {
      status = "danger";
      msg = "⚠ Phishing Attack Detected!";
      desc = "Do NOT enter sensitive info.";
    } else if (res.score >= 0.3) {
      status = "warning";
      msg = "Suspicious Activity";
      desc = "Proceed with caution.";
    }

    // Update status icon with pulse ring
    const statusWrapper = document.getElementById("status-icon");
    statusWrapper.innerHTML = `
      <div class="pulse-ring ${status}"></div>
      <div class="status-icon ${status}"></div>
    `;

    document.getElementById("status-text").className = `status-text ${status}`;
    document.getElementById("status-text").textContent = msg;
    document.getElementById("status-description").textContent = desc;

    // Update URL display with title for hover
    const urlEl = document.getElementById("current-url");
    urlEl.textContent = url;
    urlEl.setAttribute("title", url);

    // Animate risk meter
    this.animateRiskMeter(res.score);

    // Update confidence
    const confidencePercent = Math.round(res.confidence * 100);
    document.getElementById("confidence-percent").textContent = `${confidencePercent}%`;
    const confidenceFill = document.getElementById("confidence-fill");
    setTimeout(() => {
      confidenceFill.style.width = `${confidencePercent}%`;
    }, 300);

    // Update security indicators
    this.updateSecurityIndicators(res);

    // Populate features
    this.populateFeatures(res.features);
  }

  animateRiskMeter(score) {
    const riskScoreEl = document.getElementById("risk-score");
    const meterFill = document.getElementById("meter-fill");
    
    const percentage = Math.round(score * 100);
    const circumference = 251.2; // Path length of the arc
    const offset = circumference - (percentage / 100) * circumference;

    // Animate the number
    let current = 0;
    const increment = percentage / 50;
    const timer = setInterval(() => {
      current += increment;
      if (current >= percentage) {
        current = percentage;
        clearInterval(timer);
      }
      riskScoreEl.textContent = Math.round(current) + "%";
    }, 20);

    // Animate the arc
    setTimeout(() => {
      meterFill.style.strokeDashoffset = offset;
      
      // Color gradient based on risk
      if (score < 0.3) {
        meterFill.style.stroke = "#10b981"; // Green
      } else if (score < 0.7) {
        meterFill.style.stroke = "#f59e0b"; // Yellow
      } else {
        meterFill.style.stroke = "#ef4444"; // Red
      }
    }, 100);
  }

  updateSecurityIndicators(res) {
    // HTTPS indicator
    const httpsIndicator = document.getElementById("https-indicator");
    const httpsStatus = httpsIndicator.querySelector(".indicator-status");
    if (res.https) {
      httpsStatus.textContent = "Secure";
      httpsStatus.className = "indicator-status good";
    } else {
      httpsStatus.textContent = "Not Secure";
      httpsStatus.className = "indicator-status bad";
    }

    // Domain indicator
    const domainIndicator = document.getElementById("domain-indicator");
    const domainStatus = domainIndicator.querySelector(".indicator-status");
    if (res.trustedDomain) {
      domainStatus.textContent = "Trusted";
      domainStatus.className = "indicator-status good";
    } else if (res.suspiciousTld) {
      domainStatus.textContent = "Suspicious";
      domainStatus.className = "indicator-status bad";
    } else {
      domainStatus.textContent = "Unknown";
      domainStatus.className = "indicator-status";
      domainStatus.style.background = "rgba(156, 163, 175, 0.2)";
      domainStatus.style.color = "#9ca3af";
    }

    // Age/Content indicator
    const ageIndicator = document.getElementById("age-indicator");
    const ageStatus = ageIndicator.querySelector(".indicator-status");
    if (res.ageScore > 0.7) {
      ageStatus.textContent = "Established";
      ageStatus.className = "indicator-status good";
    } else {
      ageStatus.textContent = "New";
      ageStatus.className = "indicator-status";
      ageStatus.style.background = "rgba(156, 163, 175, 0.2)";
      ageStatus.style.color = "#9ca3af";
    }
  }

  populateFeatures(f) {
    const list = document.getElementById("features-list");
    list.innerHTML = "";

    const featureData = [
      { key: "url_length", name: "URL Length", format: v => `${v} chars` },
      { key: "num_dots", name: "Dots", format: v => v },
      { key: "num_hyphens", name: "Hyphens", format: v => v },
      { key: "num_subdomains", name: "Subdomains", format: v => v },
      { key: "https", name: "HTTPS", format: v => v ? "Yes ✓" : "No ✗" },
      { key: "has_ip", name: "IP Address", format: v => v ? "Yes ⚠️" : "No ✓" },
      { key: "has_suspicious_words", name: "Suspicious Words", format: v => v ? "Yes ⚠️" : "No ✓" },
      { key: "has_shortening", name: "URL Shortener", format: v => v ? "Yes ⚠️" : "No ✓" },
      { key: "digit_ratio", name: "Digit Ratio", format: v => `${(v * 100).toFixed(1)}%` },
      { key: "special_char_ratio", name: "Special Chars", format: v => `${(v * 100).toFixed(1)}%` }
    ];

    featureData.forEach(({ key, name, format }) => {
      const value = f[key] !== undefined ? f[key] : 0;
      const displayValue = format ? format(value) : value;
      
      const div = document.createElement("div");
      div.className = "feature-item";
      div.innerHTML = `
        <span class="feature-name">${name}</span>
        <span class="feature-value">${displayValue}</span>
      `;
      list.appendChild(div);
    });
  }

  showError(message) {
    document.getElementById("loading").classList.add("hidden");
    document.getElementById("result").classList.add("hidden");
    document.getElementById("error").classList.remove("hidden");
    document.getElementById("error-message").textContent = message || "An error occurred while analyzing the website.";

    // Retry button
    const retryBtn = document.getElementById("retry-btn");
    retryBtn.addEventListener("click", () => this.init());
  }
}


// === Boot Up === //
document.addEventListener("DOMContentLoaded", () => {
  new PopupUI().init();
});