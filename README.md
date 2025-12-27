 🛡️ PhishNet  
ML-Powered Client-Side Phishing Detection Browser Extension

PhishNet is a **privacy-preserving, client-side phishing detection browser extension** that uses **machine learning** to identify phishing websites in real time.  
The entire detection pipeline runs **inside the browser**, ensuring **zero data leakage**, **low latency**, and **offline capability**.

---

## 🚀 Key Features

- 🔍 **Real-time phishing detection**
- 🧠 **Machine learning–based classification**
- 🔐 **Fully client-side (no server calls)**
- ⚡ **Fast inference (<100 ms)**
- 📉 **Lightweight ONNX model (<5 MB)**
- 📊 **Probability meter with Safe / Suspicious / Danger output**
- 🧩 **Hybrid feature extraction (URL + DOM + Security)**

---

## 🧠 Project Architecture Overview

PhishGuard AI consists of two major parts:

1. **Machine Learning Training Pipeline**
2. **Browser Extension Runtime**

## The Methodology [Training (Python) → ONNX Model → Browser Extension (JavaScript)]:

### 1️⃣ Data Collection
- **Phishing URLs:** OpenPhish, URLHaus, PhishTank  
- **Legitimate URLs:** Alexa Top Sites  
- URLs are labeled as:
  - `0` → Safe  
  - `1` → Phishing  

---

### 2️⃣ Data Cleaning & Preprocessing
- Removed duplicate URLs
- Filtered invalid or malformed URLs
- Handled missing values
- Converted categorical values into numerical form
- Applied **Min–Max normalization (0–1)**

> This ensures stable and efficient model training.

---

### 3️⃣ Feature Extraction (Hybrid Approach)

Each website is converted into a **numerical feature vector** using:

#### 🔹 URL-Based Features
- URL length
- Number of dots, hyphens, special characters
- Presence of suspicious keywords
- IP address usage

#### 🔹 DOM-Based Features
- Presence of login forms
- Password input fields
- Iframes
- External scripts

#### 🔹 Security Features
- HTTPS presence
- Basic certificate indicators

> Hybrid features help detect modern phishing attacks that bypass single-feature methods.

---

### 4️⃣ Model Training (PhishNet MLP)

- **Model Type:** Multi-Layer Perceptron (MLP)
- **Hidden Layers:** ReLU activation (non-linearity)
- **Output Layer:** Sigmoid (probability output)
- **Loss Function:** Binary Cross-Entropy
- **Optimizer:** Adam
- **Learning Type:** Supervised learning

📈 **Achieved Accuracy:** **96.2%**

---

### 5️⃣ ONNX Conversion & Optimization

- Trained PyTorch model exported to **ONNX format**
- Training components removed (optimizer, loss)
- Inference-only graph retained
- Final model size: **< 5 MB**

> ONNX enables fast, cross-platform, browser-based inference.

---

### 6️⃣ Browser Extension Runtime

- **Content Script:** Extracts live URL & DOM features
- **Background Script:** Loads ONNX model
- **ONNX Runtime Web:** Executes inference
- **Scaler (`scaler.json`):** Applies same normalization used during training
- **Popup UI:** Displays phishing verdict

---

### 7️⃣ Output Classification

The model outputs a **probability (0–1)**:

- 🟢 **Safe** – Low risk  
- 🟡 **Suspicious** – Medium risk  
- 🔴 **Danger** – High risk  

> Categories are derived from model confidence, not hard-coded rules.

---

## 🖼️ Screenshots

### 🔹 Extension Popup – Safe Website
![Safe Website](screenshots/safe.png)

### 🔹 Extension Popup – Suspicious Website
![Suspicious Website](screenshots/suspicious.png)

### 🔹 Extension Popup – Dangerous Website
![Dangerous Website](screenshots/danger.png)

### 🔹 Probability Meter View
![Probability Meter](screenshots/probability_meter.png)

> 📌 Place your screenshots inside a `screenshots/` folder.

---

## 🧰 Technology Stack

- **Languages:** Python, JavaScript, HTML, CSS  
- **ML Framework:** PyTorch  
- **Model Format:** ONNX  
- **Inference Engine:** ONNX Runtime Web  
- **Data Processing:** Pandas, NumPy  
- **Extension APIs:** Chrome Extension APIs  
- **Version Control:** Git, GitHub  

---

## 🔐 Privacy & Security

- No server-side processing
- No data logging
- No user tracking
- Works offline
- Fully client-side execution

---

## 📈 Results

| Metric | Value |
|------|------|
| Accuracy | 96.2% |
| Inference Time | < 100 ms |
| Model Size | < 5 MB |
| Execution | Client-side |

---

## 🔮 Future Enhancements

- 📧 Email phishing detection (mail scanning)
- 📱 Mobile browser support
- 🔄 Continuous model retraining
- 🧠 Explainable AI (feature importance in UI)
- 🌐 Multi-browser support (Firefox, Edge)

---

## 👨‍💻 Author

**Pragyan Kalita**  
Computer Science Student  
Interested in Cybersecurity & AI  

---

## 📜 License

This project is intended for **academic and research purposes only**.

---

⭐ If you find this project useful, feel free to star the repository!



