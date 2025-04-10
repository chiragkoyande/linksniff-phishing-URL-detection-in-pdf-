
# 🕵️‍♂️ Linksniff – Smart PDF Phishing Detector

> **Catch hidden phishing links inside PDF files using automation, heuristics, and real-time analysis.**

Linksniff is a browser-based tool and Flask-powered backend that detects and highlights malicious URLs buried in PDF documents. It scans visible and hidden links (including metadata, JS, and obfuscated links), calculates a risk score, and presents results with intuitive visualizations.

---

## 📌 Features

- 🔍 **Automated URL Extraction** from PDFs using PyPDF2.
- 🧠 **Heuristic Analysis** based on phishing patterns (IP usage, shortened URLs, suspicious TLDs, etc.).
- 📊 **Risk Classification** – Low, Medium, High with percentage score.
- 📂 **Logging and Reporting** – All threats stored with timestamps for future analysis.
- 🧾 **Visual Dashboard** – PDF preview, page-level URL tracking, risk color coding.
- 🧩 **Browser Extension Integration** – Lightweight popup to trigger scans in real-time.
- 🧠 **Base64 PDF Uploads** – Efficient data transmission using base64 encoding.

---

## 💻 Technologies Used

| Layer              | Technology Used     | Purpose                                                                 |
|-------------------|---------------------|-------------------------------------------------------------------------|
| Backend API       | Flask (Python)      | URL analysis, risk calculation, PDF parsing                            |
| PDF Processing    | PyPDF2, `base64`    | Extract URLs from text, encode PDFs for transmission                   |
| Heuristic Engine  | `tldextract`, `re`, `urllib.parse` | Feature extraction & rule-based scoring                         |
| Frontend (App)    | HTML5, CSS3, JS     | File upload, result display, viewer UI                                 |
| Extension UI      | Manifest v3, popup  | Chrome extension popup & background services                           |
| Visuals           | Bootstrap, Icons    | Dashboard UI, color-coded statuses                                     |

---

## 🛠️ Installation & Setup

### 🔽 Clone the repository

```bash
git clone https://github.com/your-username/Linksniff.git
cd Linksniff
```

### ⚙️ Set up the Flask Backend

```bash
pip install -r requirements.txt
python app.py
```

- Access backend API on: `http://localhost:5000`

### 🌐 Frontend (Dashboard)

1. Open `dashboard.html` in any browser.
2. Upload a PDF.
3. Click "Scan" to begin URL extraction and phishing analysis.

---

## 🧠 Heuristic Parameters Explained

| Feature             | Example                         | Description                                                       |
|---------------------|----------------------------------|-------------------------------------------------------------------|
| `ip_address`        | `http://192.168.0.1/login`       | URLs with direct IPs instead of domains – very suspicious         |
| `url_length`        | `http://example.com/very...long` | Phishing URLs often overly long to obfuscate intent               |
| `tiny_url`          | `https://bit.ly/abc123`          | Shortened links hide actual destination                           |
| `suspicious_tld`    | `.xyz`, `.top`, `.club`          | Cheap, shady domains commonly used in phishing                   |
| `encoded_chars`     | `%20`, `%3F`                     | URL encoding tricks users and filters                             |
| `redirecting`       | `?redirect=http://malicious`     | Redirection commonly used in phishing tactics                     |
| `https`             | Not using HTTPS                  | Insecure connection, less trusted                                 |
| `brand_impersonation` | `secure-paypal-login.com`      | Mimics brand names deceptively                                    |

---

## 🧾 Logging

All flagged URLs are stored in:

```bash
/logs/malicious_urls.log
```

Each log contains:

```json
{
  "timestamp": "2025-04-10 12:34:56",
  "url": "http://malicious.xyz/login",
  "risk_percentage": 87,
  "features": {
    "ip_address": false,
    "tiny_url": true,
    "suspicious_tld": true
  }
}
```

---

## 📄 Output Preview

![Example Output](https://github.com/your-username/Linksniff/assets/output-preview.png)

---

## 📬 Contribution

Feel free to fork the repo, suggest improvements, or submit PRs to:

```bash
https://github.com/your-username/Linksniff
```

---

## 📜 License

MIT License © 2025 chirag koyande 
