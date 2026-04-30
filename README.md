# 🔐 Cybersecurity & Cryptography Toolkit

A modular, full-stack web application built with Python and Streamlit to demonstrate core cybersecurity concepts, cryptography, and network safety. 

This project was built to showcase secure coding practices, automated testing (CI/CD), and modern web development.

## 🚀 Features

* **Cryptography Sandbox**: Encrypt and decrypt text using AES-256-GCM (with PBKDF2 key derivation) and a true Cryptographically Secure XOR Cipher.
* **Password Strength Analyzer**: Real-time entropy calculation and vulnerability analysis using the `zxcvbn` library.
* **Educational Port Scanner**: A localized network utility to check open/closed ports (safely restricted to `127.0.0.1` and `scanme.nmap.org` to prevent abuse).

## 🛠️ Tech Stack & Architecture
* **Frontend/Backend**: Python, Streamlit
* **Security & Crypto**: `cryptography`, `secrets` (for true randomness), `zxcvbn`
* **DevOps**: Docker, Pytest, GitHub Actions (CI)

### Security by Design
* **AES-256-GCM**: Ensures both confidentiality and data integrity (tamper-proofing).
* **Safe Randomness**: Uses `secrets.token_bytes()` instead of `random` for cryptographic keys.
* **Error Handling**: Wrapped cryptographic operations prevent stack-trace crashes during invalid decryption attempts.

## 💻 How to Run Locally

1. Clone the repository:
   ```bash
   git clone [https://github.com/SyazAwie/cybersec-toolkit.git](https://github.com/SyazAwie/cybersec-toolkit.git)

2. Install dependencies:
   ```bash
   pip install -r requirements.txt

3. Run the application:
   ```bash
   streamlit run app.py

✅ Testing
This project includes automated unit tests powered by pytest and runs a GitHub Actions CI pipeline on every push.
Run tests locally with: 
   ```bash
   pytest tests/ -v