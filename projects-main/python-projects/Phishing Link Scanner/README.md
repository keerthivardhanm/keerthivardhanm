# Phishing Link Scanner 🔍🛡️

A terminal-based security tool to detect malicious/phishing URLs through multiple security checks.

![CLI Demo](https://img.shields.io/badge/Demo-CLI_Interface-green) 
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)

## Features

- **HTTPS Verification**: Checks for encrypted connections
- **URL Shortener Detection**: Identifies 10+ known shortening services
- **Suspicious Keywords**: Flags high-risk words (login, bank, etc.)
- **DNS Blacklist Check**: Uses Spamhaus DBL database
- **Domain Age Analysis**: Identifies newly registered domains
- **Homoglyph Detection**: Finds Unicode character spoofing
- **VirusTotal Integration** (Optional): Checks against 70+ security vendors
- **Color-Coded Results**: Instant visual threat assessment

## Installation

1. **Requirements**:
   - Python 3.6+
   - pip package manager

2. **Install Dependencies**:
```bash
pip install requests python-whois colorama
