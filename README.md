# 🔍 SecuNik LogX

<div align="center">

![SecuNik LogX Logo](frontend/public/logo.svg)

**Advanced Multi-Format Log Analysis Platform**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Node](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## 🚀 Overview

SecuNik LogX is a comprehensive security log analysis platform that supports 50+ file formats, providing real-time threat detection, AI-powered analysis, and integration with threat intelligence services.

### ✨ Key Features

- **📁 50+ File Format Support**: Parse logs, network captures, forensic artifacts, and more
- **🤖 AI-Powered Analysis**: Leverage OpenAI for intelligent log interpretation
- **🔍 Real-time Detection**: YARA and Sigma rule engine for threat detection
- **🌐 Threat Intelligence**: VirusTotal integration for IOC enrichment
- **📊 Visual Analytics**: Interactive dashboards and timeline visualization
- **🔄 Real-time Updates**: WebSocket-based live analysis progress
- **🎯 MITRE ATT&CK Mapping**: Automatic technique identification
- **📦 Modular Architecture**: Easy to extend with new parsers and analyzers

## 🛠️ Supported Formats

<details>
<summary><b>Log Files</b></summary>

- Linux Syslog
- Windows Event Logs (EVT/EVTX)
- Apache/Nginx Access & Error Logs
- IIS Logs
- Application Logs (JSON, Plain Text)
- Authentication Logs
- Firewall Logs

</details>

<details>
<summary><b>Network Captures</b></summary>

- PCAP/PCAPNG Files
- NetFlow Data
- Zeek (Bro) Logs
- Suricata Logs
- Snort Logs
- TCPDump Output
- DNS Query Logs

</details>

<details>
<summary><b>System Artifacts</b></summary>

- Windows Registry
- Memory Dumps
- Process Lists
- Windows Prefetch
- NTFS MFT
- USN Journal
- Scheduled Tasks

</details>

<details>
<summary><b>Mobile & Cloud</b></summary>

- Android Logcat
- iOS Syslog
- AWS CloudTrail
- Azure Activity Logs
- GCP Stackdriver
- Office 365 Audit Logs

</details>

<details>
<summary><b>Other Formats</b></summary>

- Email (EML, MSG, PST)
- Documents (PDF, DOCX, XLSX)
- Archives (ZIP, RAR, 7Z)
- Databases (SQLite, MySQL/PostgreSQL dumps)
- Source Code & Scripts
- Structured Data (JSON, CSV, XML, YAML)

</details>

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (optional)

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/secunik-logx.git
cd secunik-logx

# Copy environment files
cp .env.example .env
# Edit .env with your API keys

# Start all services
docker-compose up -d

# Access the application
open http://localhost
```

### Option 2: Manual Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/secunik-logx.git
cd secunik-logx

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Start backend
cd backend
source venv/bin/activate
uvicorn main:app --reload

# Start frontend (new terminal)
cd frontend
npm run dev
```

## 📖 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Parser Documentation](docs/PARSERS.md)
- [API Reference](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   React UI      │────▶│  FastAPI Backend │────▶│   Analyzers     │
│   (Vite)        │◀────│  (WebSocket)     │◀────│  (YARA/Sigma)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │                          │
                               ▼                          ▼
                        ┌─────────────┐           ┌─────────────┐
                        │   Parsers   │           │  External   │
                        │  (50+ types)│           │    APIs     │
                        └─────────────┘           └─────────────┘
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Workflow

```bash
# Create a feature branch
git checkout -b feature/amazing-feature

# Make changes and test
python scripts/test_parsers.py

# Commit changes
git commit -m "Add amazing feature"

# Push and create PR
git push origin feature/amazing-feature
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [YARA](https://virustotal.github.io/yara/) - Pattern matching engine
- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics framework
- All the amazing open-source projects that make this possible

## 📧 Contact

- **Email**: security@secunik.com
- **Twitter**: [@SecuNikLogX](https://twitter.com/SecuNikLogX)
- **Discord**: [Join our community](https://discord.gg/secunik)

---

<div align="center">

Made with ❤️ by the SecuNik Team

**[Website](https://secunik.com)** • **[Blog](https://blog.secunik.com)** • **[Documentation](https://docs.secunik.com)**

</div>
```

---
