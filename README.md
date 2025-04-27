# Pot de Miel 🍯 — Honeypot Suite

**Pot de Miel** ("Honey Pot" in French 🇫🇷) is a modular, extensible **suite of honeypots** designed to capture, analyze, and understand malicious behaviors across multiple protocols and services.

🛡️ Built with **Python**, containerized with **Docker**, and designed for **security research** and **attack intelligence**.

---

## 🚀 Current Modules

| Service | Status | Description |
|:--------|:-------|:------------|
| SSHD Honeypot | ✅ Active | Simulated interactive SSH server with command parsing and logging |
| HTTP/Web Honeypot | 🛠️ Planned | Simulated web server capturing malicious HTTP requests |
| SMB Honeypot | 🛠️ Planned | Fake SMB shares and authentication traps |
| FTP Honeypot | 🛠️ Planned | Fake FTP server accepting credentials and file uploads |

**First module available:**  
✔️ **SSHD Honeypot** (`sshd/`) — see below for details.

---

## 📦 Project Structure

```bash
pot-de-miel/
├── sshd/              # SSH Honeypot module
│   ├── app.py
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── .env.example
│   └── logs/
├── README.md          # (this file)
└── LICENSE
```

Each service lives in its own directory for **easy modular expansion**.

---

## 🧪 SSHD Honeypot Overview

**SSHD Honeypot** simulates an interactive Linux SSH server:
- Accepts password authentication
- Simulates shell commands (`ls`, `pwd`, `whoami`, `who`, `ps`, etc.)
- Realistic fake sessions and processes
- Handles clean `exit` / `quit` disconnections
- Captures and logs all activities:
  - Authentication attempts
  - Commands executed
  - URLs retrieved via `wget`/`curl`
- Structured **JSON logs** and **human-readable logs**

> 📚 Full details in [sshd/README.md](./sshd/README.md)

---

## 🛠️ Quick Start (SSHD Honeypot)

### 1. Navigate to SSHD module

```bash
cd pot-de-miel/sshd/
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env if needed
```

### 3. Build and run with Docker

```bash
docker-compose up -d
```

The SSH honeypot will listen by default on **port 22**.

Logs will be available under `logs/`.

---

## 📜 Global Roadmap

- [x] SSHD honeypot ✅
- [ ] OT honeypot 🛠️
- [ ] HTTP/Web honeypot 🛠️
- [ ] SMB honeypot 🛠️
- [ ] FTP honeypot 🛠️
- [ ] Global dashboard (optional future idea)

Stay tuned for future module releases! 🚀

---

## 📚 Documentation

Each module contains its own detailed `README.md`.

Coming soon:  
➡️ Centralized Pot de Miel documentation site 📓

---

## ⚠️ Disclaimer

**Pot de Miel** is intended for:
- Research purposes
- Education
- Threat intelligence
- Cybersecurity awareness

⚠️ **It is not meant to trap or harm attackers** — usage must comply with your local laws and ethical guidelines.

---

## ❤️ Contributions

Contributions are very welcome!

Ideas for improvements:
- New honeypot modules
- Better interaction realism
- Automation (e.g., auto-block IPs after traps)
- Dashboard integration

Pull Requests or Issues are appreciated!

---

## 📜 License

**MIT License** — open source, free to use for education, research, and awareness.

---

> 🐝 Pot de Miel — capturing the buzz of attackers, one fake service at a time.