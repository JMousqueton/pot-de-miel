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
- **Dynamic fake "ps" command** (simulated process list)
- Handles **exit** and **quit** properly (clean disconnection)
- Logs:
  - **Human-readable logs** (`logs/ssh-honeypot.log`)
  - **Structured JSON logs** (`logs/ssh-honeypot.jsonl`)
- Generates **different SSH host keys** per attacker IP
- Fully **configurable** via `.env` file
- **Docker-ready** for easy deployment
- **Session timeout** handling
- **Supports multiple concurrent connections**

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/ssh-honeypot.git
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

---

## 🐳 Docker Deployment

### Build and run with Docker

```bash
docker build -t ssh-honeypot .
docker run -d --restart unless-stopped --env-file .env -p 22:22 -v $(pwd)/logs:/opt/potdemiel/sshd/logs --name ssh-honeypot ssh-honeypot
```

Or use `docker-compose`:

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
- Commands executed
- URLs if detected (via `wget`, `curl`)
- Login attempts and failures

---

## 🛠️ Commands supported

| Command | Behavior |
|:--------|:---------|
| `ls` | List fake directory contents |
| `pwd` | Show fake current path |
| `whoami` | Return username |
| `who` | Show connected sessions |
| `ps`, `ps aux`, `ps -ef` | Show fake process list |
| `cd <dir>` | Accept silently (no real filesystem) |
| `wget <url>`, `curl <url>` | Fake download + logs URL |
| `uname -a` | Show randomized fake Linux kernel |
| `exit`, `quit` | Clean disconnection |

---
  
## 📋 Example Session

```bash
ssh julien@honeypot_ip
julien@honeypot_ip's password:
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.15.0-76-generic)

root@iot-gateway:~# who
julien   pts/1    2025-04-27 16:30 (82.65.156.219)
root     pts/0    2025-04-27 14:10 (10.0.0.5)

root@iot-gateway:~# ps aux
root      1523  0.0  0.5  11032  5232 ?        Ss   14:21   0:00 /usr/sbin/sshd -D
mysql     2124  0.2  1.0 120000 15324 ?        Sl   14:20   0:02 /usr/sbin/mysqld

root@iot-gateway:~# exit
logout
Connection to honeypot_ip closed.
```

---

## ⚠️ Important Notes

- This honeypot **does not provide real shell access** (everything is simulated).
- **Never expose the honeypot port (22) to your real systems**.
- **Use firewall rules** to isolate or monitor traffic properly.

---

## 📚 License

MIT License — Free for educational and research use.  
Not intended for malicious activities.

---

## ❤️ Contributions

Pull requests are welcome!  
If you have new ideas (fake filesystem, fake netstat, session recording...), feel free to propose improvements!

---

