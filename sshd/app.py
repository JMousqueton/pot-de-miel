import socket
import paramiko
import threading
import random
import hashlib
import datetime
import json
import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 22))
LOG_PATH = os.getenv("LOG_PATH", "./logs")
SERVICE_NAME = os.getenv("SERVICE_NAME", "ssh-honeypot")
LOGINPASSWD = os.getenv("LOGINPASSWD", "True").lower() in ("true", "1", "yes")
SSH_KEY_BITS = int(os.getenv("SSH_KEY_BITS", 2048))
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# Memory for per-IP host keys
HOST_KEYS_BY_IP = {}

# Predefined fake hostnames and uname responses
HOSTNAMES = [
    "honeypot01", "webserver-prod", "db-backup",
    "srv-test01", "admin-node", "iot-gateway", "bastion-host"
]

UNAME_RESPONSES = [
    "Linux srv-test01 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux",
    "Linux webserver-prod 4.19.0-18-amd64 #1 SMP Debian x86_64 GNU/Linux",
    "Linux db-backup 3.10.0-1160.el7.x86_64 #1 SMP CentOS x86_64 GNU/Linux",
    "Linux admin-node 5.10.0-21-amd64 #1 Debian x86_64 GNU/Linux",
    "Linux honeypot01 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux",
    "Linux bastion-host 4.18.0-348.el8.x86_64 #1 SMP RedHat x86_64 GNU/Linux"
]

# Credentials that trigger special behavior
EXCEPTION_CREDENTIALS = [
    ("*", "3245gs5662d34"),
    ("admin", "*"),
    ("testuser", "testpass123"),
]

# === Logging functions ===

def log_event_human_structured(event_type, src_ip, username=None, password=None, session_id=None, reason=None, extra=None):
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    fields = [f"event={event_type}", f"src_ip={src_ip}"]
    if username:
        fields.append(f"username={username}")
    if password:
        fields.append(f"password={password}")
    if session_id:
        fields.append(f"session_id={session_id}")
    if reason:
        fields.append(f"reason={reason}")
    if extra:
        fields.append(f"extra={extra}")
    log_line = f"[{timestamp}] " + " ".join(fields)
    with open(f"{LOG_PATH}/{SERVICE_NAME}.log", "a") as f:
        f.write(log_line + "\n")
    if DEBUG:
        print(log_line)

def log_event_json(service, data):
    data['timestamp'] = datetime.datetime.now(datetime.UTC).isoformat()
    log_line = json.dumps(data) + "\n"
    with open(f"{LOG_PATH}/{service}.jsonl", "a") as f:
        f.write(log_line)
    if DEBUG:
        print(log_line.strip())

# === Utility functions ===

def generate_session_id(ip, username, password):
    base_string = f"{ip}-{username}-{password}"
    return hashlib.sha256(base_string.encode()).hexdigest()[:16]

def generate_or_retrieve_host_key(ip_source):
    if ip_source not in HOST_KEYS_BY_IP:
        HOST_KEYS_BY_IP[ip_source] = paramiko.RSAKey.generate(SSH_KEY_BITS)
        print(f"[+] New SSH host key generated for {ip_source}")
    return HOST_KEYS_BY_IP[ip_source]

def is_exception(login, password):
    for exc_login, exc_password in EXCEPTION_CREDENTIALS:
        login_match = (exc_login == "*" or exc_login == login)
        password_match = (exc_password == "*" or exc_password == password)
        if login_match and password_match:
            return True
    return False

def extract_url(command):
    match = re.search(r'(https?://[^\s]+)', command)
    return match.group(1) if match else None

def resolve_path(cwd, path):
    if path.startswith("/"):
        return path
    if cwd.endswith("/"):
        return cwd + path
    return cwd + "/" + path

def resolve_cd(cwd, target):
    if target == "..":
        return "/" if cwd == "/" else "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
    elif target.startswith("/"):
        return target if target in FAKE_FILESYSTEM else None
    else:
        new_path = cwd.rstrip("/") + "/" + target
        return new_path if new_path in FAKE_FILESYSTEM else None

#### COMMANDS SIMULATION

def simulate_ps():
    users = ["root", "admin", "user1", "mysql", "www-data", "ubuntu"]
    commands = [
        "/usr/sbin/sshd -D",
        "/usr/sbin/apache2 -k start",
        "/usr/sbin/mysqld",
        "/usr/bin/python3 app.py",
        "/usr/bin/php-fpm",
        "/usr/bin/redis-server *:6379",
        "/usr/bin/docker-containerd",
        "/usr/bin/bash"
    ]
    
    header = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    lines = [header]
    now = datetime.datetime.now()

    for _ in range(random.randint(8, 15)):
        user = random.choice(users)
        pid = random.randint(100, 4000)
        cpu = f"{random.uniform(0.0, 3.0):.1f}"
        mem = f"{random.uniform(0.0, 1.5):.1f}"
        vsz = random.randint(30000, 500000)
        rss = random.randint(5000, 50000)
        tty = "?"  # Simpler
        stat = random.choice(["Ss", "R+", "S+", "Sl", "Z"])
        start = now.strftime("%H:%M")
        time = f"{random.randint(0, 1)}:{random.randint(0,59):02d}"
        cmd = random.choice(commands)

        lines.append(f"{user:<10} {pid:<5} {cpu:<4} {mem:<4} {vsz:<6} {rss:<5} {tty:<8} {stat:<4} {start:<7} {time:<5} {cmd}")

    return "\n".join(lines)




def simulate_who(session_username, session_ip):
    usernames = ["root", "admin", "user1", "user2", "ubuntu"]
    terminals = [f"pts/{i}" for i in range(5)]
    fake_ips = ["192.168.1.10", "10.0.0.5", "172.16.0.2", "203.0.113.5", "198.51.100.22"]

    entries = []
    now = datetime.datetime.now()

    # 1. Add the current attacker's session first
    attacker_terminal = random.choice(terminals)
    login_time = now - datetime.timedelta(minutes=random.randint(1, 10))
    login_str = login_time.strftime("%Y-%m-%d %H:%M")
    entries.append(f"{session_username:<8} {attacker_terminal:<8} {login_str} ({session_ip})")

    # 2. Add 0 to 2 fake sessions
    for _ in range(random.randint(0, 2)):
        user = random.choice(usernames)
        term = random.choice(terminals)
        login_time = now - datetime.timedelta(minutes=random.randint(5, 300))
        login_str = login_time.strftime("%Y-%m-%d %H:%M")
        ip = random.choice(fake_ips)
        entries.append(f"{user:<8} {term:<8} {login_str} ({ip})")

    return "\n".join(entries)

def generate_fake_file_contents(session_username):
    return {
        "/etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
            f"{session_username}:x:1001:1001:SSH User:/home/{session_username}:/bin/bash\n"
        ),
        "/etc/shadow": (
            "root:*:18143:0:99999:7:::\n"
            "admin:*:18143:0:99999:7:::\n"
            f"{session_username}:*:18143:0:99999:7:::\n"
        ),
    }



def simulate_command(command, hostname, fake_uname, session_username=None, session_ip=None):
    command = command.lower()
    if command in ("exit", "quit"):
        return "__EXIT__"
    if command == "ls":
        return "bin  boot  dev  etc  home  lib  media  mnt  opt  root  sbin  tmp  usr  var"
    elif command == "pwd":
        return "/root"
    elif command == "whoami":
        return "root"
    elif command.startswith("ps"):
        return simulate_ps()
    elif command == "who" and session_username and session_ip:
        return simulate_who(session_username, session_ip)
    elif command.startswith("cd"):
        return ""
    elif command.startswith("wget"):
        return f"Connecting to {command.split()[-1]} ... connected."
    elif command.startswith("curl"):
        return f"Downloading {command.split()[-1]} ..."
    elif command == "uname -a":
        return fake_uname
    else:
        return f"-bash: {command}: command not found"

def parse_and_process_command(command_line, hostname, fake_uname, client_ip, session_id, session_username, fake_files, cwd):
    commands = re.split(r';|&&|\|\|', command_line)
    responses = []
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue

        if cmd.startswith("cd "):
            parts = cmd.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "/"
            new_cwd = resolve_cd(cwd, target)
            if new_cwd is not None:
                cwd = new_cwd
            responses.append("")  # No output on success
            continue

        if cmd == "ls":
            entries = [entry for path, entry in FAKE_FILESYSTEM.items() if path == cwd]
            if entries:
                responses.append("  ".join(entries[0]))
            else:
                responses.append("")
            continue

        if cmd.startswith("cat "):
            parts = cmd.split(maxsplit=1)
            if len(parts) > 1:
                filepath = resolve_path(cwd, parts[1])
                if filepath in fake_files:
                    responses.append(fake_files[filepath])
                else:
                    responses.append(f"cat: {filepath}: No such file or directory")
            continue

        # Handle exit and other commands
        response = simulate_command(cmd, hostname, fake_uname, session_username, client_ip)
        responses.append(response)
    return responses, cwd


# === SSH Server class ===

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.session_id = None

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.session_id = generate_session_id(self.client_ip, username, password)
        if LOGINPASSWD and username == password:
            log_event_human_structured(
                event_type="auth_denied_login_equals_password",
                src_ip=self.client_ip,
                username=username,
                password=password,
                session_id=self.session_id,
                reason="login=password"
            )
            log_event_json(SERVICE_NAME, {
                "src_ip": self.client_ip,
                "event": "auth_denied_login_equals_password",
                "username": username,
                "password": password,
                "session_id": self.session_id
            })
            return paramiko.AUTH_FAILED
        event_type = "auth_attempt_exception" if is_exception(username, password) else "auth_attempt"
        log_event_human_structured(
            event_type=event_type,
            src_ip=self.client_ip,
            username=username,
            password=password,
            session_id=self.session_id
        )
        log_event_json(SERVICE_NAME, {
            "src_ip": self.client_ip,
            "event": event_type,
            "username": username,
            "password": password,
            "session_id": self.session_id
        })
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

# === Session Handler ===
def session_handler(channel, hostname, fake_uname, client_ip, session_id, session_username):
    try:
        channel.settimeout(60)

        # NEW: Generate fake file contents dynamically
        fake_files = generate_fake_file_contents(session_username)
        current_directory = "/"  # Start at root

        channel.send(f"Welcome to Ubuntu 20.04 LTS (GNU/Linux {fake_uname.split()[2]})\n\n")
        channel.send(f"root@{hostname}:~# ")
        buffer = ""

        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break
                for char in data.decode("utf-8", errors="ignore"):
                    channel.send(char)
                    if char == "\r" or char == "\n":
                        command, buffer = buffer.strip(), ""
                        if command:
                            # Updated simulate_command to pass fake_files and current_directory
                            responses, current_directory = parse_and_process_command(
                                command, hostname, fake_uname, client_ip, session_id, session_username, fake_files, current_directory
                            )
                            for response in responses:
                                if response == "__EXIT__":
                                    channel.send("logout\n")
                                    return
                                channel.send(response + "\n")
                        channel.send(f"root@{hostname}:~# ")
                    else:
                        buffer += char
            except socket.timeout:
                channel.send(f"\nroot@{hostname}:~# ")
    except Exception as e:
        print(f"Exception in session with {client_ip}: {e} ({type(e).__name__})")
    finally:
        channel.close()


# === Connection Handler ===

def handle_connection(client_socket, addr):
    ip_source = addr[0]
    transport = paramiko.Transport(client_socket)
    host_key = generate_or_retrieve_host_key(ip_source)
    transport.add_server_key(host_key)
    server = SSHServer(ip_source)
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is not None:
            hostname = random.choice(HOSTNAMES)
            fake_uname = random.choice(UNAME_RESPONSES)
            session_thread = threading.Thread(target=session_handler, args=(channel, hostname, fake_uname, ip_source, server.session_id, server.username))
            session_thread.start()
            session_thread.join()
    except Exception as e:
        print(f"Exception during SSH handling with {ip_source}: {e} ({type(e).__name__})")
        log_event_human_structured(event_type="connection_failure", src_ip=ip_source, extra=str(e))
        log_event_json(SERVICE_NAME, {
            "src_ip": ip_source,
            "event": "connection_failure",
            "error_type": type(e).__name__,
            "error_message": str(e)
        })
    finally:
        try:
            transport.close()
        except Exception as e:
            print(f"Error closing transport: {e}")

# === Start Server ===

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    print(f"[+] SSH honeypot listening on {HOST}:{PORT}")
    while True:
        client, addr = server_socket.accept()
        threading.Thread(target=handle_connection, args=(client, addr)).start()

if __name__ == "__main__":
    os.makedirs(LOG_PATH, exist_ok=True)
    start_server()
