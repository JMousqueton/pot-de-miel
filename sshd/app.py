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

# Charger les variables d'environnement depuis .env
load_dotenv()

# Lire la configuration
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "22"))
LOG_PATH = os.getenv("LOG_PATH", "./logs")
SERVICE_NAME = os.getenv("SERVICE_NAME", "ssh-honeypot")
LOGINPASSWD = os.getenv("LOGINPASSWD", "True").lower() in ("true", "1", "yes")
SSH_KEY_BITS = int(os.getenv("SSH_KEY_BITS", "2048"))
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")


# Dictionnaire pour stocker les clés générées par IP source
HOST_KEYS_BY_IP = {}

# Faux hostnames et uname
HOSTNAMES = [
    "webserver-prod", "db-backup",
    "srv-test01", "admin-node", "iot-gateway", "bastion-host"
]

UNAME_RESPONSES = [
    "Linux srv-test01 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux",
    "Linux webserver-prod 4.19.0-18-amd64 #1 SMP Debian x86_64 GNU/Linux",
    "Linux db-backup 3.10.0-1160.el7.x86_64 #1 SMP CentOS x86_64 GNU/Linux",
    "Linux admin-node 5.10.0-21-amd64 #1 Debian x86_64 GNU/Linux",
    "Linux bastion-host 4.18.0-348.el8.x86_64 #1 SMP RedHat x86_64 GNU/Linux"
]

# Exceptions login/password
EXCEPTION_CREDENTIALS = [
    ("*", "3245gs5662d34"),
    ("admin", "*"),
    ("testuser", "testpass123"),
]

# Logger functions
def log_event_human(service, message):
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}\n"
    with open(f"{LOG_PATH}/{service}.log", "a") as f:
        f.write(log_line)
    if DEBUG:
        print(log_line.strip())

def log_event_json(service, data):
    data['timestamp'] = datetime.datetime.now(datetime.UTC).isoformat()
    log_line = json.dumps(data) + "\n"
    with open(f"{LOG_PATH}/{service}.jsonl", "a") as f:
        f.write(log_line)
    if DEBUG:
        print(log_line.strip())

# Générer Session ID
def generate_session_id(ip, username, password):
    base_string = f"{ip}-{username}-{password}"
    return hashlib.sha256(base_string.encode()).hexdigest()[:16]

# Vérifier exception login/password
def is_exception(login, password):
    for exc_login, exc_password in EXCEPTION_CREDENTIALS:
        login_match = (exc_login == "*" or exc_login == login)
        password_match = (exc_password == "*" or exc_password == password)
        if login_match and password_match:
            return True
    return False

# Extraction URL
def extract_url(command):
    match = re.search(r'(https?://[^\s]+)', command)
    if match:
        return match.group(1)
    return None

# Simulation shell
def simulate_command(command, hostname, fake_uname):
    command = command.lower()
    if command == "ls":
        return "bin  boot  dev  etc  home  lib  media  mnt  opt  root  sbin  tmp  usr  var"
    elif command == "pwd":
        return "/root"
    elif command == "whoami":
        return "root"
    elif command.startswith("cd"):
        return ""
    elif command.startswith("wget"):
        return "Connecting to " + command.split()[-1] + " ... connected."
    elif command.startswith("curl"):
        return "Downloading " + command.split()[-1] + " ..."
    elif command == "uname -a":
        return fake_uname
    else:
        return f"-bash: {command}: command not found"

# Parsing ligne de commande
def parse_and_process_command(command_line, hostname, fake_uname, client_ip, session_id):
    commands = re.split(r';|&&|\|\|', command_line)
    responses = []

    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue

        log_event_human(SERVICE_NAME, f"Command from {client_ip} (session {session_id}): {cmd}")
        log_event_json(SERVICE_NAME, {
            "src_ip": client_ip,
            "event": "command",
            "command": cmd,
            "session_id": session_id
        })

        if cmd.startswith("wget") or cmd.startswith("curl"):
            url = extract_url(cmd)
            if url:
                log_event_human(SERVICE_NAME, f"Detected URL from {client_ip} (session {session_id}): {url}")
                log_event_json(SERVICE_NAME, {
                    "src_ip": client_ip,
                    "event": "url_detected",
                    "url": url,
                    "full_command": cmd,
                    "session_id": session_id
                })

        response = simulate_command(cmd, hostname, fake_uname)
        responses.append(response)

    return responses

# Serveur SSH custom
class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.session_id = None
        self.exception_matched = False

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.session_id = generate_session_id(self.client_ip, username, password)

        if LOGINPASSWD and username == password:
            event_type = "auth_denied_login_equals_password"
            log_event_human(SERVICE_NAME, f"Denied login from {self.client_ip} - username: {username} password: {password} session_id: {self.session_id} reason: login=password")
            log_event_json(SERVICE_NAME, {
                "src_ip": self.client_ip,
                "event": event_type,
                "username": username,
                "password": password,
                "session_id": self.session_id
            })
            return paramiko.AUTH_FAILED

        self.exception_matched = is_exception(username, password)
        event_type = "auth_attempt_exception" if self.exception_matched else "auth_attempt"

        log_event_human(SERVICE_NAME, f"Login attempt from {self.client_ip} - username: {username} password: {password} session_id: {self.session_id} event: {event_type}")
        log_event_json(SERVICE_NAME, {
            "src_ip": self.client_ip,
            "event": event_type,
            "username": username,
            "password": password,
            "session_id": self.session_id
        })

        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

# Gérer une connexion client
def handle_connection(client_socket, addr):
    try:
        client_socket.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
    except Exception as e:
        print(f"Error sending SSH banner to {addr[0]}: {e}")
        client_socket.close()
        return

    ip_source = addr[0]

    # >>> Chercher ou créer une clé pour cette IP
    if ip_source in HOST_KEYS_BY_IP:
        host_key = HOST_KEYS_BY_IP[ip_source]
    else:
        host_key = paramiko.RSAKey.generate(SSH_KEY_BITS)
        HOST_KEYS_BY_IP[ip_source] = host_key
        print(f"[+] New host key generated for {ip_source}")


    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    server = SSHServer(addr[0])

    hostname = random.choice(HOSTNAMES)
    fake_uname = random.choice(UNAME_RESPONSES)

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is not None:
            channel.send(f"Welcome to Ubuntu 20.04 LTS (GNU/Linux {fake_uname.split()[2]})\n\n")
            channel.send(f"root@{hostname}:~# ")
            while True:
                try:
                    command = ""
                    while not command.endswith("\n"):
                        data = channel.recv(1024)
                        if not data:
                            raise ConnectionResetError("Connection closed by client.")
                        command += data.decode("utf-8", errors="ignore")

                    command = command.strip()
                    if not command:
                        continue

                    responses = parse_and_process_command(command, hostname, fake_uname, addr[0], server.session_id)
                    for response in responses:
                        channel.send(response + "\n")
                    channel.send(f"root@{hostname}:~# ")

                except Exception as loop_error:
                    print(f"Exception inside session with {addr[0]}: {loop_error}")
                    break  # quitter la boucle while
    except Exception as e:
        error_type = type(e).__name__
        error_message = str(e)
        print(f"Exception during SSH handling with {addr[0]}: {error_message} ({error_type})")

        log_event_human(SERVICE_NAME, f"Connection failure from {addr[0]}: {error_type} {error_message}")
        log_event_json(SERVICE_NAME, {
            "src_ip": addr[0],
            "event": "connection_failure",
            "error_type": error_type,
            "error_message": error_message
        })

    finally:
        client_socket.close()




# Lancer serveur SSH
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    print(f"[+] SSH honeypot listening on {HOST}:{PORT}")

    while True:
        client, addr = server_socket.accept()
        threading.Thread(target=handle_connection, args=(client, addr)).start()

# Générer la clé privée
host_key = paramiko.RSAKey.generate(SSH_KEY_BITS)

if __name__ == "__main__":
    os.makedirs(LOG_PATH, exist_ok=True)
    start_server()
