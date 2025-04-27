import json
import datetime
import os
from collections import Counter, defaultdict
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

LOG_DIRECTORY = os.getenv("LOG_PATH", ".")
OUTPUT_HTML = "honeypot_report.html"
INPUT_LOG = os.path.join(LOG_DIRECTORY, "ssh-honeypot.jsonl")

def load_events(filename):
    events = []
    if not os.path.isfile(filename):
        print(f"[!] Error: File {filename} not found.")
        exit(1)
    with open(filename, 'r') as f:
        for line in f:
            events.append(json.loads(line))
    return events

def generate_html(time_series, top_ips, top_users, top_passwords, top_credentials, commands, payloads):
    html = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>SSH Honeypot Dashboard</title>
<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
<link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css\" rel=\"stylesheet\">
<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
<script src=\"https://code.jquery.com/jquery-3.5.1.js\"></script>
<script src=\"https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js\"></script>
<link rel=\"stylesheet\" href=\"https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css\"/>
</head>
<body class=\"bg-light\">
<div class=\"container my-5\">
<h1 class="mb-4 text-center" style="color: #DAA520;">
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40" style="vertical-align: middle; margin-right: 10px; fill: #DAA520;">
    <path d="M12 2C10.8954 2 10 2.89543 10 4C10 4.41421 10.3358 4.75 10.75 4.75H13.25C13.6642 4.75 14 4.41421 14 4C14 2.89543 13.1046 2 12 2ZM7 6C5.89543 6 5 6.89543 5 8C5 8.55228 5.44772 9 6 9H18C18.5523 9 19 8.55228 19 8C19 6.89543 18.1046 6 17 6H7ZM4 10C3.44772 10 3 10.4477 3 11V12C3 12.5523 3.44772 13 4 13H5L6.38554 19.4497C6.73107 21.0233 8.19269 22 9.80761 22H14.1924C15.8073 22 17.2689 21.0233 17.6145 19.4497L19 13H20C20.5523 13 21 12.5523 21 12V11C21 10.4477 20.5523 10 20 10H4Z"/>
  </svg>
  SSH Honeypot Dashboard
</h1>


<div class=\"mb-5\">
<h2><i class=\"fas fa-clock\"></i> Attempts Over Time</h2>
<canvas id=\"timeseries\" height=\"100\"></canvas>
</div>

<div class=\"mb-5\">
<h2><i class=\"fas fa-network-wired\"></i> Top Source IPs</h2>
<canvas id=\"topips\" height=\"100\"></canvas>
</div>

<div class=\"mb-5\">
<h2><i class=\"fas fa-user\"></i> Top Usernames</h2>
<canvas id=\"topusers\" height=\"100\"></canvas>
</div>

<div class=\"mb-5\">
<h2><i class=\"fas fa-key\"></i> Top Passwords</h2>
<div class=\"table-responsive\">
<table class=\"table table-striped table-bordered\">
<thead class=\"table-dark\"><tr><th>Password</th><th>Attempts</th></tr></thead>
<tbody>
"""
    for password, count in top_passwords.items():
        html += f"<tr><td>{password}</td><td>{count}</td></tr>"

    html += """
</tbody></table>
</div>
</div>

<div class="mb-5">
<h2><i class="fas fa-user-lock"></i> Top Login:Password</h2>
<div class="table-responsive">
<table class="table table-striped table-bordered">
<thead class="table-dark"><tr><th>Login:Password</th><th>Attempts</th></tr></thead>
<tbody>
"""
    for credential, count in top_credentials.items():
        html += f"<tr><td>{credential}</td><td>{count}</td></tr>"

    html += """
</tbody></table>
</div>
</div>


<div class=\"mb-5\">
<h2><i class=\"fas fa-terminal\"></i> Commands Executed</h2>
<ul class=\"list-group\">
"""
    for cmd in commands:
        html += f"<li class='list-group-item'>{cmd}</li>"

    html += """
</ul>
</div>

<div class=\"mb-5\">
<h2><i class=\"fas fa-bug\"></i> Payloads</h2>
<div class=\"table-responsive\">
<table id=\"payloads\" class=\"table table-striped table-bordered\">
<thead class=\"table-dark\"><tr><th>SHA256</th><th>File Path</th><th>VirusTotal</th></tr></thead>
<tbody>
"""
    for payload in payloads:
        sha = payload['sha256']
        file_path = payload['file_path']
        vt_link = f"https://www.virustotal.com/gui/file/{sha}"
        html += f"<tr><td>{sha}</td><td>{file_path}</td><td><a href='{vt_link}' target='_blank' class='btn btn-primary btn-sm'><i class='fas fa-external-link-alt'></i> View</a></td></tr>"

    html += """
</tbody></table>
</div>
</div>
</div>

<script>
const timeSeriesCtx = document.getElementById('timeseries').getContext('2d');
new Chart(timeSeriesCtx, {
    type: 'line',
    data: {
        labels: """ + json.dumps(list(time_series.keys())) + "," + "\n" + """
        datasets: [{
            label: 'Attempts',
            data: """ + json.dumps(list(time_series.values())) + "," + "\n" + """
            fill: false,
            borderColor: 'red'
        }]
    }
});

const topIpsCtx = document.getElementById('topips').getContext('2d');
new Chart(topIpsCtx, {
    type: 'bar',
    data: {
        labels: """ + json.dumps(list(top_ips.keys())) + "," + "\n" + """
        datasets: [{
            label: 'Attempts',
            data: """ + json.dumps(list(top_ips.values())) + "," + "\n" + """
            backgroundColor: 'blue'
        }]
    }
});

const topUsersCtx = document.getElementById('topusers').getContext('2d');
new Chart(topUsersCtx, {
    type: 'bar',
    data: {
        labels: """ + json.dumps(list(top_users.keys())) + "," + "\n" + """
        datasets: [{
            label: 'Attempts',
            data: """ + json.dumps(list(top_users.values())) + "," + "\n" + """
            backgroundColor: 'green'
        }]
    }
});

$(document).ready(function() {
    $('#payloads').DataTable();
});
</script>
<footer class="text-center mt-5 mb-3 text-muted small">
    <p>
        &copy; 2025<span id="year"></span> Julien Mousqueton —
        <a href="https://github.com/JMousqueton/pot-de-miel" target="_blank" style="text-decoration: none; color: #6c757d;">
            <i class="fab fa-github"></i> pot-de-miel
        </a>
    </p>
</footer>

<script>
const yearSpan = document.getElementById('year');
const currentYear = new Date().getFullYear();
if (currentYear > 2025) {
    yearSpan.innerText = '-' + currentYear;
}
</script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""
    return html

def main():
    events = load_events(INPUT_LOG)

    times = defaultdict(int)
    ip_counter = Counter()
    user_counter = Counter()
    password_counter = Counter()
    command_list = []
    credential_counter = Counter()
    payloads = []

    for e in events:
        dt = e.get('timestamp', '')
        if dt:
            day = dt.split('T')[0]
            times[day] += 1
        if e.get('src_ip'):
            ip_counter[e['src_ip']] += 1
        if e.get('username'):
            user_counter[e['username']] += 1
        if e.get('password'):
            password_counter[e['password']] += 1
        if e.get('username') and e.get('password'):
            credential = f"{e['username']}:{e['password']}"
            credential_counter[credential] += 1
        if e.get('event') == 'command' and e.get('command'):
            command_list.append(e['command'])
        if e.get('event') == 'payload_downloaded':
            payloads.append(e)

    time_series = dict(sorted(times.items()))
    top_ips = dict(ip_counter.most_common(10))
    top_users = dict(user_counter.most_common(10))
    top_passwords = dict(password_counter.most_common(10))
    top_credentials = dict(credential_counter.most_common(10))
    commands = command_list

    html_content = generate_html(time_series, top_ips, top_users, top_passwords, top_credentials, commands, payloads)
    with open(OUTPUT_HTML, 'w') as f:
        f.write(html_content)

    print(f"[+] Report generated: {OUTPUT_HTML}")

if __name__ == "__main__":
    main()
