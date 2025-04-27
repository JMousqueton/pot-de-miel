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
<h1 class=\"mb-4 text-center\"><i class=\"fas fa-shield-alt\"></i> SSH Honeypot Dashboard</h1>

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
