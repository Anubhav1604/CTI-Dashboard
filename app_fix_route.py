from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from weasyprint import HTML
from datetime import datetime
from flask import redirect, url_for
from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from pymongo import MongoClient
import os
import requests
from datetime import datetime
from bson.son import SON
import csv
from io import StringIO
import subprocess
from lxml import etree
from flask import render_template

app = Flask(__name__)
app.secret_key = '9369'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

socketio = SocketIO(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        if user_id == 'admin' and password == 'password':
            user = User(user_id)
            login_user(user)
            return redirect(url_for('index'))
        return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

CORS(app)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client.cti_dashboard

VIRUSTOTAL_API_KEY = os.getenv("66fce07d44a73423df6e61e953a351b0b3bd928dd2d43d32568683c9996c36cb")
ABUSEIPDB_API_KEY = os.getenv("49e3138ba01220f68e09f61c84278f4a9c2b2796b8d6a68822597eee2c54578bb685dd93bd984d37")

def fetch_virustotal_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def fetch_abuseipdb_data(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return None

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/lookup', methods=['POST'])
def lookup():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address required"}), 400

    vt_data = fetch_virustotal_data(ip)
    abuse_data = fetch_abuseipdb_data(ip)

    db.lookups.insert_one({
        "ip": ip,
        "virustotal": vt_data,
        "abuseipdb": abuse_data,
        "timestamp": datetime.utcnow()
    })

    return jsonify({
        "virustotal": vt_data,
        "abuseipdb": abuse_data
    })

@app.route('/api/trends', methods=['GET'])
def trends():
    pipeline = [
        {
            "$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }
        },
        {"$sort": SON([("_id", 1)])}
    ]
    results = list(db.lookups.aggregate(pipeline))
    return jsonify(results)

@app.route('/api/tag', methods=['POST'])
def tag():
    data = request.json
    ip = data.get('ip')
    tag = data.get('tag')
    if not ip or not tag:
        return jsonify({"error": "IP and tag required"}), 400

    db.tags.update_one({"ip": ip}, {"$addToSet": {"tags": tag}}, upsert=True)
    return jsonify({"message": "Tag added"})

@app.route('/api/export', methods=['GET'])
def export():
    lookups = db.lookups.find()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['IP', 'Timestamp', 'VirusTotal', 'AbuseIPDB'])
    for lookup in lookups:
        cw.writerow([
            lookup.get('ip'),
            lookup.get('timestamp'),
            str(lookup.get('virustotal')),
            str(lookup.get('abuseipdb'))
        ])
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=cti_export.csv"})

@socketio.on('connect')
def handle_connect():
    emit('alert', {'data': 'Connected to real-time alerts'})

def send_alert(ip, threat_type):
    socketio.emit('alert', {
        'ip': ip,
        'threat': threat_type,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/preview-report')
@login_required
def preview_report():
    lookups = list(db.lookups.find())
    return render_template('report_template.html', lookups=lookups, datetime=datetime)

def run_nmap_scan(target):
    result = subprocess.run(['nmap', '-sV', target, '-oX', '-'], capture_output=True, text=True)
    return result.stdout

def parse_nmap_xml(xml_data):
    root = etree.fromstring(xml_data.encode())
    hosts = []
    for host in root.findall('host'):
        addr_elem = host.find('address')
        if addr_elem is None:
            continue
        addr = addr_elem.get('addr')
        ports = []
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            state = port.find('state').get('state')
            service_elem = port.find('service')
            service = service_elem.get('name') if service_elem is not None else 'unknown'
            version = service_elem.get('version') if service_elem is not None else ''
            ports.append({'port': port_id, 'state': state, 'service': service, 'version': version})
        hosts.append({'address': addr, 'ports': ports})
    return hosts

@app.route('/api/scan', methods=['POST'])
def api_scan():
    target = request.json.get('target')
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    xml_output = run_nmap_scan(target)
    scan_results = parse_nmap_xml(xml_output)
    return jsonify(scan_results)

@app.route('/api/report', methods=['POST'])
def api_report():
    html_content = request.json.get('html')
    if not html_content:
        return jsonify({'error': 'HTML content is required'}), 400
    pdf = HTML(string=html_content).write_pdf()
    return (pdf, 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="scan_report.pdf"'
    })


if __name__ == '__main__':
    socketio.run(app, debug=True)
