from flask import Blueprint, jsonify, render_template, request
from collections import deque
from datetime import datetime
import requests

siem_bp = Blueprint('siem', __name__)
THREATS = deque(maxlen=100)

def get_geo(ip):
    try:
        if ip.startswith("127.") or ip.startswith("10."):
            return -26.2041, 28.0473, "Soweto"
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=1.5).json()
        return r.get('latitude', -26.2), r.get('longitude', 28.0), r.get('city','Unknown')
    except:
        return -26.2041, 28.0473, "Soweto"

@siem_bp.before_app_request
def log_request():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    path = request.path
    if any(x in path for x in ['/admin','/.env','wp-','.git','/login','phpmyadmin']):
        lat,lng,city = get_geo(ip)
        THREATS.append({"ip": ip, "lat": lat, "lng": lng, "city": city, "type": f"Probe {path}", "path": path, "time": datetime.now().strftime("%H:%M:%S")})

@siem_bp.route('/api/threats')
def threats_api():
    return jsonify(list(THREATS))

@siem_bp.route('/siem')
def dashboard():
    return render_template('siem_globe.html')
