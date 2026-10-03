from flask import Blueprint, jsonify, render_template, request, session, redirect
from collections import deque
from datetime import datetime
import requests

siem_bp = Blueprint('siem', __name__)
THREATS = deque(maxlen=100)

SIEM_USER = "admin"
SIEM_PASS = "Astro2026!"

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
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    path = request.path
    if any(x in path for x in ['/admin','/.env','wp-','.git','/login','phpmyadmin','/config','/backup']):
        lat,lng,city = get_geo(ip)
        THREATS.append({"ip": ip, "lat": lat, "lng": lng, "city": city, "type": f"Probe {path}", "path": path, "time": datetime.now().strftime("%H:%M:%S")})

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    if request.method == "POST":
        if request.form.get('username') == SIEM_USER and request.form.get('password') == SIEM_PASS:
            session['siem_auth'] = True
            return redirect('/siem')
        return "<h3 style='color:red'>Wrong! <a href=/siem/login>Try again</a></h3>"
    return """<html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>SIEM Login</title></head>
<body style="background:#0a0e1a;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="background:#111827;padding:30px;border-radius:16px;width:320px;text-align:center;border:1px solid #333">
<h2>🛡️ ASTRO SIEM</h2><p style="color:#888">Login to see FULL IPs</p>
<form method="POST"><input name="username" placeholder="admin" required style="width:100%;padding:12px;margin:8px 0;border-radius:8px;background:#000;color:#fff;border:1px solid #333">
<input name="password" type="password" placeholder="Astro2026!" required style="width:100%;padding:12px;margin:8px 0;border-radius:8px;background:#000;color:#fff;border:1px solid #333">
<button style="width:100%;padding:12px;background:#22c55e;border:none;border-radius:8px;font-weight:800;cursor:pointer">LOGIN</button></form>
</div></body></html>"""

@siem_bp.route('/siem/logout')
def logout():
    session.pop('siem_auth', None)
    return redirect('/siem/login')

@siem_bp.before_request
def protect():
    if request.path.startswith('/siem') and request.path not in ['/siem/login','/siem/logout']:
        if not session.get('siem_auth'):
            return redirect('/siem/login')
    if request.path.startswith('/api/threats'):
        if not session.get('siem_auth'):
            return redirect('/siem/login')

@siem_bp.route('/api/threats')
def threats_api():
    return jsonify(list(THREATS))

@siem_bp.route('/siem')
def dashboard():
    return render_template('siem_globe.html')
