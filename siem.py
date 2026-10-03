from flask import Blueprint, jsonify, render_template, request, session, redirect
from collections import deque
from datetime import datetime
import requests

siem_bp = Blueprint('siem', __name__)
THREATS = deque(maxlen=200)

SIEM_USER = "admin"
SIEM_PASS = "Astro2026!"

def get_geo(ip):
    try:
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168"):
            return -26.2041, 28.0473, "Johannesburg (Local)"
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2).json()
        return r.get('latitude', -26.2), r.get('longitude', 28.0), r.get('city','Unknown')
    except:
        return -26.2041, 28.0473, "Soweto"

@siem_bp.before_app_request
def log_request():
    # LOG ALL REQUESTS for visibility
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    path = request.path
    # Log if suspicious OR show all for demo
    if any(x in path.lower() for x in ['/admin','/.env','wp-','.git','/login','phpmyadmin','/config']) or len(THREATS)<5:
        lat,lng,city = get_geo(ip)
        THREATS.append({"ip": ip, "lat": lat, "lng": lng, "city": city, "type": f"Visit {path}", "path": path, "time": datetime.now().strftime("%H:%M:%S")})

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    if request.method == "POST":
        if request.form.get('username')==SIEM_USER and request.form.get('password')==SIEM_PASS:
            session['siem_auth']=True
            return redirect('/siem')
        return "<h3 style=color:red>Wrong! <a href=/siem/login>Retry</a></h3>"
    return """<html><body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif"><div style="background:#111827;padding:30px;border-radius:16px;width:320px;text-align:center"><h2>🛡️ SIEM Login</h2><form method=POST><input name=username placeholder=admin required style="width:100%;padding:10px;margin:6px 0"><input name=password type=password placeholder=Astro2026! required style="width:100%;padding:10px;margin:6px 0"><button style="width:100%;padding:10px;background:#22c55e;border:none;border-radius:8px">LOGIN</button></form></div></body></html>"""

@siem_bp.route('/siem/logout')
def logout():
    session.pop('siem_auth',None)
    return redirect('/siem/login')

@siem_bp.route('/api/threats')
def threats_api():
    if not session.get('siem_auth'):
        return jsonify({"error":"login required"}), 401
    return jsonify(list(THREATS))

@siem_bp.route('/siem')
def dashboard():
    if not session.get('siem_auth'):
        return redirect('/siem/login')
    return render_template('siem_globe.html')
