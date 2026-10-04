import os
from flask import Blueprint, jsonify, render_template, request, session, redirect
from collections import deque, Counter
from datetime import datetime
import requests
import time

siem_bp = Blueprint('siem', __name__)
THREATS = deque(maxlen=500)
FAILED = {}

SIEM_USER = (os.getenv("SIEM_USER") or "admin").strip()
SIEM_PASS = (os.getenv("SIEM_PASSWORD") or os.getenv("SIEM_PASS") or "change-me").strip()

def get_geo(ip):
    try:
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192."):
            return -26.2041, 28.0473, "Johannesburg"
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2).json()
        return r.get('latitude', -26.2), r.get('longitude', 28.0), r.get('city','Unknown')
    except:
        return -26.2041, 28.0473, "Soweto"

@siem_bp.before_app_request
def log_request():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    p = request.path.lower()
    if p.startswith('/siem') or p.startswith('/api/') or p.startswith('/debug'):
        return
    query = request.query_string.decode().lower() if request.query_string else ""
    full = f"{p} {query} {str(request.args).lower()}"
    sigs = {'.env': 'ENV Leak','.git': 'Git Leak','wp-': 'WP Scan','phpmyadmin': 'phpMyAdmin','<script': 'XSS','onerror': 'XSS onerror','img src': 'XSS img','{{': 'SSTI','or 1=1': 'SQLi','union select': 'SQLi UNION','../': 'LFI'}
    is_bad = False
    reason = "Legit Visit"
    for k,v in sigs.items():
        if k in full:
            is_bad = True
            reason = v
            break
    lat,lng,city = get_geo(ip)
    THREATS.append({"ip": ip, "lat": lat, "lng": lng, "city": city, "type": "Attack" if is_bad else "Visit", "path": request.path + (f"?{request.query_string.decode()}" if request.query_string else ""), "reason": reason, "time": datetime.now().strftime("%H:%M:%S"), "page": request.path, "time_str": datetime.now().strftime("%H:%M:%S")})

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if FAILED.get(ip, {}).get('count',0) >= 5 and time.time() - FAILED[ip]['time'] < 300:
        return "<h3>Too many attempts. Try again in 5 minutes.</h3>", 429
    if request.method == "POST":
        u = request.form.get('username','').strip()
        p = request.form.get('password','').strip()
        if u==SIEM_USER and p==SIEM_PASS:
            FAILED.pop(ip, None)
            session.permanent = True
            session['siem_auth'] = True
            session['siem_user'] = u
            return redirect('/siem')
        FAILED[ip] = {'count': FAILED.get(ip, {}).get('count',0)+1, 'time': time.time()}
        return "<h3 style=color:red>Wrong username or password. <a href=/siem/login>Retry</a></h3>", 401
    return """<html><body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif"><div style="background:#111827;padding:30px;border-radius:16px;width:320px;text-align:center;border:1px solid #333"><h2>SIEM Login</h2><p style="font-size:11px;color:#94a3b8">7-day login - © 2026 Astro Job SA - Made by Mthembisi</p><form method=POST><input name=username placeholder="Username" required style="width:100%;padding:12px;margin:6px 0;background:#000;color:#fff;border:1px solid #333;border-radius:8px"><input name=password type=password placeholder="Password" required style="width:100%;padding:12px;margin:6px 0;background:#000;color:#fff;border:1px solid #333;border-radius:8px"><button style="width:100%;padding:12px;background:#22c55e;border:none;border-radius:8px;font-weight:800">LOGIN - Stay 7 Days</button></form></div></body></html>"""

@siem_bp.route('/siem/logout')
def logout():
    session.pop('siem_auth',None)
    session.pop('siem_user',None)
    return redirect('/siem/login')

@siem_bp.route('/siem')
def dashboard():
    if not session.get('siem_auth'):
        return redirect('/siem/login')
    return render_template('siem_globe.html')

@siem_bp.route('/api/threats')
def threats_api():
    if not session.get('siem_auth'):
        return jsonify({"error":"login"}), 401
    return jsonify(list(THREATS))

@siem_bp.route('/api/security-logs')
def security_logs():
    if not session.get('siem_auth'):
        return jsonify({"error":"login"}), 401
    all_data = list(THREATS)
    legit = [x for x in all_data if x['type']=="Visit"][-20:][::-1]
    malicious = [x for x in all_data if x['type']=="Attack"][-20:][::-1]
    total = len(all_data); blocked = len(malicious); uniq = len(set([x['ip'] for x in all_data]))
    return {"total": total, "blocked": blocked, "uniq": uniq, "bots": blocked, "hours": ["5h ago","4h ago","3h ago","2h ago","1h ago","now"], "visits": [len(legit)//6+1]*6, "attacks": [blocked//6+1]*6, "attackTypes": dict(Counter([x.get('reason','/') for x in malicious])) or {"Legit": len(legit)}, "legit": [{"ip": x['ip'], "page": x['page'], "time": x['time']} for x in legit], "malicious": [{"ip": x['ip'], "reason": x['reason'], "time": x['time']} for x in malicious]}
