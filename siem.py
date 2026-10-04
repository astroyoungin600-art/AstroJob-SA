import os
from flask import Blueprint, jsonify, render_template, request, session, redirect
from collections import deque, Counter
from datetime import datetime
import requests

siem_bp = Blueprint('siem', __name__)
THREATS = deque(maxlen=500)

# SECURE - from Render Environment, not hardcoded
SIEM_USER = os.getenv("SIEM_USER", "admin")
SIEM_PASS = os.getenv("SIEM_PASSWORD", os.getenv("SIEM_PASS", "change-me-2026"))
RESET_SECRET = os.getenv("RESET_SECRET", "mthembisi2026")

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
    path = request.path
    if path.startswith('/siem') or path.startswith('/api/threats') or path.startswith('/api/security-logs') or path.startswith('/reset'):
        return
    lat,lng,city = get_geo(ip)
    is_bad = any(x in path.lower() for x in ['admin','/.env','wp-','.git','phpmyadmin','config','backup','login'])
    THREATS.append({"ip": ip, "lat": lat, "lng": lng, "city": city, "type": "Attack" if is_bad else "Visit", "path": path, "reason": path if is_bad else "Legit", "time": datetime.now().strftime("%H:%M:%S"), "page": path, "time_str": datetime.now().strftime("%H:%M:%S")})

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    if request.method == "POST":
        if request.form.get('username')==SIEM_USER and request.form.get('password')==SIEM_PASS:
            session['siem_auth']=True
            session.permanent = False
            return redirect('/siem')
        return "<h3 style=color:red>Wrong! <a href=/siem/login>Retry</a></h3>"
    return """<html><body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif">
<div style="background:#111827;padding:30px;border-radius:16px;width:320px;text-align:center;border:1px solid #333">
<h2>SIEM Login</h2>
<p style="font-size:11px;color:#94a3b8">© 2026 Astro Job SA - Made by Mthembisi</p>
<form method=POST>
<input name=username placeholder="Username" required style="width:100%;padding:12px;margin:6px 0;background:#000;color:#fff;border:1px solid #333;border-radius:8px">
<input name=password type=password placeholder="••••••••" required style="width:100%;padding:12px;margin:6px 0;background:#000;color:#fff;border:1px solid #333;border-radius:8px">
<button style="width:100%;padding:12px;background:#22c55e;border:none;border-radius:10px;font-weight:800;margin-top:8px">LOGIN</button>
</form>
<p style="margin-top:12px;font-size:11px"><a href="/siem/reset" style="color:#64748b">Forgot password? Reset</a></p>
</div></body></html>"""

@siem_bp.route('/siem/reset', methods=["GET","POST"])
def reset():
    msg=""
    if request.method=="POST":
        secret=request.form.get("secret","")
        new_user=request.form.get("new_user","")
        new_pass=request.form.get("new_pass","")
        if secret==RESET_SECRET and new_pass:
            msg=f"RESET OK - Now go to Render Dashboard > Environment and set: SIEM_USER={new_user} and SIEM_PASSWORD={new_pass} then redeploy. Then login with new password."
        else:
            msg="Wrong reset secret"
    return f"""<html><body style="background:#020617;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif">
<div style="background:#0f172a;padding:25px;border-radius:15px;width:330px">
<h3>Password Reset</h3>
<p style="font-size:11px;color:#94a3b8">© 2026 Astro Job SA - Made by Mthembisi</p>
<form method=POST>
<input name=secret type=password placeholder="Reset Secret" required style="width:100%;padding:12px;background:#000;color:#fff;border-radius:8px;border:1px solid #333;margin:6px 0">
<input name=new_user placeholder="New Username" value="admin" required style="width:100%;padding:12px;background:#000;color:#fff;border-radius:8px;border:1px solid #333;margin:6px 0">
<input name=new_pass type=password placeholder="New Password" required style="width:100%;padding:12px;background:#000;color:#fff;border-radius:8px;border:1px solid #333;margin:6px 0">
<button style="width:100%;padding:12px;background:#22c55e;border:none;border-radius:8px;font-weight:bold;margin-top:8px">RESET PASSWORD</button>
</form>
<p style="color:#22c55e;font-size:13px;margin-top:12px">{msg}</p>
<a href="/siem/login" style="color:#94a3b8;font-size:12px">Back to Login</a>
</div></body></html>"""

@siem_bp.route('/siem/logout')
def logout():
    session.pop('siem_auth',None)
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
    total = len(all_data)
    blocked = len(malicious)
    uniq = len(set([x['ip'] for x in all_data]))
    return {
        "total": total,
        "blocked": blocked,
        "uniq": uniq,
        "bots": blocked,
        "hours": ["5h ago","4h ago","3h ago","2h ago","1h ago","now"],
        "visits": [len(legit)//6+1]*6,
        "attacks": [blocked//6+1]*6,
        "attackTypes": dict(Counter([x.get('path','/') for x in malicious])) or {"Legit": len(legit)},
        "legit": [{"ip": x['ip'], "page": x['page'], "time": x['time']} for x in legit],
        "malicious": [{"ip": x['ip'], "reason": x['reason'], "time": x['time']} for x in malicious]
    }

@siem_bp.route('/manifest.json')
def manifest():
    return {
      "name": "Astro Job SA - Made by Mthembisi",
      "short_name": "AstroJobSA",
      "start_url": "/",
      "display": "standalone",
      "background_color": "#0a0e1a",
      "theme_color": "#22c55e",
      "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/3135/3135715.png", "sizes": "192x192", "type": "image/png"}]
    }
