import os, time, secrets, hashlib, requests
from flask import Blueprint, jsonify, render_template, request, session, redirect, abort
from collections import deque, Counter
from datetime import datetime, timedelta, timezone
from werkzeug.security import check_password_hash

siem_bp = Blueprint('siem', __name__)

# --- Advanced Threat Store ---
THREATS = deque(maxlen=1500)
FAILED = {}
AUDIT = deque(maxlen=200)
SAST = timezone(timedelta(hours=2))
SESSION_STORE = {} # server-side session validation {sid: {ip, ua_hash, created}}

SIEM_USER = os.getenv("SIEM_USER", "admin").strip()
SIEM_HASH = os.getenv("SIEM_PASSWORD_HASH", "").strip() # REQUIRED - bcrypt
SIEM_ALLOW_IPS = [x.strip() for x in os.getenv("SIEM_ALLOW_IPS","").split(",") if x.strip()] # optional allowlist

def now_sa(): return datetime.now(SAST)
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()[:16]

def get_geo(ip):
    try:
        if ip.startswith(("127.","10.","192.168.","172.","100.")):
            return -26.2041, 28.0473, "Johannesburg [Internal]"
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=1.5).json()
        return r.get('latitude', -26.2041), r.get('longitude', 28.0473), r.get('city','Unknown')
    except: return -26.2041, 28.0473, "Soweto"

def is_attack(path_qs: str):
    sigs = {
        '.env': 'ENV Leak', '.git': 'Git Leak', 'wp-': 'WP Scan',
        'phpmyadmin': 'phpMyAdmin Probe', '<script': 'XSS Attempt',
        'onerror=': 'XSS Event', 'union select': 'SQLi UNION', 'or 1=1': 'SQLi',
        '../': 'LFI Path Traversal', 'etc/passwd': 'LFI', '{{': 'SSTI',
        'base64_decode': 'RCE Probe'
    }
    low = path_qs.lower()
    for k,v in sigs.items():
        if k in low: return True, v
    return False, "Legit Visit"

@siem_bp.before_app_request
def siem_logger():
    # Skip own assets to avoid loop
    if request.path.startswith(('/siem','/api/threats','/api/security-logs','/static')):
        return
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    full = f"{request.path} {request.query_string.decode(errors='ignore')}"
    bad, reason = is_attack(full)
    lat,lng,city = get_geo(ip)
    THREATS.append({
        "ip": ip, "lat": lat, "lng": lng, "city": city,
        "type": "Attack" if bad else "Visit",
        "path": request.path[:250] + (f"?{request.query_string.decode()[:150]}" if request.query_string else ""),
        "reason": reason, "time": now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),
        "page": request.path[:200], "ua": request.headers.get('User-Agent','')[:80]
    })

def validate_session() -> bool:
    """Advanced session validation: server-side binding"""
    if not session.get('siem_auth'): return False
    sid = session.get('sid')
    if not sid or sid not in SESSION_STORE: return False
    rec = SESSION_STORE[sid]
    cur_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    cur_ua_hash = sha256(request.headers.get('User-Agent',''))
    # IP binding + UA binding + 7 day expiry
    if rec['ip']!= cur_ip: return False
    if rec['ua_hash']!= cur_ua_hash: return False
    if time.time() - rec['created'] > 7*24*3600:
        SESSION_STORE.pop(sid, None)
        return False
    return True

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    # IP Allowlist (optional hardening)
    if SIEM_ALLOW_IPS and ip not in SIEM_ALLOW_IPS:
        AUDIT.append(f"{now_sa()} BLOCK allowlist {ip}")
        abort(403)

    # Brute-force shield
    if FAILED.get(ip,{}).get('count',0) >= 5 and time.time() - FAILED[ip]['time'] < 300:
        return "<h3>🔒 SIEM Locked 5min - Brute force detected<br><a href=/siem/login>Retry</a></h3>",429

    if request.method == "POST":
        u = request.form.get('username','').strip()
        p = request.form.get('password','').strip()

        if not SIEM_HASH:
            return "<h3>Server misconfigured: SIEM_PASSWORD_HASH not set. Contact admin.</h3>",500

        if u == SIEM_USER and check_password_hash(SIEM_HASH, p):
            FAILED.pop(ip, None)
            sid = secrets.token_urlsafe(32)
            session.clear()
            session.permanent = True
            session['siem_auth'] = True
            session['siem_user_id'] = SIEM_USER
            session['sid'] = sid
            session['login_time'] = int(time.time())
            SESSION_STORE[sid] = {
                'ip': ip,
                'ua_hash': sha256(request.headers.get('User-Agent','')),
                'created': time.time(),
                'user': SIEM_USER
            }
            # cleanup old sessions
            if len(SESSION_STORE) > 50:
                oldest = sorted(SESSION_STORE.items(), key=lambda x: x[1]['created'])[0][0]
                SESSION_STORE.pop(oldest, None)
            AUDIT.append(f"{now_sa()} LOGIN OK {SIEM_USER} from {ip}")
            return redirect('/siem')

        FAILED[ip] = {'count': FAILED.get(ip,{}).get('count',0)+1, 'time': time.time()}
        AUDIT.append(f"{now_sa()} LOGIN FAIL {u} from {ip} ({FAILED[ip]['count']}/5)")
        return f"<h3 style=color:#ef4444>❌ Wrong {FAILED[ip]['count']}/5</h3><a href=/siem/login>Retry</a>",401

    return """<html><head><title>SIEM - AstroJobSA</title><meta name=viewport content="width=device-width,initial-scale=1"></head>
    <body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:JetBrains Mono,monospace">
    <div style="background:#111827;padding:32px;border-radius:20px;width:360px;text-align:center;border:1px solid #1f2937;box-shadow:0 0 40px #22c55e22">
    <h2 style="letter-spacing:2px">🔒 SIEM v2.5</h2><p style="font-size:10px;color:#64748b">IP-Bound • UA-Bound • Server-Side Session • SAST</p>
    <form method=POST><input name=username placeholder="Username" required style="width:100%;padding:14px;margin:10px 0;background:#020617;color:#fff;border:1px solid #334155;border-radius:10px">
    <input name=password type=password placeholder="Password" required style="width:100%;padding:14px;margin:10px 0;background:#020617;color:#fff;border:1px solid #334155;border-radius:10px">
    <button style="width:100%;padding:14px;background:linear-gradient(90deg,#22c55e,#16a34a);border:none;border-radius:10px;font-weight:900;letter-spacing:1px;color:#000">AUTHENTICATE</button></form>
    <p style="font-size:9px;color:#334155;margin-top:14px">Failed logins are logged & geo-mapped</p></div></body></html>"""

@siem_bp.route('/siem/logout')
def logout():
    sid = session.get('sid')
    if sid: SESSION_STORE.pop(sid, None)
    session.clear()
    return redirect('/siem/login')

@siem_bp.route('/siem')
def dashboard():
    if not validate_session():
        session.clear()
        return redirect('/siem/login')
    return render_template('siem_globe.html')

@siem_bp.route('/api/threats')
def threats_api():
    if not validate_session(): return jsonify({"error":"unauthorized","code":"SESSION_INVALID"}),401
    return jsonify(list(THREATS))

@siem_bp.route('/api/security-logs')
def security_logs():
    if not validate_session(): return jsonify({"error":"unauthorized"}),401
    all_data = list(THREATS)
    legit = [x for x in all_data if x['type']=="Visit"][-25:][::-1]
    malicious = [x for x in all_data if x['type']=="Attack"][-25:][::-1]
    total = len(all_data); blocked = len([x for x in all_data if x['type']=="Attack"]); uniq = len(set([x['ip'] for x in all_data]))
    return {
        "total": total, "blocked": blocked, "uniq": uniq, "bots": blocked,
        "hours": ["5h ago","4h ago","3h ago","2h ago","1h ago","now"],
        "visits": [max(1, len(legit)//6)]*6,
        "attacks": [max(0, blocked//6)]*6,
        "attackTypes": dict(Counter([x.get('reason','/') for x in malicious])) or {"Legit": len(legit)},
        "legit": [{"ip": x['ip'], "page": x['page'], "time": x['time']} for x in legit],
        "malicious": [{"ip": x['ip'], "reason": x['reason'], "time": x['time'], "city": x.get('city')} for x in malicious],
        "server_time": now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),
        "active_sessions": len(SESSION_STORE),
        "audit": list(AUDIT)[-10:]
    }
