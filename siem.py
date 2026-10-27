"""
Astro Job SA - SIEM v3.1 Enterprise Endless + Advanced Honeypot
Author: Mthembisi Motakone | SOC L2 | Deception Tech
Stack: Flask 3.1 | Python 3.11 | SAST | POPIA
"""

import os, time, secrets, hashlib, requests, json, logging
from flask import Blueprint, jsonify, render_template, request, session, redirect, abort, render_template_string
from collections import deque, Counter
from datetime import datetime, timedelta, timezone
from werkzeug.security import check_password_hash
from typing import Dict, Tuple

siem_bp = Blueprint('siem', __name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SIEM-v3.1")

# --- Stores ---
THREATS: deque = deque(maxlen=1500)
FAILED: Dict = {}
AUDIT: deque = deque(maxlen=200)
SESSION_STORE: Dict = {}
HONEYPOT_HITS: deque = deque(maxlen=1000)
FAKE_CREDS: deque = deque(maxlen=300)
BLACKLIST: Dict = {}
SAST = timezone(timedelta(hours=2))
STATS_FILE = "siem_stats.json"
BLACKLIST_FILE = "blacklist.json"

# --- Endless Stats ---
class EndlessStatsEngine:
    def __init__(self):
        self.total_ever=0; self.visits_ever=0; self.attacks_ever=0
        self.unique_ips_ever=set(); self.honeypot_ever=0
        self.started=datetime.now(SAST).isoformat()
        self.load()
    def load(self):
        try:
            if os.path.exists(STATS_FILE):
                with open(STATS_FILE) as f:
                    d=json.load(f)
                    self.total_ever=d.get("total_ever",0); self.visits_ever=d.get("visits_ever",0)
                    self.attacks_ever=d.get("attacks_ever",0); self.honeypot_ever=d.get("honeypot_ever",0)
                    self.unique_ips_ever=set(d.get("unique_ips_ever",[]))
                    self.started=d.get("started",self.started)
            if os.path.exists(BLACKLIST_FILE):
                with open(BLACKLIST_FILE) as f: BLACKLIST.update(json.load(f))
        except Exception as e: logger.warning(f"load fail {e}")
    def save(self):
        try:
            with open(STATS_FILE,"w") as f:
                json.dump({"total_ever":self.total_ever,"visits_ever":self.visits_ever,"attacks_ever":self.attacks_ever,"honeypot_ever":self.honeypot_ever,"unique_ips_ever":list(self.unique_ips_ever)[-5000:],"started":self.started},f)
            with open(BLACKLIST_FILE,"w") as f: json.dump(BLACKLIST,f)
        except: pass
    def inc(self, ip, is_attack=False, is_honeypot=False):
        self.total_ever+=1
        if is_honeypot: self.honeypot_ever+=1; self.attacks_ever+=1
        elif is_attack: self.attacks_ever+=1
        else: self.visits_ever+=1
        self.unique_ips_ever.add(ip)
        if self.total_ever%10==0: self.save()

STATS=EndlessStatsEngine()

SIEM_USER=os.getenv("SIEM_USER","admin").strip()
SIEM_HASH=os.getenv("SIEM_PASSWORD_HASH","").strip()
SIEM_ALLOW_IPS=[x.strip() for x in os.getenv("SIEM_ALLOW_IPS","").split(",") if x.strip()]

def now_sa(): return datetime.now(SAST)
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()[:16]

def get_geo(ip):
    try:
        if ip.startswith(("127.","10.","192.168.","172.","100.")): return -26.2041,28.0473,"Johannesburg [Internal]"
        r=requests.get(f"https://ipapi.co/{ip}/json/",timeout=1.2).json()
        return r.get('latitude',-26.2041),r.get('longitude',28.0473),r.get('city','Unknown')
    except: return -26.2041,28.0473,"Soweto"

def is_blacklisted(ip):
    rec=BLACKLIST.get(ip)
    if not rec: return False
    return rec.get('blocked_until',0) > time.time()

def add_blacklist(ip, reason):
    now=time.time()
    if ip not in BLACKLIST: BLACKLIST[ip]={'count':1,'first':now,'last':now,'reasons':[reason],'blocked_until':0}
    else:
        BLACKLIST[ip]['count']+=1; BLACKLIST[ip]['last']=now; BLACKLIST[ip]['reasons'].append(reason)
        BLACKLIST[ip]['reasons']=BLACKLIST[ip]['reasons'][-5:]
    if BLACKLIST[ip]['count']>=3: BLACKLIST[ip]['blocked_until']=now+24*3600; logger.warning(f"BLACKLISTED {ip} 24h")
    STATS.save()

class ThreatIntel:
    SIGS={'.env':'ENV Leak','.git':'Git Leak','wp-':'WP Scan','phpmyadmin':'phpMyAdmin Probe','<script':'XSS Attempt','onerror=':'XSS Event','union select':'SQLi UNION','or 1=1':'SQLi','../':'LFI Path Traversal','etc/passwd':'LFI','{{':'SSTI','base64_decode':'RCE Probe'}
    @classmethod
    def scan(cls, path_qs):
        low=path_qs.lower()
        for k,v in cls.SIGS.items():
            if k in low: return True,v
        return False,"Legit Visit"

@siem_bp.before_app_request
def siem_logger():
    if request.path.startswith(('/siem','/api/threats','/api/security-logs','/api/honeypot','/static','/ads.txt','/robots.txt','/health','/sitemap.xml')): return
    if request.path in ["/.env","/.git/config","/.git/HEAD","/wp-login.php","/wp-admin","/admin","/administrator","/phpmyadmin","/config.php","/backup.zip","/.aws/credentials"]:
        return
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if is_blacklisted(ip): return
    full=f"{request.path} {request.query_string.decode(errors='ignore')}"
    bad,reason=ThreatIntel.scan(full)
    lat,lng,city=get_geo(ip)
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Attack" if bad else "Visit","path":request.path[:250],"reason":reason,"time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":request.path[:200],"ua":request.headers.get('User-Agent','')[:80]})
    STATS.inc(ip, is_attack=bad)

def validate_session():
    if not session.get('siem_auth'): return False
    sid=session.get('sid')
    if not sid or sid not in SESSION_STORE: return False
    rec=SESSION_STORE[sid]
    cur_ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    cur_ua_hash=sha256(request.headers.get('User-Agent',''))
    if rec['ip']!=cur_ip or rec['ua_hash']!=cur_ua_hash: return False
    if time.time()-rec['created']>7*24*3600: SESSION_STORE.pop(sid,None); return False
    return True

# ================= ADVANCED HONEYPOT INSIDE SIEM =================

@siem_bp.route('/.env')
def honey_env():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    HONEYPOT_HITS.append({"ip":ip,"path":"/.env","city":city,"time":str(now_sa()),"type":"ENV Leak","ua":request.headers.get('User-Agent','')[:60]})
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":"HONEYPOT TRAP: /.env","reason":"Honeypot ENV Leak","time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":"TRAP:/.env","ua":request.headers.get('User-Agent','')[:80]})
    add_blacklist(ip,"/.env"); STATS.inc(ip, is_honeypot=True); time.sleep(1.5)
    return f"""APP_NAME=AstroJobSA
APP_ENV=production
APP_KEY=base64:FAKE_{secrets.token_hex(16)}_TRAPPED
DB_PASSWORD=TRAPPED_{ip}
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE_TRAP
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_HONEYPOT
HONEYPOT_ID={hashlib.md5(ip.encode()).hexdigest()[:8]}
""",200,{'Content-Type':'text/plain'}

@siem_bp.route('/.git/config')
@siem_bp.route('/.git/HEAD')
def honey_git():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Git Leak"})
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":f"HONEYPOT TRAP: {request.path}","reason":"Honeypot Git Leak","time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":f"TRAP:{request.path}","ua":""})
    add_blacklist(ip,request.path); STATS.inc(ip, is_honeypot=True); time.sleep(2)
    return "[core]\n\trepositoryformatversion=0\n[remote \"origin\"]\n\turl=https://github.com/astrojobsa/trap.git\n",200

@siem_bp.route('/wp-login.php', methods=["GET","POST"])
@siem_bp.route('/wp-admin', methods=["GET","POST"])
@siem_bp.route('/admin', methods=["GET","POST"])
@siem_bp.route('/administrator', methods=["GET","POST"])
def honey_admin():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    if request.method=="POST":
        user=request.form.get('username') or request.form.get('log') or request.form.get('user') or request.form.get('email') or "unknown"
        pw=request.form.get('password') or request.form.get('pwd') or request.form.get('pass') or "unknown"
        FAKE_CREDS.append({"ip":ip,"user":user,"pass":pw,"path":request.path,"city":city,"time":str(now_sa())})
        HONEYPOT_HITS.append({"ip":ip,"path":f"{request.path} LOGIN {user}:{pw[:20]}","city":city,"time":str(now_sa()),"type":"Admin Brute"})
        THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":f"HONEYPOT BRUTE: {user}:{pw[:10]}","reason":f"Honeypot Brute {user}","time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":f"TRAP:{request.path}","ua":request.headers.get('User-Agent','')[:80]})
        add_blacklist(ip,f"brute {user}"); STATS.inc(ip, is_honeypot=True); time.sleep(3)
        return render_template_string("""
        <html><body style="background:#0a0e1a;color:#ef4444;font-family:monospace;padding:40px">
        <h2>🔒 SIEM v3.1 - IP {{ip}} FLAGGED</h2><p>Location: {{city}}</p><p>Attempt: {{user}} / {{pw}}</p>
        <p>Your IP is now blacklisted for 24h. Incident ID: {{id}}</p>
        <p style="color:#22c55e">This honeypot captured your credentials for SOC analysis.</p></body></html>
        """, ip=ip, city=city, user=user, pw=pw, id=hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8]),200
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Admin Scan"})
    add_blacklist(ip,request.path)
    return """
    <html><head><title>WordPress Login</title></head>
    <body style="background:#f0f0f1;display:flex;justify-content:center;align-items:center;height:100vh">
    <div style="background:white;padding:30px;border-radius:4px;width:320px"><h1>WordPress</h1><form method=POST>
    <input name=log placeholder="Username" style="width:100%;padding:10px;margin:5px 0"><input name=pwd type=password placeholder="Password" style="width:100%;padding:10px;margin:5px 0">
    <button style="background:#2271b1;color:white;padding:10px;width:100%;border:none">Log In</button></form>
    <p style="font-size:10px;color:#999">Protected by SIEM v3.1 Honeypot</p></div></body></html>
    """,200

@siem_bp.route('/phpmyadmin')
@siem_bp.route('/config.php')
@siem_bp.route('/backup.zip')
@siem_bp.route('/.aws/credentials')
def honey_generic():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Config Probe"})
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":f"HONEYPOT TRAP: {request.path}","reason":f"Honeypot {request.path}","time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":f"TRAP:{request.path}","ua":""})
    add_blacklist(ip,request.path); STATS.inc(ip, is_honeypot=True); time.sleep(1)
    return f"404 - Trap logged for {ip}",404

# --- Auth Routes ---
@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if SIEM_ALLOW_IPS and ip not in SIEM_ALLOW_IPS: AUDIT.append(f"{now_sa()} BLOCK allowlist {ip}"); abort(403)
    if FAILED.get(ip,{}).get('count',0)>=5 and time.time()-FAILED[ip]['time']<300: return "<h3>🔒 SIEM Locked 5min<br><a href=/siem/login>Retry</a></h3>",429
    if request.method=="POST":
        u=request.form.get('username','').strip(); p=request.form.get('password','').strip()
        if not SIEM_HASH: return "<h3>SIEM_PASSWORD_HASH not set</h3>",500
        if u==SIEM_USER and check_password_hash(SIEM_HASH,p):
            FAILED.pop(ip,None); sid=secrets.token_urlsafe(32); session.clear(); session.permanent=True; session['siem_auth']=True; session['siem_user_id']=SIEM_USER; session['sid']=sid; session['login_time']=int(time.time())
            SESSION_STORE[sid]={'ip':ip,'ua_hash':sha256(request.headers.get('User-Agent','')),'created':time.time(),'user':SIEM_USER}
            if len(SESSION_STORE)>50: oldest=sorted(SESSION_STORE.items(), key=lambda x: x[1]['created'])[0][0]; SESSION_STORE.pop(oldest,None)
            AUDIT.append(f"{now_sa()} LOGIN OK {SIEM_USER} from {ip}"); return redirect('/siem')
        FAILED[ip]={'count':FAILED.get(ip,{}).get('count',0)+1,'time':time.time()}; AUDIT.append(f"{now_sa()} LOGIN FAIL {u} from {ip} ({FAILED[ip]['count']}/5)"); return f"<h3 style=color:#ef4444>❌ Wrong {FAILED[ip]['count']}/5</h3><a href=/siem/login>Retry</a>",401
    return f"""<html><head><title>SIEM v3.1 Honeypot - AstroJobSA</title><meta name=viewport content="width=device-width,initial-scale=1"></head>
    <body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:JetBrains Mono,monospace">
    <div style="background:#111827;padding:32px;border-radius:20px;width:400px;text-align:center;border:1px solid #1f2937;box-shadow:0 0 40px #22c55e22">
    <h2 style="letter-spacing:2px">🔒 SIEM v3.1 HONEYPOT</h2><p style="font-size:10px;color:#22c55e">ENDLESS • HONEYPOT • TARPIT • CRED-HARVEST • SAST</p>
    <p style="font-size:9px;color:#64748b">Total Ever: {STATS.total_ever} | Honeypot: {STATS.honeypot_ever} | Blacklisted: {len(BLACKLIST)}</p>
    <form method=POST><input name=username placeholder="Username" required style="width:100%;padding:14px;margin:10px 0;background:#020617;color:#fff;border:1px solid #334155;border-radius:10px">
    <input name=password type=password placeholder="Password" required style="width:100%;padding:14px;margin:10px 0;background:#020617;color:#fff;border:1px solid #334155;border-radius:10px">
    <button style="width:100%;padding:14px;background:linear-gradient(90deg,#22c55e,#16a34a);border:none;border-radius:10px;font-weight:900;color:#000">AUTHENTICATE</button></form></div></body></html>"""

@siem_bp.route('/siem/logout')
def logout():
    sid=session.get('sid')
    if sid: SESSION_STORE.pop(sid,None)
    session.clear(); return redirect('/siem/login')

@siem_bp.route('/siem')
def dashboard():
    if not validate_session(): session.clear(); return redirect('/siem/login')
    return render_template('siem_globe.html')

@siem_bp.route('/api/threats')
def threats_api():
    if not validate_session(): return jsonify({"error":"unauthorized"}),401
    return jsonify(list(THREATS))

@siem_bp.route('/api/security-logs')
def security_logs():
    if not validate_session(): return jsonify({"error":"unauthorized"}),401
    all_data=list(THREATS); legit=[x for x in all_data if x['type']=="Visit"][-25:][::-1]; malicious=[x for x in all_data if x['type']!="Visit"][-25:][::-1]
    return {"total":STATS.total_ever,"visits_ever":STATS.visits_ever,"blocked":STATS.attacks_ever,"honeypot_ever":STATS.honeypot_ever,"uniq":len(STATS.unique_ips_ever),"bots":STATS.attacks_ever,"total_window":len(all_data),"blocked_window":len([x for x in all_data if x['type']!="Visit"]),"uniq_window":len(set([x['ip'] for x in all_data])),"hours":["5h ago","4h ago","3h ago","2h ago","1h ago","now"],"visits":[max(1,len(legit)//6)]*6,"attacks":[max(0,len(malicious)//6)]*6,"attackTypes":dict(Counter([x.get('reason','/') for x in malicious])) or {"Legit":len(legit)},"legit":[{"ip":x['ip'],"page":x['page'],"time":x['time']} for x in legit],"malicious":[{"ip":x['ip'],"reason":x['reason'],"time":x['time'],"city":x.get('city')} for x in malicious],"server_time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"active_sessions":len(SESSION_STORE),"audit":list(AUDIT)[-10:],"started":STATS.started,"endless":True,"version":"3.1 Honeypot"}

@siem_bp.route('/api/honeypot')
def honeypot_api():
    if not validate_session(): return jsonify({"error":"unauthorized"}),401
    return jsonify({"total_trapped":STATS.honeypot_ever,"current_hits":len(HONEYPOT_HITS),"blacklisted":len([k for k,v in BLACKLIST.items() if v.get('blocked_until',0)>time.time()]),"total_blacklist":len(BLACKLIST),"hits":list(HONEYPOT_HITS)[-50:][::-1],"creds":list(FAKE_CREDS)[-20:][::-1],"blacklist":sorted([{"ip":k,"count":v['count'],"last":str(datetime.fromtimestamp(v['last'], SAST)),"reasons":v['reasons'][-2:]} for k,v in BLACKLIST.items()], key=lambda x: x['count'], reverse=True)[:20]})
