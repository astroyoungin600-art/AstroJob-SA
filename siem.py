"""
SIEM v3.2 CRAZY - Fixed
"""
import os, time, secrets, hashlib, json, logging
try:
    import requests
except:
    requests = None
from flask import Blueprint, jsonify, render_template, request, session, redirect, abort, render_template_string
from collections import deque, Counter
from datetime import datetime, timedelta, timezone
from werkzeug.security import check_password_hash

siem_bp = Blueprint('siem', __name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SIEM-v3.2")

THREATS = deque(maxlen=2000)
FAILED = {}
AUDIT = deque(maxlen=200)
SESSION_STORE = {}
HONEYPOT_HITS = deque(maxlen=1000)
FAKE_CREDS = deque(maxlen=500)
BLACKLIST = {}
SAST = timezone(timedelta(hours=2))
STATS_FILE = "siem_stats.json"
BLACKLIST_FILE = "blacklist.json"

class EndlessStatsEngine:
    def __init__(self):
        self.total_ever=0; self.visits_ever=0; self.attacks_ever=0; self.honeypot_ever=0
        self.unique_ips_ever=set(); self.malware_ever=0
        self.started=datetime.now(SAST).isoformat()
        self.load()
    def load(self):
        try:
            if os.path.exists(STATS_FILE):
                with open(STATS_FILE) as f:
                    d=json.load(f)
                    self.total_ever=d.get("total_ever",0); self.visits_ever=d.get("visits_ever",0)
                    self.attacks_ever=d.get("attacks_ever",0); self.honeypot_ever=d.get("honeypot_ever",0)
                    self.malware_ever=d.get("malware_ever",0)
                    self.unique_ips_ever=set(d.get("unique_ips_ever",[]))
        except: pass
    def save(self):
        try:
            with open(STATS_FILE,"w") as f:
                json.dump({"total_ever":self.total_ever,"visits_ever":self.visits_ever,"attacks_ever":self.attacks_ever,"honeypot_ever":self.honeypot_ever,"malware_ever":self.malware_ever,"unique_ips_ever":list(self.unique_ips_ever)[-5000:],"started":self.started},f)
            with open(BLACKLIST_FILE,"w") as f: json.dump(BLACKLIST,f)
        except: pass
    def inc(self, ip, is_attack=False, is_honeypot=False, is_malware=False):
        self.total_ever+=1
        if is_malware: self.malware_ever+=1; self.honeypot_ever+=1; self.attacks_ever+=1
        elif is_honeypot: self.honeypot_ever+=1; self.attacks_ever+=1
        elif is_attack: self.attacks_ever+=1
        else: self.visits_ever+=1
        self.unique_ips_ever.add(ip)
        if self.total_ever%5==0: self.save()

STATS=EndlessStatsEngine()
SIEM_USER=os.getenv("SIEM_USER","admin").strip()
SIEM_HASH=os.getenv("SIEM_PASSWORD_HASH","").strip()
SIEM_ALLOW_IPS=[x.strip() for x in os.getenv("SIEM_ALLOW_IPS","").split(",") if x.strip()]

def now_sa(): return datetime.now(SAST)
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()[:16]
def get_geo(ip):
    try:
        if ip.startswith(("127.","10.","192.168.","172.","100.")): return -26.2041,28.0473,"Johannesburg [Internal]"
        if requests:
            r=requests.get(f"https://ipapi.co/{ip}/json/",timeout=1.2).json()
            return r.get('latitude',-26.2041),r.get('longitude',28.0473),r.get('city','Unknown')
        return -26.2041,28.0473,"Unknown"
    except: return -26.2041,28.0473,"Soweto"
def is_blacklisted(ip): return BLACKLIST.get(ip,{}).get('blocked_until',0) > time.time()
def add_blacklist(ip, reason):
    now=time.time()
    if ip not in BLACKLIST: BLACKLIST[ip]={'count':1,'first':now,'last':now,'reasons':[reason],'blocked_until':0}
    else: BLACKLIST[ip]['count']+=1; BLACKLIST[ip]['last']=now; BLACKLIST[ip]['reasons'].append(reason)
    if BLACKLIST[ip]['count']>=3: BLACKLIST[ip]['blocked_until']=now+24*3600
    STATS.save()

class ThreatIntel:
    SIGS={'.env':'ENV Leak','.git':'Git Leak','wp-':'WP Scan','<script':'XSS','union select':'SQLi','../':'LFI','{{':'SSTI','jndi:':'Log4Shell'}
    @classmethod
    def scan(cls, p):
        low=p.lower()
        for k,v in cls.SIGS.items():
            if k in low: return True,v
        return False,"Legit Visit"

@siem_bp.before_app_request
def siem_logger():
    if request.path.startswith(('/siem','/api/threats','/api/security-logs','/api/honeypot','/static','/ads.txt','/robots.txt','/health','/api/honeypot/fp')): return
    if request.path in ["/.env","/.git/config","/.git/HEAD","/wp-login.php","/wp-admin","/admin","/administrator","/phpmyadmin","/config.php","/backup.zip","/.aws/credentials","/upload.php","/file_upload.php","/shell.php","/cmd.php","/console.php","/test.php","/info.php"]: return
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if is_blacklisted(ip): return
    full=f"{request.path} {request.query_string.decode(errors='ignore')} {request.headers.get('User-Agent','')}"
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
@siem_bp.route('/.env')
def honey_env():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    HONEYPOT_HITS.append({"ip":ip,"path":"/.env","city":city,"time":str(now_sa()),"type":"ENV Leak"})
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":"HONEYPOT TRAP: /.env","reason":"Honeypot ENV Leak","time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":"TRAP:/.env","ua":""})
    add_blacklist(ip,"/.env"); STATS.inc(ip, is_honeypot=True); time.sleep(1.5)
    return f"APP_NAME=AstroJobSA\nHONEYPOT_ID={hashlib.md5(ip.encode()).hexdigest()[:8]}\n",200,{'Content-Type':'text/plain'}

@siem_bp.route('/.git/config')
@siem_bp.route('/.git/HEAD')
def honey_git():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Git Leak"})
    add_blacklist(ip,request.path); STATS.inc(ip, is_honeypot=True); time.sleep(2)
    return "[core]\n",200

@siem_bp.route('/wp-login.php', methods=["GET","POST"])
@siem_bp.route('/wp-admin', methods=["GET","POST"])
@siem_bp.route('/admin', methods=["GET","POST"])
@siem_bp.route('/administrator', methods=["GET","POST"])
def honey_admin():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    if request.method=="POST":
        user=request.form.get('username') or request.form.get('log') or "unknown"
        pw=request.form.get('password') or request.form.get('pwd') or "unknown"
        FAKE_CREDS.append({"ip":ip,"user":user,"pass":pw,"path":request.path,"city":city,"time":str(now_sa())})
        HONEYPOT_HITS.append({"ip":ip,"path":f"{request.path} LOGIN {user}","city":city,"time":str(now_sa()),"type":"Admin Brute"})
        add_blacklist(ip,f"brute {user}"); STATS.inc(ip, is_honeypot=True); time.sleep(3)
        return f"<h2>FLAGGED {ip} - {city} - Blacklisted</h2>",200
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Admin Scan"}); add_blacklist(ip,request.path)
    return "<h1>WordPress</h1><form method=POST><input name=log><input name=pwd type=password><button>Log In</button></form>",200

@siem_bp.route('/phpmyadmin')
@siem_bp.route('/config.php')
@siem_bp.route('/backup.zip')
@siem_bp.route('/.aws/credentials')
def honey_generic():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":get_geo(ip)[2],"time":str(now_sa()),"type":"Config Probe"})
    add_blacklist(ip,request.path); STATS.inc(ip, is_honeypot=True)
    return f"404 - Trap logged for {ip}",404

@siem_bp.route('/upload.php', methods=['GET','POST'])
@siem_bp.route('/file_upload.php', methods=['GET','POST'])
@siem_bp.route('/test.php', methods=['GET','POST'])
def crazy_shell_trap():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    if request.method=='POST':
        f=request.files.get('file') or request.files.get('upload')
        if f:
            data=f.read(1024*200)
            fname=f.filename[:50]
            FAKE_CREDS.append({"ip":ip,"user":f"SHELL:{fname}","pass":f"{len(data)} bytes","city":city,"time":str(now_sa())})
            HONEYPOT_HITS.append({"ip":ip,"path":f"SHELL UPLOAD {fname}","city":city,"time":str(now_sa()),"type":"Malware Upload"})
            THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":f"HONEYPOT MALWARE: {fname}","reason":f"Shell Upload","time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":"TRAP:upload","ua":""})
            add_blacklist(ip,f"shell {fname}"); STATS.inc(ip, is_malware=True)
            return f"File uploaded to /uploads/{fname} [HONEYPOT LOGGED]",200
    return '<h3>File Upload</h3><form method=POST enctype=multipart/form-data><input type=file name=file><button>Upload</button></form>',200

@siem_bp.route('/shell.php')
@siem_bp.route('/cmd.php')
@siem_bp.route('/console.php')
@siem_bp.route('/info.php')
def crazy_cmd_trap():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat,lng,city=get_geo(ip)
    cmd=request.args.get('cmd') or request.args.get('c') or ""
    if cmd:
        HONEYPOT_HITS.append({"ip":ip,"path":f"CMD: {cmd[:100]}","city":city,"time":str(now_sa()),"type":"RCE Attempt"})
        add_blacklist(ip,f"rce {cmd[:20]}"); STATS.inc(ip, is_honeypot=True); time.sleep(4)
        return f"uid=33(www-data)\nFAKE SHELL - IP {ip} LOGGED [{city}]\n$ {cmd}\nsh: not found (honeypot)\n",200,{'Content-Type':'text/plain'}
    return f"uid=33 fake shell - try ?cmd=id - IP {ip} logged",200,{'Content-Type':'text/plain'}

@siem_bp.route('/api/honeypot/fp', methods=['POST'])
def honey_fp():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    data=request.get_json(silent=True) or {}
    FAKE_CREDS.append({"ip":ip,"user":f"FP:{data.get('screen','?')}","pass":str(data)[:300],"city":get_geo(ip)[2],"time":str(now_sa())})
    return jsonify({"ok":True})

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    if SIEM_ALLOW_IPS and ip not in SIEM_ALLOW_IPS: abort(403)
    if FAILED.get(ip,{}).get('count',0)>=5 and time.time()-FAILED[ip]['time']<300: return "<h3>Locked 5min</h3>",429
    if request.method=="POST":
        u=request.form.get('username','').strip(); p=request.form.get('password','').strip()
        if not SIEM_HASH: return "<h3>HASH not set</h3>",500
        if u==SIEM_USER and check_password_hash(SIEM_HASH,p):
            FAILED.pop(ip,None); sid=secrets.token_urlsafe(32); session.clear(); session.permanent=True; session['siem_auth']=True; session['sid']=sid
            SESSION_STORE[sid]={'ip':ip,'ua_hash':sha256(request.headers.get('User-Agent','')),'created':time.time(),'user':SIEM_USER}
            return redirect('/siem')
        FAILED[ip]={'count':FAILED.get(ip,{}).get('count',0)+1,'time':time.time()}; return f"<h3>Wrong {FAILED[ip]['count']}/5</h3>",401
    total=STATS.total_ever; honey=STATS.honeypot_ever; mal=STATS.malware_ever; bl=len(BLACKLIST); visits=STATS.visits_ever
    html = f"""<html><head><title>SIEM v3.2 CRAZY</title><meta name=viewport content="width=device-width,initial-scale=1"></head>
    <body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:monospace">
    <div style="background:#111827;padding:32px;border-radius:20px;width:400px;text-align:center;border:1px solid #1f2937">
    <h2>SIEM v3.2 CRAZY</h2><p style="font-size:10px;color:#22c55e">ENDLESS HONEYPOT SHELL-TRAP RCE FP TARPIT</p>
    <p style="font-size:9px;color:#64748b">Total: {total} | Honey: {honey} | Malware: {mal} | Black: {bl} | Visits: {visits}</p>
    <form method=POST><input name=username placeholder=Username required style="width:100%;padding:14px;margin:10px 0;background:#020617;color:#fff;border:1px solid #334155;border-radius:10px">
    <input name=password type=password placeholder=Password required style="width:100%;padding:14px;margin:10px 0;background:#020617;color:#fff;border:1px solid #334155;border-radius:10px">
    <button style="width:100%;padding:14px;background:#22c55e;border:none;border-radius:10px;font-weight:900;color:#000">AUTHENTICATE</button></form></div></body></html>"""
    return html

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
    all_data=list(THREATS)
    legit=[x for x in all_data if x['type']=="Visit"][-25:][::-1]
    malicious=[x for x in all_data if x['type']!="Visit"][-25:][::-1]
    result = {
        "total": STATS.total_ever,
        "visits_ever": STATS.visits_ever,
        "blocked": STATS.attacks_ever,
        "honeypot_ever": STATS.honeypot_ever,
        "malware_ever": STATS.malware_ever,
        "uniq": len(STATS.unique_ips_ever),
        "bots": STATS.attacks_ever,
        "total_window": len(all_data),
        "blocked_window": len([x for x in all_data if x['type']!="Visit"]),
        "uniq_window": len(set([x['ip'] for x in all_data])),
        "hours": ["5h ago","4h ago","3h ago","2h ago","1h ago","now"],
        "visits": [max(1,len(legit)//6)]*6,
        "attacks": [max(0,len(malicious)//6)]*6,
        "attackTypes": dict(Counter([x.get('reason','/') for x in malicious])) or {"Legit": len(legit)},
        "legit": [{"ip":x['ip'],"page":x['page'],"time":x['time']} for x in legit],
        "malicious": [{"ip":x['ip'],"reason":x['reason'],"time":x['time'],"city":x.get('city')} for x in malicious],
        "server_time": now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),
        "active_sessions": len(SESSION_STORE),
        "audit": list(AUDIT)[-10:],
        "started": STATS.started,
        "endless": True,
        "version": "3.2 CRAZY"
    }
    return result

@siem_bp.route('/api/honeypot')
def honeypot_api():
    if not validate_session(): return jsonify({"error":"unauthorized"}),401
    return jsonify({
        "total_trapped": STATS.honeypot_ever,
        "malware": STATS.malware_ever,
        "current_hits": len(HONEYPOT_HITS),
        "blacklisted": len([k for k,v in BLACKLIST.items() if v.get('blocked_until',0)>time.time()]),
        "total_blacklist": len(BLACKLIST),
        "hits": list(HONEYPOT_HITS)[-50:][::-1],
        "creds": list(FAKE_CREDS)[-30:][::-1],
        "blacklist": sorted([{"ip":k,"count":v['count'],"last":str(datetime.fromtimestamp(v['last'], SAST)),"reasons":v['reasons'][-2:]} for k,v in BLACKLIST.items()], key=lambda x: x['count'], reverse=True)[:20]
    })
