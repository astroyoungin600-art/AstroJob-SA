"""
SIEM v4.0 ADVANCED - Behavioural + Honeypot + Rate Limit + Alerts
"""
import os, time, secrets, hashlib, json, logging, sqlite3
try:
    import requests
except:
    requests = None
from flask import Blueprint, jsonify, render_template, request, session, redirect, abort
from collections import deque, Counter
from datetime import datetime, timedelta, timezone
from werkzeug.security import check_password_hash

siem_bp = Blueprint('siem', __name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SIEM-v4.0")

THREATS = deque(maxlen=2000)
FAILED = {}
AUDIT = deque(maxlen=200)
SESSION_STORE = {}
HONEYPOT_HITS = deque(maxlen=1000)
FAKE_CREDS = deque(maxlen=500)
BLACKLIST = {}
SCORES = {}
RATE = {}  # ip -> [timestamps]
SAST = timezone(timedelta(hours=2))
STATS_FILE = "siem_stats.json"
BLACKLIST_FILE = "blacklist.json"
GEO_CACHE = {}
DB_FILE = "siem.db"
ALERTED = set()

# --- SQLite persistence ---
def db_init():
    try:
        con = sqlite3.connect(DB_FILE); cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS threats (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, city TEXT, type TEXT, path TEXT, reason TEXT, score INTEGER, time TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS scores (ip TEXT PRIMARY KEY, score INTEGER, last TEXT)")
        con.commit(); con.close()
    except Exception as e: print("db init", e)

def db_log(ip, city, typ, path, reason, score):
    try:
        con = sqlite3.connect(DB_FILE); cur = con.cursor()
        cur.execute("INSERT INTO threats (ip,city,type,path,reason,score,time) VALUES (?,?,?,?,?,?,?)", (ip, city, typ, path[:250], reason, score, datetime.now(SAST).isoformat()))
        cur.execute("INSERT OR REPLACE INTO scores (ip,score,last) VALUES (?,?,?)", (ip, score, datetime.now(SAST).isoformat()))
        con.commit(); con.close()
    except: pass

db_init()

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
            if os.path.exists(BLACKLIST_FILE):
                with open(BLACKLIST_FILE) as f: BLACKLIST.update(json.load(f))
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
WHATSAPP_NUMBER=os.getenv("WHATSAPP_NUMBER","")
ALERT_WEBHOOK=os.getenv("ALERT_WEBHOOK","")

def now_sa(): return datetime.now(SAST)
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()[:16]
def get_ip(): return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_geo(ip):
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    default = (-26.2041, 28.0473, "Johannesburg")
    if ip.startswith(("127.","10.","192.168.","172.","100.")):
        GEO_CACHE[ip] = (-26.2041, 28.0473, "Johannesburg [Internal]"); return GEO_CACHE[ip]
    if requests:
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=1.2).json()
            result = (r.get('latitude', -26.2041), r.get('longitude', 28.0473), r.get('city','Unknown'))
            GEO_CACHE[ip]=result; return result
        except: pass
    GEO_CACHE[ip]=default; return default

def is_googlebot(ip, ua): return ip.startswith(("66.249.","66.102.")) and "Googlebot" in ua
def is_blacklisted(ip): return BLACKLIST.get(ip,{}).get('blocked_until',0) > time.time()

def send_alert(ip, score, reason, city):
    if ip in ALERTED: return
    ALERTED.add(ip)
    msg = f"🚨 SIEM ALERT: {ip} [{city}] Score {score} - {reason}"
    print(msg)
    # WhatsApp via wa.me link log + webhook if set
    if ALERT_WEBHOOK and requests:
        try: requests.post(ALERT_WEBHOOK, json={"text": msg}, timeout=3)
        except: pass

def add_blacklist(ip, reason):
    now=time.time()
    if ip not in BLACKLIST: BLACKLIST[ip]={'count':1,'first':now,'last':now,'reasons':[reason],'blocked_until':0}
    else: BLACKLIST[ip]['count']+=1; BLACKLIST[ip]['last']=now; BLACKLIST[ip]['reasons'].append(reason)
    if BLACKLIST[ip]['count']>=3: BLACKLIST[ip]['blocked_until']=now+24*3600
    STATS.save()

def add_score(ip, points, reason, city=""):
    SCORES[ip] = SCORES.get(ip, 0) + points
    score = SCORES[ip]
    if score >= 100:
        send_alert(ip, score, reason, city)
    if score >= 80:
        add_blacklist(ip, f"score {score}: {reason}")
    return score

def check_rate_limit(ip):
    now=time.time()
    RATE[ip]=[t for t in RATE.get(ip,[]) if now-t<60]
    RATE[ip].append(now)
    if len(RATE[ip])>30:
        add_score(ip, 30, "Rate Limit 30/min")
        return True
    return False

def is_bot_ua(ua):
    low=ua.lower()
    if not ua or len(ua)<10: return True, "Empty UA"
    for b in ["curl","python-requests","sqlmap","nmap","nikto","masscan","zgrab","go-http","wget"]:
        if b in low: return True, f"Bot UA: {b}"
    return False,""

class ThreatIntel:
    SIGS={'.env':('ENV Leak',50),'.git':('Git Leak',50),'wp-':('WP Scan',30),'<script':('XSS',40),'union select':('SQLi',40),'../':('LFI',40),'{{':('SSTI',40),'jndi:':('Log4Shell',60),'etc/passwd':('LFI',50),'select * from':('SQLi',40),'onerror=':('XSS',40),'base64':('Encoded',20),'eval(' :('RCE',50),'sleep(':('SQLi Time',30),'phpmyadmin':('DB Scan',40),'.aws':('AWS Leak',50),'backup.zip':('Backup Leak',40)}
    @classmethod
    def scan(cls, p):
        low=p.lower()
        for k,(v,pts) in cls.SIGS.items():
            if k in low: return True,v,pts
        return False,"Legit Visit",0

@siem_bp.before_app_request
def siem_logger():
    if request.path.startswith(('/siem','/api/threats','/api/security-logs','/api/honeypot','/static','/ads.txt','/robots.txt','/health','/api/honeypot/fp')): return
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    ua=request.headers.get('User-Agent','')
    if is_googlebot(ip, ua): return
    # Rate limit
    if check_rate_limit(ip):
        return abort(429)
    # Bot UA
    is_bot, bot_reason = is_bot_ua(ua)
    try: body = request.get_data(as_text=True)[:2000] if request.method in ('POST','PUT') else ''
    except: body=''
    full=f"{request.path} {request.query_string.decode(errors='ignore')} {ua} {body}"
    bad, reason, pts = ThreatIntel.scan(full)
    lat,lng,city=get_geo(ip)
    score=SCORES.get(ip,0)
    if is_bot:
        score=add_score(ip, 15, bot_reason, city)
        if not bad: bad=True; reason=bot_reason; pts=15
    if bad:
        score=add_score(ip, pts, reason, city)
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Attack" if bad else "Visit","path":request.path[:250],"reason":reason,"score":score,"time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":request.path[:200],"ua":ua[:80]})
    if bad: db_log(ip, city, "Attack", request.path, reason, score)
    STATS.inc(ip, is_attack=bad)

def validate_session():
    if not session.get('siem_auth'): return False
    sid=session.get('sid')
    if not sid or sid not in SESSION_STORE: return False
    rec=SESSION_STORE[sid]
    if rec['ip']!=get_ip() or rec['ua_hash']!=sha256(request.headers.get('User-Agent','')): return False
    if time.time()-rec['created']>7*24*3600: SESSION_STORE.pop(sid,None); return False
    return True

@siem_bp.route('/.env')
def honey_env():
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    lat,lng,city=get_geo(ip); s=add_score(ip,50,"Honeypot /.env",city)
    HONEYPOT_HITS.append({"ip":ip,"path":"/.env","city":city,"time":str(now_sa()),"type":"ENV Leak","score":s})
    THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":"HONEYPOT TRAP: /.env","reason":"Honeypot ENV Leak","score":s,"time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":"TRAP:/.env","ua":""})
    add_blacklist(ip,"/.env"); STATS.inc(ip, is_honeypot=True); db_log(ip,city,"Honeypot","/.env","ENV Leak",s); time.sleep(1.5)
    return "APP_NAME=AstroJobSA\nHONEYPOT_ID="+hashlib.md5(ip.encode()).hexdigest()[:8]+"\n",200,{'Content-Type':'text/plain'}

@siem_bp.route('/.git/config')
@siem_bp.route('/.git/HEAD')
def honey_git():
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    lat,lng,city=get_geo(ip); s=add_score(ip,50,"Honeypot .git",city)
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Git Leak","score":s})
    add_blacklist(ip, request.path); STATS.inc(ip, is_honeypot=True); time.sleep(2)
    return "[core]\n",200

@siem_bp.route('/wp-login.php', methods=["GET","POST"])
@siem_bp.route('/wp-admin', methods=["GET","POST"])
@siem_bp.route('/admin', methods=["GET","POST"])
@siem_bp.route('/administrator', methods=["GET","POST"])
def honey_admin():
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    lat,lng,city=get_geo(ip)
    if request.method=="POST":
        user=request.form.get('username') or request.form.get('log') or "unknown"
        pw=request.form.get('password') or request.form.get('pwd') or "unknown"
        s=add_score(ip,40,"Brute Force",city)
        FAKE_CREDS.append({"ip":ip,"user":user[:50],"pass_hash":hashlib.sha256(pw.encode()).hexdigest()[:12],"path":request.path,"city":city,"time":str(now_sa()),"score":s})
        HONEYPOT_HITS.append({"ip":ip,"path":f"{request.path} LOGIN {user[:30]}","city":city,"time":str(now_sa()),"type":"Admin Brute","score":s})
        add_blacklist(ip,f"brute {user[:20]}"); STATS.inc(ip, is_honeypot=True); time.sleep(3)
        return f"<h2>FLAGGED {ip} - {city} - Score {s} - Blacklisted</h2>",200
    s=add_score(ip,30,"Admin Scan",city)
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":city,"time":str(now_sa()),"type":"Admin Scan","score":s})
    add_blacklist(ip, request.path)
    return "<h1>WordPress</h1><form method=POST><input name=log><input name=pwd type=password><button>Log In</button></form>",200

@siem_bp.route('/phpmyadmin')
@siem_bp.route('/config.php')
@siem_bp.route('/backup.zip')
@siem_bp.route('/.aws/credentials')
def honey_generic():
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    s=add_score(ip,40,f"Honeypot {request.path}",get_geo(ip)[2])
    HONEYPOT_HITS.append({"ip":ip,"path":request.path,"city":get_geo(ip)[2],"time":str(now_sa()),"type":"Config Probe","score":s})
    add_blacklist(ip, request.path); STATS.inc(ip, is_honeypot=True)
    return "404 - Trap logged",404

@siem_bp.route('/upload.php', methods=['GET','POST'])
@siem_bp.route('/file_upload.php', methods=['GET','POST'])
@siem_bp.route('/test.php', methods=['GET','POST'])
def crazy_shell_trap():
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    lat,lng,city=get_geo(ip)
    if request.method=='POST':
        f=request.files.get('file') or request.files.get('upload')
        if f:
            data=f.read(1024*200); fname=f.filename[:50]; s=add_score(ip,60,"Shell Upload",city)
            FAKE_CREDS.append({"ip":ip,"user":f"SHELL:{fname}","pass_hash":hashlib.sha256(data[:100]).hexdigest()[:12],"city":city,"time":str(now_sa()),"score":s})
            HONEYPOT_HITS.append({"ip":ip,"path":f"SHELL UPLOAD {fname}","city":city,"time":str(now_sa()),"type":"Malware Upload","score":s})
            THREATS.append({"ip":ip,"lat":lat,"lng":lng,"city":city,"type":"Honeypot","path":f"HONEYPOT MALWARE: {fname}","reason":"Shell Upload","score":s,"time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"page":"TRAP:upload","ua":""})
            add_blacklist(ip,f"shell {fname}"); STATS.inc(ip, is_malware=True); db_log(ip,city,"Malware",fname,"Shell Upload",s)
            return "File uploaded [HONEYPOT LOGGED]",200
    return '<h3>File Upload</h3><form method=POST enctype=multipart/form-data><input type=file name=file><button>Upload</button></form>',200

@siem_bp.route('/shell.php')
@siem_bp.route('/cmd.php')
@siem_bp.route('/console.php')
@siem_bp.route('/info.php')
def crazy_cmd_trap():
    ip=get_ip()
    if is_blacklisted(ip): return abort(403)
    lat,lng,city=get_geo(ip)
    cmd=request.args.get('cmd') or request.args.get('c') or ""
    if cmd:
        s=add_score(ip,60,"RCE Attempt",city)
        HONEYPOT_HITS.append({"ip":ip,"path":f"CMD: {cmd[:100]}","city":city,"time":str(now_sa()),"type":"RCE Attempt","score":s})
        add_blacklist(ip,f"rce {cmd[:20]}"); STATS.inc(ip, is_honeypot=True); time.sleep(4)
        return f"uid=33(www-data)\nFAKE SHELL - IP {ip} LOGGED [{city}] Score {s}\n$ {cmd}\nsh: not found (honeypot)\n",200,{'Content-Type':'text/plain'}
    return f"uid=33 fake shell - IP {ip} logged",200,{'Content-Type':'text/plain'}

@siem_bp.route('/api/honeypot/fp', methods=['POST'])
def honey_fp():
    ip=get_ip(); data=request.get_json(silent=True) or {}
    FAKE_CREDS.append({"ip":ip,"user":f"FP:{str(data.get('screen','?'))[:20]}","pass_hash":hashlib.sha256(str(data)[:300].encode()).hexdigest()[:12],"city":get_geo(ip)[2],"time":str(now_sa())})
    return jsonify({"ok":True})

@siem_bp.route('/siem/login', methods=["GET","POST"])
def login():
    ip=get_ip()
    if SIEM_ALLOW_IPS and ip not in SIEM_ALLOW_IPS: abort(403)
    if FAILED.get(ip,{}).get('count',0)>=5 and time.time()-FAILED[ip]['time']<300: return "<h3>Locked 5min</h3>",429
    if request.method=="POST":
        u=request.form.get('username','').strip(); p=request.form.get('password','').strip()
        if not SIEM_HASH: return "<h3>HASH not set</h3>",500
        if u==SIEM_USER and check_password_hash(SIEM_HASH,p):
            FAILED.pop(ip,None); sid=secrets.token_urlsafe(32); session.clear(); session.permanent=True; session['siem_auth']=True; session['sid']=sid
            SESSION_STORE[sid]={'ip':ip,'ua_hash':sha256(request.headers.get('User-Agent','')),'created':time.time(),'user':SIEM_USER}
            return redirect('/siem')
        FAILED[ip]={'count':FAILED.get(ip,{}).get('count',0)+1,'time':time.time()}
        return f"<h3>Wrong {FAILED[ip]['count']}/5</h3>",401
    total=STATS.total_ever; honey=STATS.honeypot_ever; mal=STATS.malware_ever; bl=len(BLACKLIST); visits=STATS.visits_ever
    html=f"""<html><head><title>SIEM v4.0</title><meta name=viewport content="width=device-width,initial-scale=1"></head>
    <body style="background:#0a0e1a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:monospace">
    <div style="background:#111827;padding:32px;border-radius:20px;width:400px;text-align:center;border:1px solid #1f2937">
    <h2>SIEM v4.0 ADVANCED</h2><p style="font-size:10px;color:#22c55e">BEHAVIOURAL + HONEYPOT + RATE LIMIT</p>
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
    top_scores=sorted(SCORES.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total":STATS.total_ever,"visits_ever":STATS.visits_ever,"blocked":STATS.attacks_ever,"honeypot_ever":STATS.honeypot_ever,"malware_ever":STATS.malware_ever,
        "uniq":len(STATS.unique_ips_ever),"bots":STATS.attacks_ever,"total_window":len(all_data),"blocked_window":len([x for x in all_data if x['type']!="Visit"]),"uniq_window":len(set([x['ip'] for x in all_data])),
        "hours":["5h ago","4h ago","3h ago","2h ago","1h ago","now"],"visits":[max(1,len(legit)//6)]*6,"attacks":[max(0,len(malicious)//6)]*6,
        "attackTypes":dict(Counter([x.get('reason','/') for x in malicious])) or {"Legit":len(legit)},
        "legit":[{"ip":x['ip'],"page":x['page'],"time":x['time']} for x in legit],
        "malicious":[{"ip":x['ip'],"reason":x['reason'],"time":x['time'],"city":x.get('city'),"score":x.get('score',0)} for x in malicious],
        "top_scores":[{"ip":k,"score":v,"city":get_geo(k)[2]} for k,v in top_scores],
        "server_time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"active_sessions":len(SESSION_STORE),"audit":list(AUDIT)[-10:],"started":STATS.started,"endless":True,"version":"4.0"
    }

@siem_bp.route('/api/honeypot')
def honeypot_api():
    if not validate_session(): return jsonify({"error":"unauthorized"}),401
    return jsonify({
        "total_trapped":STATS.honeypot_ever,"malware":STATS.malware_ever,"current_hits":len(HONEYPOT_HITS),
        "blacklisted":len([k for k,v in BLACKLIST.items() if v.get('blocked_until',0)>time.time()]),"total_blacklist":len(BLACKLIST),
        "hits":list(HONEYPOT_HITS)[-50:][::-1],"creds":list(FAKE_CREDS)[-30:][::-1],
        "scores":dict(SCORES),
        "blacklist":sorted([{"ip":k,"count":v['count'],"last":str(datetime.fromtimestamp(v['last'], SAST)),"reasons":v['reasons'][-2:]} for k,v in BLACKLIST.items()], key=lambda x: x['count'], reverse=True)[:20]
    })

@siem_bp.route('/wpadmin', methods=["GET","POST"])
@siem_bp.route('/wp-admin.php', methods=["GET","POST"])
@siem_bp.route('/administrator.php', methods=["GET","POST"])
@siem_bp.route('/admin.php', methods=["GET","POST"])
def honey_admin_typos(): return honey_admin()

# --- Threat Intel Dashboard ---
@siem_bp.route('/siem/intel')
def intel_page():
    if not validate_session(): return redirect('/siem/login')
    return render_template('siem_intel.html')

@siem_bp.route('/api/threat-intel')
def api_threat_intel():
    if not validate_session(): return jsonify({"error":"unauth"}), 401
    from collections import Counter
    all_threats = list(THREATS)
    total = len(all_threats) + STATS.total_ever
    by_country = Counter([t.get('city','Unknown') for t in all_threats])
    by_type = Counter([t.get('reason','Legit Visit') for t in all_threats])
    by_path = Counter([t.get('path','/')[:60] for t in all_threats])
    def to_list(c):
        tot = sum(c.values()) or 1
        return [{"name":k,"count":v,"pct":round(v*100/tot,1)} for k,v in c.most_common(10)]
    iocs = []
    for ip, score in sorted(SCORES.items(), key=lambda x: x[1], reverse=True)[:20]:
        city = "Unknown"
        for t in reversed(all_threats):
            if t.get('ip')==ip: city=t.get('city','Unknown'); break
        iocs.append({"ip":ip,"city":city,"score":score,"last":str(now_sa().strftime("%H:%M:%S"))})
    fps = []
    try:
        for fp, rec in list(FINGERPRINTS.items())[:20]:
            fps.append({"fp":fp[:18],"ip":rec.get('ip','-'),"score":rec.get('score',0),"banned":rec.get('blocked_until',0)>time.time()})
    except: pass
    risk = "CRITICAL" if any(s>=80 for s in SCORES.values()) else "MEDIUM" if any(s>=40 for s in SCORES.values()) else "LOW"
    return jsonify({"total":total,"unique_ips":len(STATS.unique_ips_ever),"by_country":to_list(by_country),"by_type":to_list(by_type),"by_path":to_list(by_path),"iocs":iocs,"fingerprints":fps,"risk":risk,"server_time":now_sa().strftime("%Y-%m-%d %H:%M:%S SAST"),"version":"4.0"})
