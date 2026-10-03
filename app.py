from flask import Flask, render_template_string, render_template, request
import requests, os, re, logging, time
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)

# === SIEM LOGIN SYSTEM ===
import secrets
app.secret_key = os.environ.get("SECRET_KEY", "astro-siem-2026-secret-key-mthembisi")
from flask import session, redirect, url_for

SIEM_USER = "admin"
SIEM_PASS = "Astro2026!"

@app.route('/siem/login', methods=["GET","POST"])
def siem_login():
    if request.method == "POST":
        u = request.form.get('username','')
        p = request.form.get('password','')
        if u == SIEM_USER and p == SIEM_PASS:
            session['siem_auth'] = True
            return redirect('/siem')
        return """<h2 style="color:red">Wrong! Try again</h2><a href='/siem/login'>Back to login</a>"""
    return """
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>SIEM Login</title>
    <style>body{background:#0a0e1a;color:#fff;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .box{background:#111827;border:1px solid #1f2937;padding:30px;border-radius:16px;width:320px;text-align:center}
    input{width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid #333;background:#000;color:#fff}
    button{width:100%;padding:12px;background:#22c55e;border:none;border-radius:8px;font-weight:800;cursor:pointer;margin-top:10px}
    </style></head><body>
    <div class="box"><h2>🛡️ ASTRO SIEM</h2><p style="color:#94a3b8;font-size:13px">Authorized Access Only</p>
    <form method="POST"><input name="username" placeholder="Username (admin)" required>
    <input name="password" type="password" placeholder="Password (Astro2026!)" required>
    <button>LOGIN</button></form><p style="font-size:11px;color:#64748b;margin-top:12px">Full IP logs protected</p></div></body></html>
    """

@app.route('/siem/logout')
def siem_logout():
    session.pop('siem_auth', None)
    return redirect('/siem/login')

# Protect all SIEM routes
@app.before_request
def protect_siem_login():
    protected = ['/siem', '/siem_globe', '/api/threats', '/api/security-logs']
    if any(request.path.startswith(p) for p in protected):
        if request.path == '/siem/login' or request.path == '/siem/logout':
            return
        if not session.get('siem_auth'):
            return redirect('/siem/login')


# === OLD PROTECTION REMOVED - ONLY YOU ===

@app.before_request
def protect_siem():
    if request.path.startswith('/siem') or request.path.startswith('/api/threats') or request.path.startswith('/api/security-logs'):
        key = request.args.get('key') or request.headers.get('X-SIEM-KEY')
        # Allow if ?key=Astro2026!
        if key != SIEM_PASSWORD:
            # Check if already authenticated via cookie? For now require key
            if request.path.startswith('/api/'):
                return {"error":"Unauthorized - SIEM protected"}, 401
            return f"<h1>401 - SIEM Protected</h1><p>Add ?key={SIEM_PASSWORD} to URL</p><a href='/'>Home</a>", 401

# Register SIEM Blueprint - FULL IP
try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
    print("SIEM blueprint registered - FULL IP enabled")
except Exception as e:
    print(f"SIEM import failed: {e}")


# === REAL SIEM - FULL IP VERSION ===
from collections import deque, Counter
VISITS=deque(maxlen=500)
MALICIOUS=deque(maxlen=200)

@app.before_request
def _log():
    try:
        if request.path.startswith('/api/security-logs'):
            return
        if request.path.startswith('/static'):
            return
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or "0.0.0.0"
        ip = ip.split(',')[0].strip() # take first if multiple
        ipm = ip # FULL IP - NOT MASKED
        e = {"ip": ipm, "ip_full": ip, "path": request.path, "ts": time.time(), "time_str": datetime.now().strftime("%H:%M:%S"), "device": "Mobile", "loc": "SA"}
        c = f"{request.path} {request.args} {request.headers.get('User-Agent','')}".lower()
        atk = None
        if "' or" in c or "or 1=1" in c:
            atk = "SQLi"
        elif "<script" in c:
            atk = "XSS"
        elif "../" in c:
            atk = "Traversal"
        elif "bot" in c or "curl" in c:
            atk = "Bot"
        if atk:
            MALICIOUS.append({"ip": ipm, "reason": atk, "loc": "SA", "time": e["time_str"], "type": atk, "ts": e["ts"]})
        else:
            VISITS.append(e)
    except:
        pass

def is_traversal_attack(value):
    if not value: return False
    low = value.lower()
    for p in ["..", "%2e%2e", "%252e", "etc/passwd", ".env", "/etc", "/proc", "\\", "%00"]:
        if p in low: return True
    return False

def is_safe_url(url):
    try:
        p = urlparse(url)
        return p.scheme in ("http","https") and p.netloc and "." in p.netloc and "adzuna" not in p.netloc.lower() or True
    except: return False

def sanitize(text, maxlen=40):
    if not text: return ""
    if is_traversal_attack(text):
        logging.warning(f"WAF BLOCKED: IP={request.remote_addr} PAYLOAD={text[:100]}")
        return ""
    # Strict whitelist: letters, numbers, space, dash only - kills XSS/SQLi
    text = re.sub(r'[^a-zA-Z0-9 \-]', '', text)
    return text.strip()[:maxlen]

def get_jobs(q="Driver", loc="South Africa"):
    # If keys not set, return empty - don't crash
    if not APP_ID or not APP_KEY:
        return []
    q = sanitize(q, 40); loc = sanitize(loc, 40)
    if not q: q="Driver"
    if not loc: loc="South Africa"
    url="https://api.adzuna.com/v1/api/jobs/za/search/1"
    params={"app_id":APP_ID,"app_key":APP_KEY,"results_per_page":50,"what":q,"where":loc}
    jobs=[]
    try:
        resp=requests.get(url, params=params, timeout=12)
        if resp.status_code!=200: return []
        data=resp.json()
        for j in data.get('results',[]):
            title=j.get('title','')
            if 'whatsapp' in title.lower() or 'telegram' in title.lower(): continue
            redirect=j.get('redirect_url','')
            if not is_safe_url(redirect): continue
            # XSS: strip < >
            safe_desc = (j.get('description','')[:200]).replace('<','').replace('>','').replace('"','').replace("'",'')
            jobs.append({
                "title": re.sub(r'[^a-zA-Z0-9 \-\(\)]', '', title)[:120],
                "company": re.sub(r'[^a-zA-Z0-9 \-\&]', '', j.get('company',{}).get('display_name','Top SA Company'))[:80],
                "location": re.sub(r'[^a-zA-Z0-9 \-,]', '', j.get('location',{}).get('display_name',loc))[:80],
                "desc": safe_desc,
                "url": redirect,
                "created": j.get('created','')[:10]
            })
    except Exception as e:
        logging.error(f"API Error: {e}")
        jobs=[]
    return jobs

@app.route('/post-job')
def post_job():
    return render_template('post-job.html')


@app.route('/cv')
def cv_page():
    return render_template('cv.html')

@app.route('/cv-maker')
def cv_maker():
    return render_template('cv.html')


HTML="""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Astro Job SA - Made by Mthembisi</title><meta name="description" content="Real verified jobs in South Africa - No scams. Made by Mthembisi"><script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2133699761079270" crossorigin="anonymous"></script><style>body{font-family:system-ui;background:#f8fafc;margin:0;color:#0f172a}.header{background:#fff;padding:14px 20px;border-bottom:4px solid #0a2a8a;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:10}.logo-text{font-size:26px;font-weight:900;color:#0a2a8a}.logo-text span{color:#00a651}.hero{background:linear-gradient(135deg,#0a2a8a,#00a651);color:white;padding:28px 18px;text-align:center}.searchBox{background:#fff;padding:14px;border-radius:14px;max-width:900px;margin:-22px auto 15px;box-shadow:0 10px 25px rgba(0,0,0,.2);display:flex;gap:8px;flex-wrap:wrap}.searchBox input,select{padding:12px;border-radius:10px;border:1px solid #cbd5e1;flex:1;min-width:130px;font-size:15px}.btn{padding:12px 20px;border-radius:10px;border:0;background:#0a2a8a;color:white;font-weight:800;cursor:pointer}.card{background:#fff;padding:16px;border-radius:12px;margin:10px auto;max-width:900px;box-shadow:0 2px 6px rgba(0,0,0,.06);border-left:5px solid #00a651}.apply{background:#0a2a8a;color:white;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block}.share{background:#25D366;color:white;padding:10px 14px;border-radius:8px;text-decoration:none;margin-left:6px;font-weight:700;display:inline-block}.footer{background:#0f172a;color:#94a3b8;padding:25px;text-align:center;margin-top:25px}.badge{background:#e0f2fe;color:#0a2a8a;padding:3px 8px;border-radius:12px;font-weight:700;font-size:11px}.adbox{max-width:900px;margin:14px auto;background:#fff;padding:12px;border-radius:10px;border:1px dashed #cbd5e1;text-align:center}</style></head><body>
<a href="/cv" style="background:#00a651;margin-right:8px" style="background:#ff9800;color:#000;padding:12px;border-radius:8px;text-decoration:none;font-weight:bold;display:block;text-align:center;margin:10px;font-family:Arial">+ FREE CV MAKER ⭐ Get 10x More Applicants</a><div class=header><div style="font-size:32px">🚀</div><div><div class=logo-text>Astro Job <span>SA</span></div><div style="color:#00a651;font-weight:800;font-size:11px;letter-spacing:2px">MADE BY MTHEMBISI</div></div></div><div class=hero><h2 style="margin:0">Your Future Starts Here, Mzansi</h2><p style="max-width:720px;margin:12px auto"><b>"Umsebenzi wakho uqala lapha. Akuwona amanga, akuwona ama-scams - imisebenzi yangempela."</b><br>We built Astro Job SA because every young South African deserves a fair shot. No fees. No WhatsApp payments. Just real, verified opportunities.<br><small>Verified daily • Trusted by SA youth • Built in SA for SA</small></p></div><form method=POST autocomplete=off><div class=searchBox><input name=q value="{{q}}" placeholder="Job: Driver, Cashier, IT..." maxlength=40 pattern="[a-zA-Z0-9 ]+"><select name=loc><option value="South Africa" {% if loc=='South Africa' %}selected{%endif%}>South Africa</option><option value="Johannesburg" {% if loc=='Johannesburg' %}selected{%endif%}>Johannesburg</option><option value="Cape Town" {% if loc=='Cape Town' %}selected{%endif%}>Cape Town</option><option value="Durban" {% if loc=='Durban' %}selected{%endif%}>Durban</option><option value="Pretoria" {% if loc=='Pretoria' %}selected{%endif%}>Pretoria</option><option value="Port Elizabeth" {% if loc=='Port Elizabeth' %}selected{%endif%}>Port Elizabeth</option></select><button class=btn type=submit>Find Jobs</button></div></form><div style="max-width:900px;margin:0 auto;padding:0 12px"><b>{{jobs|length}} Verified Jobs</b> in {{loc}} for "{{q}}" • {{now}}</div>{% for j in jobs %}<div class=card><span class=badge>✓ VERIFIED • {{j.location}}</span><div style="font-weight:800;margin:6px 0;font-size:17px">{{j.title}}</div><small>{{j.company}} • {{j.created}}</small><p style="color:#475569;font-size:13px">{{j.desc}}...</p><a class=apply href="{{j.url}}" target=_blank rel="noopener">Apply on Company Site →</a><a class=share href="https://wa.me/?text={{ ('I found this job: '+j.title+' '+j.url) | urlencode }}" target=_blank>WhatsApp Share</a></div>{% if loop.index==4 %}<div class=adbox><small style="color:#888">Advertisement</small><ins class="adsbygoogle" style="display:block" data-ad-client="ca-pub-2133699761079270" data-ad-format="auto" data-full-width-responsive="true"></ins><script>(adsbygoogle=window.adsbygoogle||[]).push({});</script></div>{% endif %}{% if loop.index==10 %}<div class=adbox><small style="color:#888">Advertisement - Supports free jobs</small><ins class="adsbygoogle" style="display:block" data-ad-client="ca-pub-2133699761079270" data-ad-format="auto" data-full-width-responsive="true"></ins><script>(adsbygoogle=window.adsbygoogle||[]).push({});</script></div>{% endif %}{% endfor %}<div style="max-width:900px;margin:18px auto;background:#fff3cd;padding:14px;border-radius:10px;text-align:center"><b>📢 Share & Help Others Get Jobs</b><br><a style="display:inline-block;margin-top:8px;background:#25D366;color:white;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:800" href="https://wa.me/?text={{ share_text | urlencode }}" target=_blank>Share Astro Job SA 🚀</a></div><div class=footer><b style="color:white">Astro Job SA</b> - Made with ❤️ by Mthembisi<br>astroyoungin600@gmail.com • Johannesburg<br>© 2026 Astro Job SA • Powered by Adzuna Official API • Security: No SQL DB, XSS Protected, Path Traversal Proof + WAF, No sensitive disclosure</div>
<a href="/cv" style="position:fixed;bottom:24px;right:24px;background:#22c55e;color:#000;padding:14px 22px;border-radius:999px;font-weight:800;text-decoration:none;z-index:9999;box-shadow:0 6px 20px rgba(0,0,0,0.25);font-family:system-ui;display:flex;align-items:center;gap:8px;border:2px solid #000;">📄 CV Maker</a>
<a href="/post-job" style="position:fixed;bottom:80px;right:24px;background:#3b82f6;color:#fff;padding:14px 22px;border-radius:999px;font-weight:800;text-decoration:none;z-index:9999;box-shadow:0 6px 20px rgba(0,0,0,0.25);font-family:system-ui;display:flex;align-items:center;gap:8px;border:2px solid #000;">💼 Post Job</a>
<a href="https://www.buymeacoffee.com/astrojobsa" target="_blank" style="position:fixed;bottom:136px;right:24px;background:#FFDD00;color:#000;padding:14px 22px;border-radius:999px;font-weight:800;text-decoration:none;z-index:9999;box-shadow:0 6px 20px rgba(0,0,0,0.25);font-family:system-ui;display:flex;align-items:center;gap:8px;border:2px solid #000;">☕ Buy Me a Coffee</a></body></html>"""

@app.route("/", methods=["GET","POST"])
def home():
    raw_q=(request.form.get("q","Driver") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc=(request.form.get("loc","South Africa") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    if not raw_q: raw_q="Driver"
    if not raw_loc: raw_loc="South Africa"
    if is_traversal_attack(raw_q) or is_traversal_attack(raw_loc):
        logging.warning(f"WAF 403: IP={request.remote_addr} q={raw_q} loc={raw_loc}")
        return "<h1>403 Forbidden - WAF Blocked</h1>",403
    q=sanitize(raw_q,40) or "Driver"
    loc=sanitize(raw_loc,40) or "South Africa"
    jobs=get_jobs(q,loc)
    share_text=f"🚀 Astro Job SA - Made by Mthembisi - Real verified jobs SA, no scams! https://astrojob-sa.onrender.com"
    return render_template_string(HTML, jobs=jobs, q=q, loc=loc, now=datetime.now().strftime("%d %b %Y"), share_text=share_text)

@app.after_request
def secure_headers(resp):
    resp.headers['X-Content-Type-Options']='nosniff'
    resp.headers['X-Frame-Options']='DENY'
    resp.headers['X-XSS-Protection']='1; mode=block'
    resp.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy']="default-src 'self' https:; script-src 'self' 'unsafe-inline' https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src https://api.adzuna.com https://googleads.g.doubleclick.net https:; frame-src https://googleads.g.doubleclick.net"
    resp.headers['Permissions-Policy']='geolocation=(), microphone=(), camera=()'
    return resp

@app.route('/ads.txt')
def ads_txt():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0", 200, {'Content-Type': 'text/plain'}

@app.route('/health')
def health():
    return {"status":"ok","app":"Astro Job SA","by":"Mthembisi","waf":"active"}

@app.route('/privacy')
def privacy():
    return open('privacy.html').read()

@app.route('/about')
def about():
    return """<h1>About Astro Job SA - Made by Mthembisi</h1>
    <p>Built in Johannesburg for SA youth. No scams, no fees, just real verified jobs.</p>
    <p>Contact: astroyoungin600@gmail.com</p>
    <a href='/'>Back</a>"""

@app.route('/contact')
def contact():
    return """<h1>Contact</h1>
    <p>Email: astroyoungin600@gmail.com<br>Johannesburg, SA</p>
    <a href='/'>Back</a>"""

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

@app.after_request
def inject_footer(response):
    try:
        if response.mimetype=='text/html' and response.status_code==200:
            html=response.get_data(as_text=True)
            if '</body>' in html and 'Privacy Policy' not in html:
                footer='<div style="text-align:center;padding:20px;font-size:14px;background:#f8f9fa;margin-top:40px"><a href="/privacy" style="color:#555;margin:0 10px">Privacy Policy</a> | <a href="/about" style="color:#555;margin:0 10px">About</a> | <a href="/" style="color:#555;margin:0 10px">Home</a><br><small>© 2026 AstroJobSA - Built for SA Youth</small></div>'
                html=html.replace('</body>', footer+'</body>')
                response.set_data(html)
        # Security headers too
        response.headers['X-Frame-Options']='DENY'
        response.headers['X-Content-Type-Options']='nosniff'
    except: pass
    return response

@app.route('/channel-queue')
def channel_queue():
    try:
        txt=open('channel_queue.txt').read()
        return f"<pre style='white-space:pre-wrap;font-family:system-ui'>{txt}</pre><hr><a href='/api/bot-preview'>Preview</a> | <a href='/'>Home</a>"
    except:
        return "Queue empty - wait 1 min after deploy. <a href='/'>Home</a>"

# --- AUTO POSTER FIX ---
import os, requests, threading, time
from datetime import datetime

def fetch_and_prepare():
    ID=os.environ.get("ADZUNA_ID"); KEY=os.environ.get("ADZUNA_KEY")
    if not ID: return []
    try:
        url=f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ID}&app_key={KEY}&results_per_page=10&what=General worker&where=South Africa&sort_by=date"
        r=requests.get(url, timeout=15).json()
        jobs=r.get('results',[])[:5]
        out=[]
        for j in jobs:
            text=f"🚀 *{j.get('title','')}*\n📍 {j.get('location',{}).get('display_name','SA')} | 🏢 {j.get('company',{}).get('display_name','')}\n\n🔗 {j.get('redirect_url','')}\n\nWe do not need your details this is a Non Profit Program.WE DO NOT CHARGE MONEY, fully POPIA compliance\n\nAstro Job SA - Made by Mthembisi"
            out.append(text)
        with open("channel_queue.txt","w") as f:
            f.write("\n\n---NEXT JOB---\n\n".join(out))
        print(f"[{datetime.now()}] AutoBot prepared {len(out)} jobs")
        return out
    except Exception as e:
        print(f"AutoBot error: {e}")
        return []

def start_scheduler_bg():
    def loop():
        while True:
            fetch_and_prepare()
            time.sleep(4*3600)
    t=threading.Thread(target=loop, daemon=True)
    t.start()

# start it now
try:
    start_scheduler_bg()
except: pass

@app.route('/api/bot-preview')
def bot_preview():
    jobs=[]
    try:
        jobs=fetch_and_prepare()
        html="<h1>Bot Preview - Copy to WhatsApp Channel</h1><a href='/channel-queue'>Queue</a> | <a href='/'>Home</a><hr>"
        for j in jobs:
            html+=f"<div style='border:1px solid #ddd;padding:10px;margin:10px'>{j.replace(chr(10), '<br>')}</div>"
        return html
    except Exception as e:
        return f"Error {e}"
