from flask import Flask, render_template_string, request, render_template, redirect
import requests, os, re, logging, time
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()

try:
    from siem import siem_bp
except:
    siem_bp = None

app = Flask(__name__)
if siem_bp:
    try:
        app.register_blueprint(siem_bp)
    except:
        pass

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24).hex()

# ADZUNA KEYS - from Render Env
APP_ID = os.environ.get("ADZUNA_ID")
APP_KEY = os.environ.get("ADZUNA_KEY")

# Cache to stop lag
job_cache = {"jobs":[], "time":0, "q":"", "loc":""}

def is_traversal_attack(value):
    if not value: return False
    low=value.lower()
    for p in ["..","%2e","etc/passwd",".env","/etc","/proc","\\","%00"]:
        if p in low: return True
    return False

def sanitize(text, maxlen=40):
    if not text: return ""
    if is_traversal_attack(text): return ""
    return re.sub(r'[^a-zA-Z0-9 \-]','',text).strip()[:maxlen]

def get_jobs(q="Driver", loc="South Africa"):
    global job_cache
    now=time.time()
    if job_cache["jobs"] and (now-job_cache["time"]<300) and job_cache["q"]==q and job_cache["loc"]==loc:
        return job_cache["jobs"]
    if not APP_ID or not APP_KEY:
        logging.warning("ADZUNA keys missing - set ADZUNA_ID and ADZUNA_KEY in Render")
        return []
    params={"app_id":APP_ID,"app_key":APP_KEY,"results_per_page":50,"what":sanitize(q,40) or "Driver","where":sanitize(loc,40) or "South Africa"}
    try:
        r=requests.get("https://api.adzuna.com/v1/api/jobs/za/search/1",params=params,timeout=12)
        if r.status_code!=200: return []
        jobs=[]
        for j in r.json().get("results",[]):
            if not j.get("redirect_url"): continue
            if "whatsapp" in j.get("title","").lower(): continue
            jobs.append({
                "title": j.get("title","")[:120],
                "company": j.get("company",{}).get("display_name","Top Company")[:80],
                "location": j.get("location",{}).get("display_name",loc)[:80],
                "desc": (j.get("description","")[:200]).replace("<","").replace(">",""),
                "url": j.get("redirect_url",""),
                "created": j.get("created","")[:10]
            })
        job_cache={"jobs":jobs,"time":now,"q":q,"loc":loc}
        return jobs
    except Exception as e:
        logging.error(f"API Error {e}")
        return job_cache["jobs"]

HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Astro Job SA - Real Jobs | Made by Mthembisi</title>
<!-- ADSENSE - YOUR ACCOUNT -->
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2133699761079270" crossorigin="anonymous"></script>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui;background:#f8fafc;color:#0f172a}
#astroHeader{position:sticky;top:0;z-index:99999;background:#fff;display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:4px solid #0a2a8a;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.btns{display:flex;gap:8px}.btns a{padding:10px 18px;border-radius:12px;font-weight:900;text-decoration:none}
.btnCV{background:#22c55e;color:#000}.btnPost{background:#0a2a8a;color:#fff}
.hero{background:linear-gradient(135deg,#0a2a8a 0%,#00a651 100%);color:#fff;padding:28px 16px;text-align:center}
.searchBox{background:#fff;max-width:900px;margin:-18px auto 0;padding:14px;border-radius:14px;box-shadow:0 8px 24px rgba(0,0,0,.1);display:flex;gap:8px;flex-wrap:wrap}
.searchBox input{flex:1;min-width:160px;padding:12px;border:1px solid #cbd5e1;border-radius:10px}
.searchBox button{padding:12px 20px;background:#0a2a8a;color:#fff;border:0;border-radius:10px;font-weight:900;cursor:pointer}
.jobs{max-width:900px;margin:20px auto;padding:0 12px;display:grid;gap:12px}
.job{background:#fff;padding:16px;border-radius:14px;box-shadow:0 2px 8px rgba(0,0,0,.05);border-left:4px solid #0a2a8a}
.coffeeF{position:fixed;bottom:18px;right:14px;z-index:99999;background:#FFDD00;color:#000;padding:12px 20px;border-radius:30px;font-weight:900;box-shadow:0 6px 20px rgba(0,0,0,.25);text-decoration:none;border:2px solid #000}
</style></head><body>
<div id="astroHeader">
  <div><a href="/" style="text-decoration:none"><b style="font-size:22px;color:#0a2a8a">🚀 Astro Job SA</b><br><small style="color:#00a651;font-weight:800;letter-spacing:2px;font-size:10px">MADE BY MTHEMBISI</small></a></div>
  <div class="btns">
    <a href="/cv" class="btnCV">📄 CV</a>
    <a href="/post-job" class="btnPost">+ Post Job</a>
  </div>
</div>
<div class="hero"><h1>Your Future Starts Here, Mzansi 🇿🇦</h1><p>Real verified jobs SA, no scams!</p></div>
<form method="POST" class="searchBox"><input name="q" value="{{qq}}" placeholder="Driver"><input name="loc" value="{{loc}}" placeholder="Johannesburg"><button>🔍 Search</button></form>
<div class="jobs">
{% for j in jobs %}
<div class="job"><h3 style="margin:0 0 6px;color:#0a2a8a">{{j.title}}</h3><div style="font-size:12px;color:#64748b">🏢 {{j.company}} • 📍 {{j.location}} • {{j.created}}</div><div style="font-size:13px;margin-top:6px">{{j.desc}}...</div><div style="margin-top:10px"><a href="{{j.url}}" target="_blank" style="background:#0a2a8a;color:#fff;padding:8px 14px;border-radius:8px;text-decoration:none;font-weight:800">Apply →</a> <a href="https://wa.me/?text={{share_text}}%20{{j.url}}" target="_blank" style="background:#22c55e;color:#000;padding:8px 14px;border-radius:8px;text-decoration:none;font-weight:800">WhatsApp</a></div></div>
{% endfor %}
</div>
<!-- BUYMEACOFFEE - YOUR ACCOUNT -->
<a href="https://www.buymeacoffee.com/astrojobsa" target="_blank" class="coffeeF">☕ Buy Me a Coffee</a>
</body></html>
"""

@app.route("/", methods=["GET","POST"])
def home():
    raw_q=(request.form.get("q","Driver") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc=(request.form.get("loc","South Africa") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    if is_traversal_attack(raw_q) or is_traversal_attack(raw_loc): return "403 WAF Blocked",403
    qq=sanitize(raw_q,40) or "Driver"
    loc_q=sanitize(raw_loc,40) or "South Africa"
    jobs=get_jobs(qq,loc_q)
    share_text="Astro Job SA - Made by Mthembisi - https://astrojobsa.onrender.com"
    return render_template_string(HTML,jobs=jobs,qq=qq,loc=loc_q,share_text=share_text)

@app.after_request
def secure_headers(r):
    r.headers['X-Frame-Options']='DENY'
    r.headers['X-Content-Type-Options']='nosniff'
    return r

@app.route("/ads.txt")
def ads():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}

@app.route("/health")
def health(): return {"status":"ok","by":"Mthembisi"}

@app.route("/cv")
def cv(): 
    try: return render_template("cv.html")
    except: return "CV Maker - Coming soon <a href='/'>Home</a>"

@app.route("/post-job")
def post_job():
    try: return render_template("post-job.html")
    except: return "Post Job - WhatsApp 0812602918 <a href='/'>Home</a>"

if __name__=="__main__":
    app.run(host="0.0.0.0",port=8080,debug=False)
