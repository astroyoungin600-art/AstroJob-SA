from flask import Flask, render_template_string, request, render_template, redirect
import requests, os, re, logging, time
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()
try:
 from siem import siem_bp
except:
 siem_bp=None
 # dummy
app = Flask(__name__)
if siem_bp:
 app.register_blueprint(siem_bp)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.secret_key = "astro-siem-2026-strong-key-mthembisi"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24).hex()
APP_ID = os.environ.get("ADZUNA_ID")
APP_KEY = os.environ.get("ADZUNA_KEY")
job_cache = {"jobs":[], "time":0, "q":"", "loc":""}

def is_traversal_attack(value):
    if not value: return False
    low = value.lower()
    for p in ["..", "%2e", "etc/passwd", ".env", "/etc", "/proc", "\\", "%00"]:
        if p in low: return True
    return False
def is_safe_url(url):
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return p.scheme in ("http","https") and "." in p.netloc and "adzuna" not in p.netloc.lower()
    except: return False
def sanitize(text, maxlen=40):
    if not text: return ""
    if is_traversal_attack(text):
        logging.warning(f"WAF BLOCKED: {text[:100]}")
        return ""
    text = re.sub(r'[^a-zA-Z0-9 \-]', '', text)
    return text.strip()[:maxlen]

def get_jobs(q="Driver", loc="South Africa"):
    global job_cache
    # Cache 5 mins for speed - fixes lag
    now = time.time()
    if job_cache["jobs"] and (now - job_cache["time"] < 300) and job_cache["q"]==q and job_cache["loc"]==loc:
        return job_cache["jobs"]
    if not APP_ID or not APP_KEY:
        logging.warning("ADZUNA keys missing")
        return []
    q = sanitize(q, 40) or "Driver"
    loc = sanitize(loc, 40) or "South Africa"
    url = f"https://api.adzuna.com/v1/api/jobs/za/search/1"
    params = {"app_id": APP_ID, "app_key": APP_KEY, "results_per_page": 50, "what": q, "where": loc}
    try:
        r = requests.get(url, params=params, timeout=12)
        if r.status_code!=200: return []
        data = r.json()
        jobs=[]
        for j in data.get("results",[]):
            title = j.get("title","")
            if "whatsapp" in title.lower() or "telegram" in title.lower(): continue
            if not j.get("redirect_url"): continue
            safe_desc = (j.get("description","")[:200]).replace("<","").replace(">","")
            jobs.append({
                "title": re.sub(r'[^a-zA-Z0-9 \-]', ' ', title)[:120],
                "company": re.sub(r'[^a-zA-Z0-9 \-]', ' ', j.get("company",{}).get("display_name","Top Company"))[:80],
                "location": re.sub(r'[^a-zA-Z0-9 \-]', ' ', j.get("location",{}).get("display_name",loc))[:80],
                "desc": safe_desc,
                "url": j.get("redirect_url",""),
                "created": j.get("created","")[:10]
            })
        job_cache = {"jobs": jobs, "time": now, "q": q, "loc": loc}
        return jobs
    except Exception as e:
        logging.error(f"API Error: {e}")
        return job_cache["jobs"] if job_cache["jobs"] else []

HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Astro Job SA - Real Jobs | Made by Mthembisi</title>
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2133699761079270" crossorigin="anonymous"></script>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui;background:#f8fafc;color:#0f172a}
#astroHeader{position:sticky;top:0;z-index:99999;background:#fff;display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:4px solid #0a2a8a;box-shadow:0 2px 12px rgba(0,0,0,.08)}
.logo{line-height:1.1}.logo a{text-decoration:none}.logo b{font-size:22px;color:#0a2a8a}.logo span{color:#00a651}.logo small{display:block;color:#00a651;font-weight:800;letter-spacing:2px;font-size:10px;margin-top:2px}
.btns{display:flex;gap:8px}.btns a{padding:10px 18px;border-radius:12px;font-weight:900;text-decoration:none;font-size:14px}
.btnCV{background:#22c55e;color:#000}.btnPost{background:#0a2a8a;color:#fff}
.hero{background:linear-gradient(135deg,#0a2a8a 0%,#00a651 100%);color:#fff;padding:28px 16px;text-align:center}
.hero h1{margin:0;font-size:26px}.hero p{opacity:.9}
.searchBox{background:#fff;max-width:900px;margin:-18px auto 0;padding:14px;border-radius:14px;box-shadow:0 8px 24px rgba(0,0,0,.1);display:flex;gap:8px;flex-wrap:wrap}
.searchBox input{flex:1;min-width:180px;padding:12px;border:1px solid #cbd5e1;border-radius:10px}
.searchBox button{padding:12px 20px;background:#0a2a8a;color:#fff;border:0;border-radius:10px;font-weight:900;cursor:pointer}
.jobs{max-width:900px;margin:20px auto;padding:0 12px;display:grid;gap:12px}
.job{background:#fff;padding:16px;border-radius:14px;box-shadow:0 2px 8px rgba(0,0,0,.05);border-left:4px solid #0a2a8a}
.job h3{margin:0 0 6px;font-size:16px;color:#0a2a8a}.meta{font-size:12px;color:#64748b;margin-bottom:8px}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.actions a{padding:8px 14px;border-radius:8px;text-decoration:none;font-weight:800;font-size:13px}
.apply{background:#0a2a8a;color:#fff}.whats{background:#22c55e;color:#000}
.coffeeF{position:fixed;bottom:18px;right:14px;z-index:99999;background:#FFDD00;color:#000;padding:12px 20px;border-radius:30px;font-weight:900;box-shadow:0 6px 20px rgba(0,0,0,.25);text-decoration:none;border:2px solid #000}
footer{padding:30px;text-align:center;color:#64748b;font-size:12px}
</style></head><body>
<div id="astroHeader">
  <div class="logo"><a href="/"><b>🚀 Astro Job SA</b><br><small>MADE BY MTHEMBISI</small></a></div>
  <div class="btns">
    <a href="/cv" class="btnCV">📄 CV</a>
    <a href="/post-job" class="btnPost">+ Post Job</a>
  </div>
</div>
<div class="hero">
  <h1>Your Future Starts Here, Mzansi 🇿🇦</h1>
  <p>Real verified jobs SA, no scams! - Built in Johannesburg for SA youth</p>
  <p style="margin-top:8px;font-size:12px;background:rgba(255,255,255,.15);display:inline-block;padding:6px 12px;border-radius:20px">📄 Free CV Maker • Get 10x More Applicants</p>
</div>
<form method="POST" class="searchBox">
  <input name="q" value="{{qq}}" placeholder="Job title, e.g. Driver, Cashier">
  <input name="loc" value="{{loc}}" placeholder="Location, e.g. Johannesburg">
  <button type="submit">🔍 Search Jobs</button>
</form>
<div class="jobs">
{% for j in jobs %}
<div class="job">
  <h3>{{j.title}}</h3>
  <div class="meta">🏢 {{j.company}} • 📍 {{j.location}} • 🕒 {{j.created}}</div>
  <div style="font-size:13px;color:#334155">{{j.desc}}...</div>
  <div class="actions">
    <a href="{{j.url}}" target="_blank" class="apply">Apply on Company Site →</a>
    <a href="https://wa.me/?text={{share_text}}%20{{j.url}}" target="_blank" class="whats">WhatsApp Share</a>
  </div>
</div>
{% else %}
<div style="text-align:center;padding:30px;background:#fff;border-radius:14px">No jobs found for <b>{{qq}}</b> in <b>{{loc}}</b>. Try Driver, Cashier, General Worker</div>
{% endfor %}
</div>
<a href="https://www.buymeacoffee.com/mthembisi" target="_blank" class="coffeeF">☕ Buy Me a Coffee</a>
</body></html>
"""

@app.route("/", methods=["GET","POST"])
def home():
    raw_q = (request.form.get("q","Driver") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc = (request.form.get("loc","South Africa") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    if is_traversal_attack(raw_q) or is_traversal_attack(raw_loc):
        logging.warning(f"WAF 403: {raw_q} {raw_loc}")
        return "<h1>403 Forbidden - WAF Blocked</h1>", 403
    qq = sanitize(raw_q, 40) or "Driver"
    loc_q = sanitize(raw_loc, 40) or "South Africa"
    jobs = get_jobs(qq, loc_q)
    import datetime
    share_text = f"Astro Job SA - Made by Mthembisi - Real verified jobs SA, no scams! https://astrojobsa.onrender.com"
    return render_template_string(HTML, jobs=jobs, qq=qq, loc=loc_q, share_text=share_text)

@app.after_request
def secure_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return resp

@app.route("/ads.txt")
def ads_txt():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0", 200, {'Content-Type': 'text/plain'}

@app.route("/health")
def health():
    return {"status":"ok","app":"Astro Job SA","by":"Mthembisi","waf":"active"}

@app.route("/privacy")
def privacy():
    try: return open("privacy.html").read()
    except: return "<h1>Privacy Policy - Astro Job SA</h1><p>Contact: astroyoungin600@gmail.com</p>"

@app.route("/about")
def about():
    return "<h1>About Astro Job SA - Made by Mthembisi</h1><p>Built in Johannesburg for SA youth. No scams, no fees, just real verified jobs.</p><p>Contact: astroyoungin600@gmail.com</p><a href='/'>Back</a>"

@app.route("/contact")
def contact():
    return "<h1>Contact</h1><p>Email: astroyoungin600@gmail.com<br>Johannesburg, SA</p><a href='/'>Back</a>"

@app.route("/cv")
def cv_page():
    try: return render_template("cv.html")
    except: return redirect("/")

@app.route("/cvs")
def cvs_redirect():
    return redirect("/cv")

@app.route("/employee")
def employee_page_disabled():
    return redirect("/cv")

@app.route("/post-job")
def post_job():
    try: return render_template("post-job.html")
    except: return "<h1>Post a Job</h1><p>WhatsApp: 0812602918</p><a href='/'>Back</a>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
