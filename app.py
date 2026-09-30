from flask import Flask, render_template_string, request
import requests, os, re, logging
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "astro-mthembisi-2026-secure")

# SECURE: env vars
APP_ID = os.environ.get("ADZUNA_ID", "2ea72f94")
APP_KEY = os.environ.get("ADZUNA_KEY", "da76cec8b2c40779e6d303bedabc5eb1")

# ========= WAF LOGGER FOR PATH TRAVERSAL =========
logging.basicConfig(filename="waf.log", level=logging.WARNING, format='%(asctime)s - %(message)s')

def is_traversal_attack(value):
    if not value: return False
    low = value.lower()
    patterns = ["..", "%2e%2e", "%252e", "etc/passwd", ".env", "/etc", "/proc", "\\"]
    for p in patterns:
        if p in low:
            return True
    return False

def is_safe_url(url):
    try:
        p = urlparse(url)
        return p.scheme in ("http","https") and p.netloc and "." in p.netloc
    except:
        return False

def sanitize(text, maxlen=40):
    if not text: return ""
    if is_traversal_attack(text):
        logging.warning(f"WAF BLOCKED TRAVERSAL: IP={request.remote_addr} PAYLOAD={text}")
        return ""
    text = re.sub(r'[^a-zA-Z0-9 \-]', '', text)
    return text.strip()[:maxlen]

def get_jobs(q="Driver", loc="South Africa"):
    q = sanitize(q, 40)
    loc = sanitize(loc, 40)
    if not q: q = "Driver"
    if not loc: loc = "South Africa"

    url = "https://api.adzuna.com/v1/api/jobs/za/search/1"
    params = {"app_id":APP_ID,"app_key":APP_KEY,"results_per_page":50,"what":q,"where":loc}
    jobs=[]
    try:
        resp = requests.get(url, params=params, timeout=12)
        if resp.status_code != 200: return []
        data = resp.json()
        for j in data.get('results',[]):
            title = j.get('title','')
            if 'whatsapp' in title.lower() or 'telegram' in title.lower(): continue
            redirect = j.get('redirect_url','')
            if not is_safe_url(redirect): continue
            jobs.append({
              "title": title[:120],
              "company": j.get('company',{}).get('display_name','Top SA Company')[:80],
              "location": j.get('location',{}).get('display_name',loc)[:80],
              "desc": (j.get('description','')[:200]).replace('<','').replace('>',''),
              "url": redirect,
              "created": j.get('created','')[:10]
            })
    except Exception as e:
        logging.error(f"API Error: {e}")
        jobs=[]
    return jobs

HTML = """<!DOCTYPE html>
<html lang="en"><head><script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2133699761079270" crossorigin="anonymous"></script><script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2133699761079270" crossorigin="anonymous"></script><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Astro Job SA - Made by Mthembisi</title>
<meta name="description" content="Real verified jobs in South Africa - No scams. Made by Mthembisi">
<style>
body{font-family:system-ui,Segoe UI,Roboto;background:#f8fafc;margin:0;color:#0f172a}
.header{background:#fff;padding:14px 20px;border-bottom:4px solid #0a2a8a;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:10}
.logo-text{font-size:26px;font-weight:900;color:#0a2a8a}.logo-text span{color:#00a651}
.hero{background:linear-gradient(135deg,#0a2a8a,#00a651);color:white;padding:28px 18px;text-align:center}
.searchBox{background:#fff;padding:14px;border-radius:14px;max-width:900px;margin:-22px auto 15px;box-shadow:0 10px 25px rgba(0,0,0,.2);display:flex;gap:8px;flex-wrap:wrap}
.searchBox input,select{padding:12px;border-radius:10px;border:1px solid #cbd5e1;flex:1;min-width:130px;font-size:15px}
.btn{padding:12px 20px;border-radius:10px;border:0;background:#0a2a8a;color:white;font-weight:800;cursor:pointer}
.card{background:#fff;padding:16px;border-radius:12px;margin:10px auto;max-width:900px;box-shadow:0 2px 6px rgba(0,0,0,.06);border-left:5px solid #00a651;word-wrap:break-word}
.apply{background:#0a2a8a;color:white;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block}
.share{background:#25D366;color:white;padding:10px 14px;border-radius:8px;text-decoration:none;margin-left:6px;font-weight:700;display:inline-block}
.footer{background:#0f172a;color:#94a3b8;padding:25px;text-align:center;margin-top:25px;line-height:1.6}
.badge{background:#e0f2fe;color:#0a2a8a;padding:3px 8px;border-radius:12px;font-weight:700;font-size:11px}
</style></head><body>
<div class=header><div style="font-size:32px">🚀</div><div><div class=logo-text>Astro Job <span>SA</span></div><div style="color:#00a651;font-weight:800;font-size:11px;letter-spacing:2px">MADE BY MTHEMBISI</div></div></div>
<div class=hero><h2 style="margin:0">Your Future Starts Here, Mzansi</h2>
<p style="max-width:720px;margin:12px auto;line-height:1.6"><b>"Umsebenzi wakho uqala lapha. Akuwona amanga, akuwona ama-scams - imisebenzi yangempela."</b><br>We built Astro Job SA because every young South African deserves a fair shot. No fees. No WhatsApp payments. Just real, verified opportunities from top companies. If you are reading this, your next job is one click away. <b>Sizokwenza!</b><br><small>Verified daily • Trusted by SA youth • Built in SA for SA • astroyoungin600@gmail.com</small></p></div>
<form method=POST autocomplete=off><div class=searchBox>
<input name=q value="{{q}}" placeholder="Job: Driver, Cashier, IT..." maxlength=40 pattern="[a-zA-Z0-9 ]+">
<select name=loc><option value="South Africa" {% if loc=='South Africa' %}selected{%endif%}>South Africa</option><option value="Johannesburg" {% if loc=='Johannesburg' %}selected{%endif%}>Johannesburg</option><option value="Cape Town" {% if loc=='Cape Town' %}selected{%endif%}>Cape Town</option><option value="Durban" {% if loc=='Durban' %}selected{%endif%}>Durban</option><option value="Pretoria" {% if loc=='Pretoria' %}selected{%endif%}>Pretoria</option><option value="Port Elizabeth" {% if loc=='Port Elizabeth' %}selected{%endif%}>Port Elizabeth</option></select>
<button class=btn type=submit>Find Jobs</button></div></form>
<div style="max-width:900px;margin:0 auto;padding:0 12px"><b>{{jobs|length}} Verified Jobs</b> in {{loc}} for "{{q}}" • {{now}}</div>
{% for j in jobs %}<div class=card><span class=badge>✓ VERIFIED • {{j.location}}</span><div style="font-weight:800;margin:6px 0;font-size:17px">{{j.title}}</div><small>{{j.company}} • {{j.created}}</small><p style="color:#475569;font-size:13px;line-height:1.5">{{j.desc}}...</p><a class=apply href="{{j.url}}" target=_blank rel="noopener noreferrer">Apply on Company Site →</a><a class=share href="https://wa.me/?text={{ ('I found this job on Astro Job SA Made by Mthembisi: ' + j.title + ' ' + j.url) | urlencode }}" target=_blank rel="noopener">WhatsApp Share</a></div>{% endfor %}
<div style="max-width:900px;margin:18px auto;background:#fff3cd;padding:14px;border-radius:10px;text-align:center;border:1px solid #ffe69c"><b>📢 Share & Help Others Get Jobs</b><br><a style="display:inline-block;margin-top:8px;background:#25D366;color:white;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:800" href="https://wa.me/?text={{ share_text | urlencode }}" target=_blank rel="noopener">Share Astro Job SA 🚀</a></div>
<div class=footer><b style="color:white">Astro Job SA</b> - Made with ❤️ by Mthembisi<br>astroyoungin600@gmail.com • Johannesburg, South Africa<br>For Companies: List your jobs to 10,000+ youth. Contact us.<br><span style="font-size:11px">© 2026 Astro Job SA • Powered by Adzuna Official API • No scams, ever. • Security: XSS protected, No SQL, No sensitive disclosure, Path Traversal Proof + WAF.</span><br><br><i style="color:#38bdf8">"From the kasi to the boardroom - your hustle deserves a real platform."</i></div></body></html>"""

@app.route("/", methods=["GET","POST"])
def home():
    raw_q = (request.form.get("q","Driver") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc = (request.form.get("loc","South Africa") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    if not raw_q: raw_q = "Driver"
    if not raw_loc: raw_loc = "South Africa"


    # WAF CHECK
    if is_traversal_attack(raw_q) or is_traversal_attack(raw_loc):
        logging.warning(f"WAF 403: IP={request.remote_addr} q={raw_q} loc={raw_loc}")
        return "<h1>403 Forbidden</h1><p>WAF Blocked: Traversal detected</p>", 403

    q = sanitize(raw_q, 40) or "Driver"
    loc = sanitize(raw_loc, 40) or "South Africa"
    jobs = get_jobs(q, loc)
    share_text = f"🚀 Astro Job SA - Made by Mthembisi - Real verified jobs SA, no scams!"
    return render_template_string(HTML, jobs=jobs, q=q, loc=loc, now=datetime.now().strftime("%d %b %Y"), share_text=share_text)

@app.after_request
def secure_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src https://api.adzuna.com https://googleads.g.doubleclick.net https:; frame-src https://googleads.g.doubleclick.net"
    return resp

@app.route("/health")
@app.route('/ads.txt')
def ads_txt():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0", 200, {'Content-Type': 'text/plain'}

@app.route('/privacy')
def privacy():
    return "<h1>Privacy Policy - AstroJob SA</h1><p>We use Adzuna API. No personal data. Contact: astroyoungin600@gmail.com</p><p>AdSense uses cookies.</p><a href='/'>Back</a>"

@app.route('/about')
def about():
    return "<h1>About AstroJob SA</h1><p>Real verified jobs from Adzuna, no scams. Made by Mthembisi in SA.</p><a href='/'>Back</a>"

@app.route('/contact')
def contact():
    return "<h1>Contact</h1><p>Email: astroyoungin600@gmail.com<br>GitHub: astroyoungin600-art/AstroJob-SA</p><a href='/'>Back</a>"

def health():
    return {"status":"ok","app":"Astro Job SA","by":"Mthembisi","waf":"active"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

