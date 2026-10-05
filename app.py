from flask import Flask, request, render_template, Response, redirect
from datetime import timedelta
import re, random, os
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "astro-job-sa-2026-fixed-7day-random-x9k2m4p7-no-phone")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
except: pass

def sanitize(s,n): return re.sub(r'[^a-zA-Z0-9 \-]', '', s)[:n] if s else ""

ADZUNA_ID = os.getenv("ADZUNA_ID", "REDACTED")
ADZUNA_KEY = os.getenv("ADZUNA_KEY", "REDACTED")

DB_CACHE = {"jobs": [], "time": 0}

def fetch_adzuna(q, loc):
    import requests, time
    # cache 10 min
    if time.time() - DB_CACHE["time"] < 600 and DB_CACHE["jobs"]:
        jobs = DB_CACHE["jobs"]
    else:
        try:
            url = f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ADZUNA_ID}&app_key={ADZUNA_KEY}&results_per_page=30&what={q}&where={loc}&sort_by=date"
            r = requests.get(url, timeout=10).json()
            jobs = r.get("results", [])
            DB_CACHE["jobs"] = jobs
            DB_CACHE["time"] = time.time()
        except Exception as e:
            print(f"Adzuna fetch error {e}")
            jobs = DB_CACHE["jobs"] or []
    return jobs

def get_jobs(q, loc):
    raw = fetch_adzuna(q, loc)
    res = []
    for j in raw:
        title = j.get("title","").strip()
        company = j.get("company",{}).get("display_name","")
        location = j.get("location",{}).get("display_name","South Africa")
        redirect_url = j.get("redirect_url","")
        # slug for /apply/
        slug = re.sub(r'[^a-z0-9]+','-', title.lower()).strip('-') + "-" + re.sub(r'[^a-z0-9]+','-', company.lower()).strip('-')
        res.append({
            "title": title,
            "company": company,
            "location": location,
            "url": redirect_url,  # REAL main company URL from Adzuna
            "slug": slug,
            "desc": j.get("description","")[:150]
        })
    if not res:
        # fallback hardcoded if API fails
        for t,c,l in DB:
            res.append({"title":t,"company":c,"location":l,"url":f"https://www.adzuna.co.za/search?q={t}", "slug": re.sub(r'[^a-z0-9]+','-', t.lower()).strip('-'), "desc": t})
    random.shuffle(res)
    return res[:18]

# Keep old DB as fallback only
DB=[("Driver Code 14 - JHB R25k","Unitrans","Johannesburg"),("Driver Code 10 - Durban R14k","Famous Brands","Durban"),("Code 14 + PDP - Gauteng R16k","Shoprite","Gauteng"),("Truck Driver - Cape Town R22k","Logistics SA","Cape Town"),("Delivery Driver - Soweto R12k","Takealot","Soweto"),("Cashier - Soweto R8.5k","Shoprite","Soweto"),("Shop Assistant - Pretoria R9k","Clicks","Pretoria"),("General Worker - CPT R7.5k","Woolworths","Cape Town"),("Retail Assistant - JHB R8k","Pick n Pay","Johannesburg"),("Nursing Assistant - Gauteng R18k","Life Hospital","Gauteng"),("Enrolled Nurse - JHB R28k","Netcare","Johannesburg"),("Data Entry Remote R12k","Remote Co","Remote"),("IT Support Remote R35k","BCX","Remote"),("Software Dev - CPT R65k","Takealot","Cape Town"),("Call Centre - Centurion R11k","Telkom","Centurion"),("Security Guard - JHB R9k","Fidelity","Johannesburg"),("Cleaner - Soweto Schools R6.5k","Dept Education","Soweto"),("Waiter - Sandton R7k+Tips","Restaurant","Sandton"),("Admin Clerk - Pretoria R15k","SASSA","Pretoria"),("Learnership - Mr Price","Mr Price","Durban")]

@app.route("/",methods=["GET","POST"])
def home():
    qq=sanitize((request.form.get("q","") if request.method=="POST" else request.args.get("q","Driver")).strip(),40) or "Driver"
    loc=sanitize((request.form.get("loc","") if request.method=="POST" else request.args.get("loc","South Africa")).strip(),40) or "South Africa"
    return render_template("index.html",jobs=get_jobs(qq,loc),qq=qq,loc=loc)
@app.route("/ads.txt")
def ads_txt(): return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}
@app.route("/robots.txt")
def robots():
    return "User-agent: *\nAllow: /\nSitemap: https://astrojob-sa.onrender.com/sitemap.xml\n",200,{'Content-Type':'text/plain'}
@app.route("/sitemap.xml")
def sitemap(): return Response('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://astrojob-sa.onrender.com/</loc></url></urlset>', mimetype='application/xml')
@app.route("/health")
def health():
    if request.args.get('key') != os.getenv("RESET_SECRET","astro-health-2026"): return "ok",200
    return {"status":"ok","jobs":len(DB),"siem":"protected"}
@app.route("/cv")
def cv(): return render_template("cv.html")
@app.route("/post-job")
def post_job(): return render_template("post_job.html")
@app.route('/jobs/<slug>')
def job_slug(slug): return render_template('job_seo.html',slug=slug,content=f"{slug} - SA 2026",title=slug.title())
@app.route('/apply/<slug>')
def apply_external(slug):
    try:
        s = slug.lower().replace('-', ' ').strip()
        # 1. Exact match by slugified title
        for job in DB:
            if isinstance(job, dict):
                title = job.get('title','')
                url = job.get('url') or job.get('redirect_url') or ''
                company = job.get('company','')
            else:
                # tuple format fallback
                url = job[0] if len(job)>0 else ''
                title = job[1] if len(job)>1 else ''
                company = job[2] if len(job)>2 else ''
            if not url: continue
            t_low = title.lower()
            # if slug contains title words or vice versa
            if t_low and (t_low in s or s in t_low):
                return redirect(url, code=302)
            if company and company.lower() in s:
                return redirect(url, code=302)
        # 2. Fallback: return first Adzuna url that matches any word
        for job in DB:
            url = job.get('url') if isinstance(job, dict) else job[0]
            if url and 'adzuna' in url.lower():
                title = (job.get('title') if isinstance(job, dict) else job[1]).lower()
                if any(w in title for w in s.split() if len(w)>3):
                    return redirect(url, code=302)
    except Exception as e:
        print(f"apply error {e}")
    # FINAL fallback - Adzuna SA search (main company aggregator you use)
    q=slug.replace('-', ' ')
    return redirect(f'https://www.adzuna.co.za/search?q={q}', code=302)


@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")
