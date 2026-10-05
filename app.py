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
PROVINCES = ["Eastern Cape","Free State","Gauteng","KwaZulu-Natal","Limpopo","Mpumalanga","North West","Northern Cape","Western Cape"]
PROVINCE_MAP = {
 "Gauteng": ["gauteng","johannesburg","jhb","pretoria","pta","centurion","soweto","sandton","midrand","ekurhuleni"],
 "Western Cape": ["western cape","cape town","cpt","stellenbosch","paarl","george"],
 "KwaZulu-Natal": ["kwazulu","kzn","durban","pietermaritzburg"],
 "Eastern Cape": ["eastern cape","port elizabeth","gqeberha","east london"],
 "Free State": ["free state","bloemfontein"],
 "Limpopo": ["limpopo","polokwane"],
 "Mpumalanga": ["mpumalanga","nelspruit","witbank"],
 "North West": ["north west","rustenburg","mahikeng"],
 "Northern Cape": ["northern cape","kimberley"],
}

def fetch_adzuna(q, loc):
    import requests, time
    if time.time() - DB_CACHE["time"] < 600 and DB_CACHE["jobs"]:
        return DB_CACHE["jobs"]
    try:
        what = q if q else ""
        where = loc if loc else "South Africa"
        url = f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ADZUNA_ID}&app_key={ADZUNA_KEY}&results_per_page=50&what={what}&where={where}&sort_by=date"
        r = requests.get(url, timeout=10).json()
        jobs = r.get("results", [])
        DB_CACHE["jobs"] = jobs
        DB_CACHE["time"] = time.time()
        return jobs
    except:
        return DB_CACHE["jobs"] or []

def get_jobs(q, loc):
    raw = fetch_adzuna(q, loc)
    ql = (q or "").lower().strip()
    q_words = [w for w in ql.split() if len(w)>2]
    locl = (loc or "").lower().strip()
    loc_keywords = PROVINCE_MAP.get(loc, [locl]) if loc else []
    strict=[]
    for j in raw:
        title = j.get("title","")
        company = j.get("company",{}).get("display_name","")
        location = j.get("location",{}).get("display_name","South Africa")
        desc = j.get("description","")
        redirect_url = j.get("redirect_url","")
        # location filter
        if locl and locl!="all south africa":
            if locl not in location.lower() and not any(k in location.lower() for k in loc_keywords):
                continue
        # search filter - strict
        if ql:
            if ql not in title.lower() and ql not in desc.lower():
                # try any word
                if not any(w in title.lower() or w in desc.lower() for w in q_words):
                    continue
        slug = re.sub(r'[^a-z0-9]+','-', title.lower()).strip('-') + "-" + re.sub(r'[^a-z0-9]+','-', company.lower()).strip('-')
        strict.append({"title": title,"company": company,"location": location,"url": redirect_url,"slug": slug,"desc": desc[:150]})
    if strict:
        random.shuffle(strict)
        return strict[:18]
    # lenient fallback - ignore location if too strict, show what we have
    fallback=[]
    for j in raw[:30]:
        title = j.get("title","")
        company = j.get("company",{}).get("display_name","")
        location = j.get("location",{}).get("display_name","South Africa")
        desc = j.get("description","")
        redirect_url = j.get("redirect_url","")
        slug = re.sub(r'[^a-z0-9]+','-', title.lower()).strip('-')
        fallback.append({"title": title,"company": company,"location": location,"url": redirect_url,"slug": slug,"desc": desc[:150]})
    if fallback:
        return fallback[:18]
    # ultimate local DB fallback
    DB=[("Driver Code 14 - JHB R25k","Unitrans","Johannesburg"),("Driver Code 10 - Durban R14k","Famous Brands","Durban"),("Code 14 + PDP - Gauteng R16k","Shoprite","Gauteng"),("Truck Driver - Cape Town R22k","Logistics SA","Cape Town"),("Delivery Driver - Soweto R12k","Takealot","Soweto"),("Cashier - Soweto R8.5k","Shoprite","Soweto"),("Shop Assistant - Pretoria R9k","Clicks","Pretoria"),("General Worker - CPT R7.5k","Woolworths","Cape Town"),("Retail Assistant - JHB R8k","Pick n Pay","Johannesburg"),("Nursing Assistant - Gauteng R18k","Life Hospital","Gauteng"),("Social Worker - Gauteng R22k","Dept Social","Gauteng"),("Soc Analyst - Remote R40k","NPO","Remote"),("Customer Care - Centurion R11k","Telkom","Centurion"),("Security Guard - JHB R9k","Fidelity","Johannesburg"),("Cleaner - Soweto Schools R6.5k","Dept Education","Soweto"),("Admin Clerk - Pretoria R15k","SASSA","Pretoria")]
    res=[]
    for t,c,l in DB:
        if locl and locl!="all south africa":
            if locl not in l.lower() and not any(k in l.lower() for k in loc_keywords): continue
        if ql and not any(w in t.lower() for w in q_words): continue
        res.append({"title":t,"company":c,"location":l,"url":f"https://www.adzuna.co.za/search?q={t}", "slug": re.sub(r'[^a-z0-9]+','-', t.lower()).strip('-'), "desc": t})
    if not res:
        res=[{"title":t,"company":c,"location":l,"url":"https://www.adzuna.co.za/", "slug": re.sub(r'[^a-z0-9]+','-', t.lower()).strip('-'), "desc": t} for t,c,l in DB[:10]]
    return res[:18]

@app.route("/",methods=["GET","POST"])
def home():
    qq=sanitize((request.form.get("q","") if request.method=="POST" else request.args.get("q","")).strip(),40)
    loc=sanitize((request.form.get("loc","") if request.method=="POST" else request.args.get("loc","")).strip(),40)
    jobs=get_jobs(qq,loc)
    return render_template("index.html",jobs=jobs,qq=qq,loc=loc,provinces=PROVINCES)

@app.route("/ads.txt")
def ads_txt(): return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}
@app.route("/robots.txt")
def robots(): return "User-agent: *\nAllow: /\nSitemap: https://astrojob-sa.onrender.com/sitemap.xml\n",200,{'Content-Type':'text/plain'}
@app.route("/sitemap.xml")
def sitemap(): return Response('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://astrojob-sa.onrender.com/</loc></url></urlset>', mimetype='application/xml')
@app.route("/health")
def health(): return "ok",200
@app.route("/cv")
def cv(): return render_template("cv.html")
@app.route("/post-job")
def post_job(): return render_template("post_job.html")
@app.route('/jobs/<slug>')
def job_slug(slug): return render_template('job_seo.html',slug=slug,content=f"{slug} - SA 2026",title=slug.title())
@app.route('/apply/<slug>')
def apply_external(slug):
    try:
        s = slug.lower()
        jobs = DB_CACHE.get("jobs", [])
        for j in jobs:
            title = j.get('title','').lower()
            redirect_url = j.get('redirect_url','')
            if not redirect_url: continue
            slugified = re.sub(r'[^a-z0-9]+','-', title).strip('-')
            if slugified and slugified in s: return redirect(redirect_url, code=302)
        return redirect(f'https://www.adzuna.co.za/jobs?what={s.split("-")[0]}', code=302)
    except:
        return redirect('https://www.adzuna.co.za/', code=302)
@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")
