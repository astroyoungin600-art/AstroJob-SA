from flask import Flask, request, render_template, Response, redirect
import re, random, os, time
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "astro-2026-final")
try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
except: pass

ADZUNA_ID = os.getenv("ADZUNA_ID", "REDACTED")
ADZUNA_KEY = os.getenv("ADZUNA_KEY", "REDACTED")
CACHE = {"jobs": [], "time": 0}
PROVINCES = ["Eastern Cape","Free State","Gauteng","KwaZulu-Natal","Limpopo","Mpumalanga","North West","Northern Cape","Western Cape"]
MAP = {
 "Gauteng": ["gauteng","johannesburg","pretoria","centurion","soweto","sandton","midrand"],
 "Western Cape": ["western cape","cape town","stellenbosch","paarl"],
 "KwaZulu-Natal": ["kwazulu","kzn","durban"],
 "Eastern Cape": ["eastern cape","port elizabeth","gqeberha","east london"],
 "Free State": ["free state","bloemfontein"],
 "Limpopo": ["limpopo","polokwane"],
 "Mpumalanga": ["mpumalanga","nelspruit"],
 "North West": ["north west","rustenburg"],
 "Northern Cape": ["northern cape","kimberley"],
}

def fetch(q, loc):
    import requests
    # cache 10 min
    if time.time() - CACHE["time"] < 600 and CACHE["jobs"] and not q and not loc:
        return CACHE["jobs"]
    try:
        what = q or ""
        where = loc if loc and loc.lower()!="all south africa" else "South Africa"
        url = f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ADZUNA_ID}&app_key={ADZUNA_KEY}&results_per_page=50&what={what}&where={where}"
        print(f"FETCH Adzuna what={what} where={where}")
        j = requests.get(url, timeout=12).json().get("results", [])
        if not q and not loc:
            CACHE["jobs"]=j
            CACHE["time"]=time.time()
        return j
    except Exception as e:
        print("Adzuna error", e)
        return CACHE["jobs"] or []

def get_jobs(q, loc):
    raw = fetch(q, loc)
    jobs=[]
    locl=(loc or "").lower()
    # ONLY filter by location, NOT by q (Adzuna already did q)
    for r in raw:
        title=r.get("title","")
        comp=r.get("company",{}).get("display_name","")
        place=r.get("location",{}).get("display_name","South Africa")
        desc=r.get("description","")[:150]
        url=r.get("redirect_url","")
        if locl and locl!="all south africa":
            keys=MAP.get(loc, [locl])
            if locl not in place.lower() and not any(k in place.lower() for k in keys):
                # if Adzuna where is loose, skip non-matching province
                if loc.lower()!="all south africa":
                    continue
        slug=re.sub(r'[^a-z0-9]+','-',title.lower()).strip('-')[:60]
        jobs.append({"title":title,"company":comp,"location":place,"url":url,"slug":slug,"desc":desc})
    if jobs:
        return jobs[:18]
    # fallback DB so never blank
    DB=[("Social Worker - JHB","Dept Social","Gauteng"),("Soc Analyst NPO","NPO","Remote"),("Driver Code 14 JHB R25k","Unitrans","Johannesburg"),("Driver Code 10 Durban","Famous Brands","Durban"),("Cashier Soweto R8.5k","Shoprite","Soweto"),("General Worker CPT","Woolworths","Cape Town"),("Retail Assistant JHB","Pick n Pay","Johannesburg")]
    out=[]
    for t,c,l in DB:
        if locl and locl!="all south africa" and locl not in l.lower():
            if not any(k in l.lower() for k in MAP.get(loc,[])): continue
        if q and q.lower() not in t.lower(): continue
        out.append({"title":t,"company":c,"location":l,"url":"https://www.adzuna.co.za/","slug":re.sub(r'[^a-z0-9]+','-',t.lower()),"desc":t})
    return out[:18] if out else [{"title":t,"company":c,"location":l,"url":"https://www.adzuna.co.za/","slug":"x","desc":t} for t,c,l in DB[:6]]

@app.route("/",methods=["GET","POST"])
def home():
    qq=request.values.get("q","").strip()[:40]
    loc=request.values.get("loc","").strip()[:40]
    print(f"SEARCH q={qq} loc={loc}")
    jobs=get_jobs(qq, loc)
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
@app.route('/apply/<slug>')
def apply_external(slug):
    s=slug.lower()
    for j in CACHE.get("jobs",[]):
        t=j.get("title","").lower()
        u=j.get("redirect_url","")
        if u and re.sub(r'[^a-z0-9]+','-',t).strip('-') in s:
            return redirect(u,302)
    return redirect(f"https://www.adzuna.co.za/jobs?what={s.split('-')[0]}",302)
@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")
