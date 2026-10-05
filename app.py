from flask import Flask, request, render_template, Response, redirect
import re, random, os, time
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "astro-2026-final-fix")
try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
except: pass

ADZUNA_ID = os.getenv("ADZUNA_ID", "REDACTED")
ADZUNA_KEY = os.getenv("ADZUNA_KEY", "REDACTED")
CACHE = {"jobs": [], "time": 0}
PROVINCES = ["Eastern Cape","Free State","Gauteng","KwaZulu-Natal","Limpopo","Mpumalanga","North West","Northern Cape","Western Cape"]
MAP = {
 "Gauteng": ["gauteng","johannesburg","jhb","pretoria","pta","centurion","soweto","sandton","midrand","ekurhuleni","randburg"],
 "Western Cape": ["western cape","cape town","cpt","stellenbosch","paarl","george"],
 "KwaZulu-Natal": ["kwazulu","kzn","durban","pietermaritzburg"],
 "Eastern Cape": ["eastern cape","port elizabeth","gqeberha","east london"],
 "Free State": ["free state","bloemfontein"],
 "Limpopo": ["limpopo","polokwane"],
 "Mpumalanga": ["mpumalanga","nelspruit","witbank"],
 "North West": ["north west","rustenburg","mahikeng"],
 "Northern Cape": ["northern cape","kimberley"],
}

def fetch(q, loc):
    import requests
    try:
        what = q or ""
        where = loc if loc and loc.lower()!="all south africa" else "South Africa"
        url = f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ADZUNA_ID}&app_key={ADZUNA_KEY}&results_per_page=50&what={what}&where={where}"
        r = requests.get(url, timeout=12).json().get("results", [])
        if not q:
            CACHE["jobs"]=r
            CACHE["time"]=time.time()
        return r
    except Exception as e:
        print("Adzuna error", e)
        return CACHE["jobs"] or []

def get_jobs(q, loc):
    raw = fetch(q, loc)
    locl=(loc or "").lower()
    out=[]
    for j in raw:
        title=j.get("title","")
        comp=j.get("company",{}).get("display_name","")
        place=j.get("location",{}).get("display_name","South Africa")
        # STRICT province filter - no Cape Town when Gauteng selected
        if locl and locl!="all south africa":
            keys=MAP.get(loc, [locl])
            if not any(k in place.lower() for k in keys):
                continue
        slug=re.sub(r'[^a-z0-9]+','-',title.lower()).strip('-')[:70]
        # store safe searchable URL, NOT expiring redirect_url
        safe_url = f"https://www.adzuna.co.za/jobs/search?q={title.replace(' ','+')}&w={place.replace(' ','+')}"
        out.append({"title":title,"company":comp,"location":place,"url":safe_url,"slug":slug,"desc":j.get("description","")[:150],"orig_url":j.get("redirect_url","")})
    if out:
        random.shuffle(out)
        return out[:18]
    # fallback never blank
    DB=[("Driver Code 14 - JHB R25k","Unitrans","Johannesburg"),("Social Worker Gauteng R22k","Dept Social","Gauteng"),("Cashier Soweto R8.5k","Shoprite","Soweto")]
    return [{"title":t,"company":c,"location":l,"url":f"https://www.adzuna.co.za/jobs/search?q={t.replace(' ','+')}","slug":re.sub(r'[^a-z0-9]+','-',t.lower()),"desc":t,"orig_url":""} for t,c,l in DB]

@app.route("/",methods=["GET","POST"])
def home():
    qq=request.values.get("q","").strip()[:40]
    loc=request.values.get("loc","").strip()[:40]
    jobs=get_jobs(qq, loc)
    return render_template("index.html",jobs=jobs,qq=qq,loc=loc,provinces=PROVINCES)

@app.route("/apply/<slug>")
def apply_external(slug):
    # NEVER use expired redirect_url - always search, so no "Cannot find page"
    try:
        s=slug.replace("-"," ")
        # try find original job in cache to get better query
        for j in CACHE.get("jobs",[]):
            t=j.get("title","")
            slugified=re.sub(r'[^a-z0-9]+','-',t.lower()).strip('-')
            if slugified and slugified[:50] in slug:
                # redirect to LIVE Adzuna search, not expired details page
                return redirect(f"https://www.adzuna.co.za/jobs/search?q={t.replace(' ','+')}", code=302)
        return redirect(f"https://www.adzuna.co.za/jobs/search?q={s}", code=302)
    except:
        return redirect("https://www.adzuna.co.za/jobs", code=302)

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
@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")
# v1791236657 fix apply redirect
