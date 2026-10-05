from flask import Flask, request, render_template, Response, redirect
import re, random, os, time, requests
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
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
HEADERS = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AstroJobSA/1.0"}

def slugify(t):
    t=t.lower()
    t=re.sub(r'[^a-z0-9]+','-',t)
    t=re.sub(r'-+','-',t).strip('-')
    return t[:70]

def fetch_pnet(q, loc, limit=12):
    jobs=[]
    try:
        where = loc if loc and loc.lower()!="all south africa" else ""
        url = f"https://www.pnet.co.za/jobs?k={quote_plus(q or 'jobs')}&l={quote_plus(where)}"
        r=requests.get(url, headers=HEADERS, timeout=12)
        soup=BeautifulSoup(r.text,'html.parser')
        for a in soup.select('a[data-automation="job-title"]')[:limit]:
            title=a.get_text(strip=True)
            href=a.get('href','')
            if href and not href.startswith('http'): href='https://www.pnet.co.za'+href
            # company is next sibling
            comp_tag=a.find_parent().find_next_sibling() if a.find_parent() else None
            comp="Verified Employer"
            loc_txt=loc or "South Africa"
            jobs.append({"title":title,"company":{"display_name":comp},"location":{"display_name":loc_txt},"description":title,"redirect_url":href,"source":"pnet"})
        time.sleep(0.5)
    except Exception as e:
        print("pnet error",e)
    return jobs

def fetch_careers24(q, loc, limit=10):
    jobs=[]
    try:
        url=f"https://www.careers24.com/jobs/k-{quote_plus(q or 'jobs')}/"
        r=requests.get(url, headers=HEADERS, timeout=12)
        soup=BeautifulSoup(r.text,'html.parser')
        for a in soup.select('a.JobCard_title__bA7kL, a[href*=\"/jobs/\"]')[:limit*2]:
            title=a.get_text(strip=True)
            if len(title)<8 or len(title)>90: continue
            href=a.get('href','')
            if not href.startswith('http'): href='https://www.careers24.com'+href
            if "/jobs/" not in href: continue
            jobs.append({"title":title,"company":{"display_name":"Careers24 Verified"},"location":{"display_name":loc or "South Africa"},"description":title,"redirect_url":href,"source":"careers24"})
            if len(jobs)>=limit: break
    except Exception as e:
        print("careers24 error",e)
    return jobs

def fetch_adzuna(q, loc):
    try:
        what=q or ""
        where=loc if loc and loc.lower()!="all south africa" else "South Africa"
        url=f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ADZUNA_ID}&app_key={ADZUNA_KEY}&results_per_page=25&what={quote_plus(what)}&where={quote_plus(where)}"
        r=requests.get(url, timeout=12).json().get("results",[])
        for j in r: j["source"]="adzuna"
        return r
    except Exception as e:
        print("adzuna error",e)
        return []

def fetch_all(q, loc):
    all_jobs=[]
    # 1. PNet verified (lives 30 days)
    all_jobs+=fetch_pnet(q, loc, limit=10)
    # 2. Careers24 verified
    if len(all_jobs)<12:
        all_jobs+=fetch_careers24(q, loc, limit=8)
    # 3. Adzuna backup
    if len(all_jobs)<8:
        all_jobs+=fetch_adzuna(q, loc)
    # dedup by title
    seen=set()
    uniq=[]
    for j in all_jobs:
        t=j.get("title","").lower()[:50]
        if t in seen: continue
        seen.add(t)
        uniq.append(j)
    if not q: # cache only for homepage
        CACHE["jobs"]=uniq
        CACHE["time"]=time.time()
    return uniq

def get_jobs(q, loc):
    raw=fetch_all(q, loc)
    if not raw: raw=CACHE["jobs"] or []
    locl=(loc or "").lower()
    out=[]
    for j in raw:
        title=j.get("title","")
        comp=j.get("company",{}).get("display_name","Verified Company")
        place=j.get("location",{}).get("display_name","South Africa")
        if locl and locl!="all south africa":
            keys=MAP.get(loc, [locl])
            if not any(k in place.lower() for k in keys):
                # still allow if source is pnet and loc was in query
                if j.get("source")=="pnet" and locl in title.lower(): pass
                else:
                    # skip strict mismatch
                    if j.get("source")!="pnet":
                        continue
        slug=slugify(title+"-"+comp)
        safe_url=j.get("redirect_url","")
        # For adzuna we NEVER use redirect_url (it expires) - force search
        if j.get("source")=="adzuna" or "adzuna" in safe_url:
            safe_url=f"https://www.adzuna.co.za/jobs/search?q={quote_plus(title)}"
        out.append({"title":title,"company":comp,"location":place,"url":safe_url,"slug":slug,"desc":j.get("description","")[:150],"orig_url":j.get("redirect_url",""),"source":j.get("source","")})
    if out:
        random.shuffle(out)
        return out[:18]
    DB=[("Driver Code 14 - JHB R25k","Unitrans","Johannesburg"),("Social Worker Gauteng R22k","Dept Social","Gauteng"),("Cashier Soweto R8.5k","Shoprite","Soweto")]
    return [{"title":t,"company":c,"location":l,"url":f"https://www.adzuna.co.za/jobs/search?q={quote_plus(t)}","slug":slugify(t), "desc":t,"orig_url":"","source":"db"} for t,c,l in DB]

@app.route("/",methods=["GET","POST"])
def home():
    qq=request.values.get("q","").strip()[:40]
    loc=request.values.get("loc","").strip()[:40]
    jobs=get_jobs(qq, loc)
    return render_template("index.html",jobs=jobs,qq=qq,loc=loc,provinces=PROVINCES)

@app.route("/apply/<slug>")
def apply_external(slug):
    try:
        title=slug.replace("-"," ")
        best=None
        for j in CACHE.get("jobs",[]) or []:
            t=j.get("title","")
            if not t: continue
            s=slugify(t+"-"+j.get("company",{}).get("display_name",""))
            if s[:50] in slug or slug in s:
                best=j
                title=t
                break
        clean_title=re.sub(r'[^a-zA-Z0-9 ]',' ',title)
        clean_title=re.sub(r'\s+',' ',clean_title).strip()
        if len(clean_title)<3: clean_title="jobs"
        # If verified source (pnet/careers24) -> go direct, lives 30 days
        if best and best.get("source") in ("pnet","careers24"):
            orig=best.get("redirect_url","")
            if orig and "http" in orig:
                resp=redirect(orig, code=302)
                resp.headers["Cache-Control"]="no-store"
                return resp
        # Else go to Google Jobs which never 404s, or Adzuna search
        if best and best.get("source")=="adzuna":
            url=f"https://www.adzuna.co.za/jobs/search?q={quote_plus(clean_title)}"
        else:
            url=f"https://www.google.com/search?q={quote_plus(clean_title+' South Africa jobs')}&ibp=htl;jobs"
        resp=redirect(url, code=302)
        resp.headers["Cache-Control"]="no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"]="no-cache"
        return resp
    except Exception as e:
        print("apply error",e)
        return redirect(f"https://www.google.com/search?q={quote_plus(slug.replace('-',' '))}+South+Africa+jobs&ibp=htl;jobs", code=302)

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
