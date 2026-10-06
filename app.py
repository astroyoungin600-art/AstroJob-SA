from flask import Flask, request, render_template, Response, redirect
import re, random, os, time, requests
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
from datetime import timedelta, datetime
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
except Exception as e:
    print(f"SIEM not loaded: {e}")

ADZUNA_ID = os.getenv("ADZUNA_ID")
ADZUNA_KEY = os.getenv("ADZUNA_KEY")
CACHE = {"jobs": [], "time": 0}
PROVINCES = ["Eastern Cape","Free State","Gauteng","KwaZulu-Natal","Limpopo","Mpumalanga","North West","Northern Cape","Western Cape"]
HEADERS = {"User-Agent":"Mozilla/5.0 AstroJobSA/1.0"}

def slugify(t):
    return re.sub(r'[^a-z0-9]+','-',t.lower()).strip('-')[:70]

def fetch_adzuna(q, loc):
    if not ADZUNA_ID or not ADZUNA_KEY:
        return []
    try:
        url=f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ADZUNA_ID}&app_key={ADZUNA_KEY}&results_per_page=30&what={quote_plus(q or '')}&where={quote_plus(loc or 'South Africa')}"
        r=requests.get(url, timeout=10).json().get("results",[])
        for j in r: j["source"]="adzuna"
        return r
    except:
        return []

def fetch_careers24(q, loc, limit=10):
    jobs=[]
    try:
        url=f"https://www.careers24.com/jobs/k-{quote_plus(q or 'general')}/"
        r=requests.get(url, headers=HEADERS, timeout=8)
        soup=BeautifulSoup(r.text,'html.parser')
        for a in soup.find_all('a', href=True)[:40]:
            href=a['href']
            title=a.get_text(strip=True)
            if '/jobs/' in href and 12 < len(title) < 80:
                if href.startswith('/'): href='https://www.careers24.com'+href
                jobs.append({"title":title,"company":{"display_name":"Verified"},"location":{"display_name":loc or "South Africa"},"description":title,"redirect_url":href,"source":"careers24"})
            if len(jobs)>=limit: break
    except Exception as e:
        print("careers24 error",e)
    return jobs

def fetch_all(q, loc):
    if CACHE["jobs"] and time.time()-CACHE["time"]<1200 and not q:
        return CACHE["jobs"]
    all_jobs=[]
    try:
        if os.getenv("RENDER") is None:
            from verified_fetch import fetch_pnet
            all_jobs+=fetch_pnet(q, loc)
    except: pass
    all_jobs+=fetch_careers24(q, loc, limit=8)
    if len(all_jobs)<10:
        all_jobs+=fetch_adzuna(q, loc)
    seen=set(); uniq=[]
    for j in all_jobs:
        k=j.get("title","").lower()[:50]
        if k in seen: continue
        seen.add(k); uniq.append(j)
    if uniq and not q:
        CACHE["jobs"]=uniq; CACHE["time"]=time.time()
    return uniq or CACHE["jobs"]

def get_jobs(q, loc):
    raw=fetch_all(q, loc)
    out=[]
    for j in raw:
        title=j.get("title","")
        comp=j.get("company",{}).get("display_name","Verified Company")
        place=j.get("location",{}).get("display_name","South Africa")
        slug=slugify(title)
        if j.get("source")=="adzuna":
            url=f"https://www.adzuna.co.za/search?q={quote_plus(title)}"
        else:
            url=j.get("redirect_url", f"https://www.adzuna.co.za/search?q={quote_plus(title)}")
        out.append({"title":title,"company":comp,"location":place,"url":url,"slug":slug,"desc":j.get("description","")[:150],"source":j.get("source")})
    random.shuffle(out)
    return out[:18] or [{"title":"Driver Code 14 JHB R25k","company":"Unitrans","location":"Johannesburg","url":f"https://www.adzuna.co.za/search?q={quote_plus('Driver Code 14')}","slug":slugify("Driver Code 14"),"desc":"Verified"}]

@app.route("/",methods=["GET","POST"])
def home():
    qq=request.values.get("q","").strip()[:40]
    loc=request.values.get("loc","").strip()[:40]
    jobs=get_jobs(qq, loc)
    return render_template("index.html",jobs=jobs,qq=qq,loc=loc,provinces=PROVINCES)

@app.route("/apply/<slug>")
def apply_external(slug):
    try:
        from urllib.parse import quote_plus
        from datetime import datetime
        title = slug.replace("-", " ").strip()
        # clean for search
        clean = title[:60]

        # 1. Try direct employer link from cache
        best = None
        for j in CACHE.get("jobs", []) or []:
            if slug[:40] in j.get("title","").lower().replace(" ","-"):
                best = j
                break
        
        try:
            with open("clicks.txt","a") as f:
                f.write(f"{slug} {datetime.now()}\n")
        except: pass

        # 2. If we have direct link -> go there (best conversion)
        if best and best.get("redirect_url") and "http" in best.get("redirect_url",""):
            return redirect(best["redirect_url"], code=302)

        # 3. Else -> Adzuna LIVE search (this never 404s)
        # This is the "Browse all live results across South Africa"
        q = quote_plus(clean)
        # Try 3 valid Adzuna URLs in order
        # - /search?q=  = live search (primary)
        # - /jobs/advanced-search?q= = advanced search
        # - /search = browse all
        url = f"https://www.adzuna.co.za/search?q={q}"
        resp = redirect(url, code=302)
        resp.headers["Cache-Control"]="no-store"
        return resp
    except Exception as e:
        print("apply error", e)
        from urllib.parse import quote_plus
        return redirect(f"https://www.adzuna.co.za/search?q={quote_plus(slug.replace('-',' '))}", code=302)


@app.route("/ads.txt")
@app.route("/ads.txt")
def ads_txt():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nAllow: /\nSitemap: https://astrojob-sa.onrender.com/sitemap.xml\n",200,{'Content-Type':'text/plain'}

@app.route("/sitemap.xml")
def sitemap():
    return Response('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://astrojob-sa.onrender.com/</loc></url></urlset>', mimetype='application/xml')

@app.route("/health")
def health(): return "ok",200

@app.route("/cv")
def cv(): return render_template("cv.html")

@app.route("/post-job", methods=["GET","POST"])
def post_job():
    if request.method == "POST":
        company = request.form.get("company","")[:200]
        title = request.form.get("title","")[:200]
        location = request.form.get("location","")[:200]
        contact = request.form.get("contact","")[:200]
        package = request.form.get("package","")[:50]
        desc = request.form.get("desc","")[:500]
        try:
            with open("job_requests.txt","a") as f:
                f.write(f"{datetime.now()} | {package} | {company} | {title} | {location} | {contact}\n")
        except: pass
        msg = "NEW JOB: " + package + " | " + company + " | " + title + " | " + location + " | " + contact
        return redirect("https://wa.me/27812602918?text=" + quote_plus(msg))
    return render_template("post_job.html")

@app.route('/jobs/<slug>')
def job_slug(slug): return render_template('job_seo.html',slug=slug,content=f"{slug} - SA 2026",title=slug.title())

@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")

@app.route("/employee")
def employee_redirect():
    return redirect("/post-job", code=301)

try:
    from auto_poster import start_scheduler
    start_scheduler()
except: pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)))

@app.route("/search")
def advanced_search():
    qq = request.args.get("q","").strip()[:60]
    loc = request.args.get("loc","").strip()[:40]
    jtype = request.args.get("type","").strip()
    salary = request.args.get("salary","").strip()
    # Use existing fetch logic - searches ALL SA
    jobs = get_jobs(qq, loc)
    # Filter by type if requested (simple keyword filter)
    if jtype:
        jobs = [j for j in jobs if jtype.lower() in j.get("title","").lower() or jtype.lower() in j.get("desc","").lower()] or jobs
    return render_template("search.html", jobs=jobs, qq=qq, loc=loc, type=jtype, salary=salary, provinces=PROVINCES)
