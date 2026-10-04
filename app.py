from flask import Flask, request, render_template, jsonify
import requests
from bs4 import BeautifulSoup
import re, random, os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "astro-job-sa-2026-mthembisi-secret")

# --- Load Siem Blueprint ---
try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
    print("✅ Siem loaded")
except Exception as e:
    print(f"Siem not loaded: {e}")

SA_JOBS_DB = [
    ("Driver Code 14 - JHB", "Unitrans", "Johannesburg", "R18k-R25k", "Driver"),
    ("Driver Code 10 - Durban", "Famous Brands", "Durban", "R14k", "Driver"),
    ("Driver Code 14 + PDP - Gauteng", "Shoprite", "Gauteng", "R16k", "Driver"),
    ("Cashier - Soweto", "Shoprite", "Soweto", "R8.5k", "Retail"),
    ("Shop Assistant - Pretoria", "Clicks", "Pretoria", "R9k", "Retail"),
    ("General Worker - Cape Town", "Woolworths", "Cape Town", "R7.5k", "General"),
    ("Retail Assistant - JHB", "Pick n Pay", "Johannesburg", "R8k", "Retail"),
    ("Nursing Assistant - Gauteng", "Life Hospital", "Gauteng", "R18k", "Nursing"),
    ("Enrolled Nurse - JHB", "Netcare", "Johannesburg", "R28k", "Nursing"),
    ("Data Entry Remote - SA", "Remote Co", "Remote", "R12k-R15k", "Data Entry"),
    ("Data Capturer - Pretoria", "Gov", "Pretoria", "R13k", "Data Entry"),
    ("IT Support - Remote", "BCX", "Remote", "R35k", "IT"),
    ("Software Developer", "Takealot", "Cape Town", "R65k", "Software"),
    ("Call Centre Agent", "Telkom", "Centurion", "R11k", "Call Centre"),
    ("Security Guard - JHB", "Fidelity", "Johannesburg", "R9k", "Security"),
    ("Cleaner - Schools", "Dept Education", "Soweto", "R6.5k", "Cleaning"),
    ("Waiter - Sandton", "Restaurant Group", "Sandton", "R7k+Tips", "Hospitality"),
    ("Admin Clerk - Govt", "SASSA", "Pretoria", "R15k", "Admin"),
    ("HR Intern - Gauteng", "Transnet", "Gauteng", "R8k", "Intern"),
    ("Learnership - Retail", "Mr Price", "Durban", "Stipend", "Learnership"),
]

def sanitize(s,n): return re.sub(r'[^a-zA-Z0-9 \-]', '', s)[:n] if s else ""

def get_jobs(q, loc):
    ql = q.lower()
    locl = loc.lower()
    filtered = []
    for title, company, job_loc, salary, cat in SA_JOBS_DB:
        match_q = ql in title.lower() or ql in cat.lower() or ql in company.lower() or ql == "driver" and "driver" in title.lower()
        if not match_q and ql not in ["all", "jobs", "south africa", ""]:
            continue
        match_loc = locl in job_loc.lower() or locl in ["south africa", "sa", "all", ""] or "remote" in locl and "remote" in job_loc.lower()
        if locl in ["gauteng", "johannesburg", "soweto", "pretoria", "sandton"] and job_loc.lower() in ["johannesburg", "soweto", "pretoria", "gauteng", "sandton", "centurion"]:
            match_loc = True
        if match_q or ql in ["all", "jobs", ""]:
            if match_loc or locl in ["south africa", "sa", "all", ""]:
                filtered.append({"title": f"{title} - {salary}", "company": company, "location": job_loc, "link": f"/jobs/{title.lower().replace(' ','-')}", "salary": salary})
    random.shuffle(filtered)
    return filtered[:25] if filtered else SA_JOBS_DB[:15]

@app.route("/", methods=["GET","POST"])
def home():
    raw_q = (request.form.get("q","") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc = (request.form.get("loc","") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    qq = sanitize(raw_q, 40) or "Driver"
    loc_q = sanitize(raw_loc, 40) or "South Africa"
    jobs = get_jobs(qq, loc_q)
    # convert for template
    jobs_fmt = [{"title": j["title"] if isinstance(j, dict) else f"{j[0]} - {j[3]}",
                 "company": j["company"] if isinstance(j, dict) else j[1],
                 "location": j["location"] if isinstance(j, dict) else j[2],
                 "link": j["link"] if isinstance(j, dict) else "/"} for j in jobs]
    return render_template("index.html", jobs=jobs_fmt, qq=qq, loc=loc_q)

@app.route("/ads.txt")
def ads_txt(): return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0", 200, {'Content-Type':'text/plain'}

@app.route("/health")
def health(): return {"status":"ok", "jobs": len(SA_JOBS_DB), "siem": True}

@app.route("/cv")
def cv(): return render_template("cv.html")

@app.route("/post-job")
@app.route("/post_job")
@app.route("/post-a-job")
def post_job(): return render_template("post_job.html")

@app.route('/jobs/<slug>')
def high_cpc_job(slug):
    text = f"Find {slug.replace('-',' ')} in South Africa 2026 - R25k-R85k"
    return render_template('job_seo.html', slug=slug, content=text, title=slug.replace('-',' ').title())

@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")

@app.route('/employee')
def employee(): return render_template("employee.html")

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
