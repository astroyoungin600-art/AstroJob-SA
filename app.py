from flask import Flask, request, render_template, jsonify
import requests
from bs4 import BeautifulSoup
import re, random, os

app = Flask(__name__)

SA_JOBS_DB = [
    ("Driver Code 14 - JHB", "Unitrans", "Johannesburg", "R18k-R25k", "Driver"),
    ("Driver Code 10 - Durban", "Famous Brands", "Durban", "R14k", "Driver"),
    ("Cashier - Soweto", "Shoprite", "Soweto", "R8.5k", "Retail"),
    ("Shop Assistant - Pretoria", "Clicks", "Pretoria", "R9k", "Retail"),
    ("General Worker - Cape Town", "Woolworths", "Cape Town", "R7.5k", "General"),
    ("Nursing Assistant - Gauteng", "Life Hospital", "Gauteng", "R18k", "Nursing"),
    ("Enrolled Nurse - JHB", "Netcare", "Johannesburg", "R28k", "Nursing"),
    ("Data Entry Remote - SA", "Remote Co", "Remote", "R12k-R15k", "Data Entry"),
    ("IT Support - Remote", "BCX", "Remote", "R35k", "IT"),
    ("Software Developer", "Takealot", "Cape Town", "R65k", "Software"),
    ("Call Centre Agent", "Telkom", "Centurion", "R11k", "Call Centre"),
    ("Security Guard - JHB", "Fidelity", "Johannesburg", "R9k", "Security"),
    ("Cleaner - Schools", "Dept Education", "Soweto", "R6.5k", "Cleaning"),
    ("Waiter - Sandton", "Restaurant Group", "Sandton", "R7k+Tips", "Hospitality"),
    ("Admin Clerk - Govt", "SASSA", "Pretoria", "R15k", "Admin"),
]

def sanitize(s,n): return re.sub(r'[^a-zA-Z0-9 \-]', '', s)[:n] if s else ""

def get_jobs(q, loc):
    q = q.lower()
    loc = loc.lower()
    filtered = []
    for title, company, job_loc, salary, cat in SA_JOBS_DB:
        if q in title.lower() or q in cat.lower() or q == "driver" and "driver" in title.lower():
            if loc in job_loc.lower() or loc in ["south africa", "sa", "all"] or "remote" in loc:
                filtered.append({"title": f"{title} - {salary}", "company": company, "location": job_loc, "link": f"/jobs/{title.lower().replace(' ','-')}", "salary": salary})
            elif loc in ["gauteng", "johannesburg", "soweto", "pretoria"] and job_loc.lower() in ["johannesburg", "soweto", "pretoria", "gauteng", "sandton", "centurion"]:
                filtered.append({"title": f"{title} - {salary}", "company": company, "location": job_loc, "link": f"/jobs/{title.lower().replace(' ','-')}", "salary": salary})
    
    # If no match, show all shuffled
    if not filtered:
        random.shuffle(SA_JOBS_DB)
        for title, company, job_loc, salary, cat in SA_JOBS_DB[:10]:
            filtered.append({"title": f"{title} - {salary}", "company": company, "location": job_loc, "link": f"/jobs/{title.lower().replace(' ','-')}", "salary": salary})
    
    # Try live fetch as bonus (won't fail site if blocked)
    try:
        url = f"https://za.indeed.com/jobs?q={q}&l={loc}"
        r = requests.get(url, timeout=4, headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code == 200 and len(r.text) > 5000:
            soup = BeautifulSoup(r.text, 'html.parser')
            for el in soup.select("[data-jk] h2 a")[:5]:
                t = el.get_text().strip()
                if len(t) > 10:
                    filtered.insert(0, {"title": t, "company": "Indeed SA", "location": loc.title(), "link": "https://za.indeed.com" + el.get('href',''), "salary": "Apply"})
    except: pass
    
    return filtered[:20]

# Siem Globe - restore
@app.route("/siem")
@app.route("/siem-globe")
def siem_globe():
    return render_template("siem_globe.html")

@app.route("/api/siem-jobs")
def siem_api():
    # Siem endpoint for globe
    jobs = get_jobs("all", "South Africa")
    data = [{"lat": -26.2041 + random.uniform(-3,3), "lng": 28.0473 + random.uniform(-3,3), "title": j["title"]} for j in jobs[:30]]
    return jsonify(data)

@app.route("/", methods=["GET","POST"])
def home():
    raw_q = (request.form.get("q","") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc = (request.form.get("loc","") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    qq = sanitize(raw_q, 40) or "Driver"
    loc_q = sanitize(raw_loc, 40) or "South Africa"
    jobs = get_jobs(qq, loc_q)
    return render_template("index.html", jobs=jobs, qq=qq, loc=loc_q)

@app.route("/ads.txt")
def ads_txt():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0", 200, {'Content-Type':'text/plain'}

@app.route("/health")
def health(): return {"status":"ok", "jobs": len(SA_JOBS_DB)}

@app.route("/cv")
def cv(): return render_template("cv.html")

@app.route("/post-job")
@app.route("/post_job")
@app.route("/post-a-job")
def post_job(): return render_template("post_job.html")

@app.route('/jobs/<slug>')
def high_cpc_job(slug):
    text = f"Find {slug.replace('-',' ')} in South Africa 2026 - R25k-R85k - Apply via WhatsApp Channel Jobsa"
    return render_template('job_seo.html', slug=slug, content=text, title=slug.replace('-',' ').title())

@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")

@app.route('/employee')
def employee(): return render_template("employee.html")

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
