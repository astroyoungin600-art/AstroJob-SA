from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

def is_traversal_attack(s): return ".." in s or "//" in s
def sanitize(s,n): return re.sub(r'[^a-zA-Z0-9 \-]', '', s)[:n]

def get_jobs(q, loc):
    try:
        url = f"https://za.jooble.org/jobs-{q}/{loc}" if loc.lower()!="south africa" else f"https://za.jooble.org/jobs-{q}"
        r = requests.get(url, timeout=5, headers={"User-Agent":"Mozilla/5.0"})
        soup = BeautifulSoup(r.text, 'html.parser')
        jobs = []
        for a in soup.select("a")[:20]:
            t = a.get_text().strip()
            if len(t)>15 and "job" in t.lower() or len(t)>10:
                jobs.append({"title": t, "company": "Astro Job SA", "location": loc, "link": a.get('href','/')})
        if not jobs:
            jobs = [{"title": f"{q} - {loc} - Hiring Now", "company": "Top Employer", "location": loc, "link": "/"} for _ in range(5)]
        return jobs
    except:
        return [{"title": f"{q} Jobs in {loc}", "company": "Astro Job SA", "location": loc, "link": "/"}]

@app.route("/", methods=["GET","POST"])
def home():
    raw_q=(request.form.get("q","Driver") if request.method=="POST" else request.args.get("q","Driver")).strip()
    raw_loc=(request.form.get("loc","South Africa") if request.method=="POST" else request.args.get("loc","South Africa")).strip()
    if is_traversal_attack(raw_q) or is_traversal_attack(raw_loc): return "403 Blocked",403
    qq=sanitize(raw_q,40) or "Driver"
    loc_q=sanitize(raw_loc,40) or "South Africa"
    jobs=get_jobs(qq,loc_q)
    return render_template("index.html",jobs=jobs,qq=qq,loc=loc_q)

@app.route("/ads.txt")
def ads_txt():
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/cv")
def cv():
    return render_template("cv.html")

@app.route("/post-job")
@app.route("/post_job")
@app.route("/post-a-job")
def post_job():
    return render_template("post_job.html")

@app.route('/jobs/<slug>')
def high_cpc_job(slug):
    text = f"Find {slug.replace('-',' ')} in South Africa 2026 - R25k-R85k"
    return render_template('job_seo.html', slug=slug, content=text, title=slug.replace('-',' ').title())

@app.route('/privacy')
def privacy_page():
    return render_template("privacy.html")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=8080,debug=False)
