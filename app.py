from flask import Flask, request, render_template
from datetime import timedelta
import re, random, os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "astro-job-sa-2026-Mthembisi-0812602918-fixed-key-7day")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
    print("✅ SIEM loaded")
except Exception as e:
    print(f"SIEM error {e}")

DB=[("Driver Code 14 - JHB R25k","Unitrans","Johannesburg"),("Driver Code 10 - Durban R14k","Famous Brands","Durban"),("Code 14 + PDP - Gauteng R16k","Shoprite","Gauteng"),("Truck Driver - Cape Town R22k","Logistics SA","Cape Town"),("Delivery Driver - Soweto R12k","Takealot","Soweto"),("Cashier - Soweto R8.5k","Shoprite","Soweto"),("Shop Assistant - Pretoria R9k","Clicks","Pretoria"),("General Worker - CPT R7.5k","Woolworths","Cape Town"),("Retail Assistant - JHB R8k","Pick n Pay","Johannesburg"),("Nursing Assistant - Gauteng R18k","Life Hospital","Gauteng"),("Enrolled Nurse - JHB R28k","Netcare","Johannesburg"),("Data Entry Remote R12k","Remote Co","Remote"),("IT Support Remote R35k","BCX","Remote"),("Software Dev - CPT R65k","Takealot","Cape Town"),("Call Centre - Centurion R11k","Telkom","Centurion"),("Security Guard - JHB R9k","Fidelity","Johannesburg"),("Cleaner - Soweto Schools R6.5k","Dept Education","Soweto"),("Waiter - Sandton R7k+Tips","Restaurant","Sandton"),("Admin Clerk - Pretoria R15k","SASSA","Pretoria"),("Learnership - Mr Price","Mr Price","Durban")]

def sanitize(s,n): return re.sub(r'[^a-zA-Z0-9 \-]', '', s)[:n] if s else ""

def get_jobs(q,loc):
    ql,locl=q.lower(),loc.lower()
    res=[]
    for t,c,l in DB:
        if ql in t.lower() or (ql=="driver" and "driver" in t.lower()) or ql in ["all","","jobs"]:
            if locl in ["south africa","sa","all",""] or locl in l.lower() or l.lower() in locl or ("gauteng" in locl and l in ["Johannesburg","Soweto","Pretoria","Gauteng"]):
                res.append({"title":t,"company":c,"location":l,"link":f"/jobs/{t.lower().replace(' ','-')[:40]}"})
    while len(res)<18:
        for t,c,l in DB:
            if not any(r["title"]==t for r in res): res.append({"title":t,"company":c,"location":l,"link":f"/jobs/{t.lower().replace(' ','-')[:40]}"})
            if len(res)>=18: break
    random.shuffle(res)
    return res[:18]

@app.route("/",methods=["GET","POST"])
def home():
    qq=sanitize((request.form.get("q","") if request.method=="POST" else request.args.get("q","Driver")).strip(),40) or "Driver"
    loc=sanitize((request.form.get("loc","") if request.method=="POST" else request.args.get("loc","South Africa")).strip(),40) or "South Africa"
    return render_template("index.html",jobs=get_jobs(qq,loc),qq=qq,loc=loc)

@app.route("/ads.txt")
def ads_txt(): return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}

@app.route("/health")
def health(): return {"status":"ok","jobs":len(DB),"siem":"7day"}

@app.route("/cv")
def cv(): return render_template("cv.html")

@app.route("/post-job")
def post_job(): return render_template("post_job.html")

@app.route('/jobs/<slug>')
def job_slug(slug): return render_template('job_seo.html',slug=slug,content=f"{slug} - SA 2026",title=slug.title())

@app.route('/privacy')
def privacy_page(): return render_template("privacy.html")
