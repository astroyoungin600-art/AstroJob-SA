from flask import Flask, request, render_template
import re, random, os
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "astro-job-sa-2026")

# Load SIEM - your siem.py is correct
try:
    from siem import siem_bp
    app.register_blueprint(siem_bp)
    print("✅ SIEM loaded")
except Exception as e:
    print(f"SIEM error {e}")

DB=[("Driver Code 14 - JHB R25k","Unitrans","Johannesburg"),("Cashier - Soweto R8.5k","Shoprite","Soweto"),("General Worker - CPT R7.5k","Woolworths","Cape Town"),("IT Support Remote R35k","BCX","Remote")]
def get_jobs(q,loc): 
    return [{"title":t,"company":c,"location":l,"link":f"/jobs/{t.lower().replace(' ','-')[:40]}"} for t,c,l in DB]

@app.route("/",methods=["GET","POST"])
def home():
    q = request.form.get("q","Driver") if request.method=="POST" else request.args.get("q","Driver")
    loc = request.form.get("loc","South Africa") if request.method=="POST" else request.args.get("loc","South Africa")
    return render_template("index.html",jobs=get_jobs(q,loc),qq=q,loc=loc)

@app.route("/ads.txt")
def ads_txt(): 
    return "google.com, pub-2133699761079270, DIRECT, f08c47fec0942fa0",200,{'Content-Type':'text/plain'}

@app.route("/cv")
def cv(): return render_template("cv.html")
@app.route("/post-job")
def post_job(): return render_template("post_job.html")
@app.route("/privacy")
def privacy(): return render_template("privacy.html")
@app.route("/health")
def health(): return {"status":"ok"}
