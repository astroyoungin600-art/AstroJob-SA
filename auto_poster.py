import os, requests, threading, time
from datetime import datetime

def fetch_and_prepare():
    ID=os.environ.get("ADZUNA_ID"); KEY=os.environ.get("ADZUNA_KEY")
    if not ID or not KEY:
        print("ADZUNA keys missing")
        return []
    try:
        url=f"https://api.adzuna.com/v1/api/jobs/za/search/1?app_id={ID}&app_key={KEY}&results_per_page=10&what=General worker&where=South Africa&sort_by=date"
        r=requests.get(url, timeout=15).json()
        jobs=r.get('results',[])[:5]
        out=[]
        for j in jobs:
            text=f"🚀 *{j.get('title','')}*\n📍 {j.get('location',{}).get('display_name','SA')} | 🏢 {j.get('company',{}).get('display_name','')}\n\n🔗 {j.get('redirect_url','')}\n\nWe do not need your details this is a Non Profit Program.WE DO NOT CHARGE MONEY, fully POPIA compliance\n\nAstro Job SA - Made by Mthembisi"
            out.append(text)
        # save to file that bot-preview reads
        with open("channel_queue.txt","w") as f:
            f.write("\n\n---NEXT JOB---\n\n".join(out))
        print(f"[{datetime.now()}] AutoBot prepared {len(out)} jobs for channel")
        return out
    except Exception as e:
        print(f"AutoBot error: {e}")
        return []

def start_scheduler():
    def loop():
        while True:
            fetch_and_prepare()
            time.sleep(4*3600) # every 4 hours
    t=threading.Thread(target=loop, daemon=True)
    t.start()

