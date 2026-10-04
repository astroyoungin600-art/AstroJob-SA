import os, glob

banner = '''
<!-- Jobsa Channel -->
<div style="background:#25D366;color:white;text-align:center;padding:12px;font-family:Arial;position:relative;z-index:9999">
  🔥 <b>500+ Jobs Daily on WhatsApp</b>
  <a href="https://whatsapp.com/channel/0029VbDh9dGK5cDEn5Epcw0F" 
     style="background:white;color:#25D366;padding:6px 14px;border-radius:20px;text-decoration:none;font-weight:bold;margin-left:8px;display:inline-block">
     📲 Follow Jobsa🇿🇦
  </a>
</div>
'''

float_btn = '''
<a href="https://whatsapp.com/channel/0029VbDh9dGK5cDEn5Epcw0F"
   style="position:fixed;bottom:20px;right:20px;background:#25D366;color:white;width:60px;height:60px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;text-decoration:none;z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,0.3)">💬</a>
</body>'''

for f in glob.glob("templates/*.html"):
    with open(f, "r", encoding="utf-8", errors="ignore") as fh:
        content = fh.read()
    
    if "whatsapp.com/channel/0029VbDh9dGK5cDEn5Epcw0F" in content:
        print(f"Skip {f} - already has")
        continue

    # Add banner after <body>
    if "<body>" in content:
        content = content.replace("<body>", "<body>\n" + banner, 1)
    elif "<body " in content:
        # handle <body class=...>
        import re
        content = re.sub(r"<body[^>]*>", lambda m: m.group(0) + "\n" + banner, content, count=1)
    
    # Add floating button before </body>
    if "</body>" in content:
        content = content.replace("</body>", float_btn)
    else:
        content += float_btn

    with open(f, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"✅ Added to {f}")

print("DONE - All pages have Jobsa Channel")
