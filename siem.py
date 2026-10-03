from flask import Blueprint, jsonify
from collections import Counter
import random

siem_bp = Blueprint('siem', __name__)

# Mock attacks - real version reads request logs
ATTACKS = [
    {"ip": "41.13.45.2", "lat": -26.2041, "lng": 28.0473, "city": "Johannesburg", "type": "Brute-force"},
    {"ip": "41.28.90.12", "lat": -33.9249, "lng": 18.4241, "city": "Cape Town", "type": "Bot scrape"},
    {"ip": "102.67.12.5", "lat": 40.7128, "lng": -74.0060, "city": "New York", "type": "SQLi attempt"},
    {"ip": "197.210.54.8", "lat": 51.5074, "lng": -0.1278, "city": "London", "type": "XSS probe"},
]

@siem_bp.route('/api/threats')
def threats():
    # add random jitter so globe animates
    for a in ATTACKS:
        a['lat'] += random.uniform(-0.1, 0.1)
    return jsonify(ATTACKS)

@siem_bp.route('/siem')
def dashboard():
    return open('templates/siem_globe.html').read()
