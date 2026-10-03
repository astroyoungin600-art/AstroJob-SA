from flask import Blueprint, jsonify, render_template
import random
siem_bp = Blueprint('siem', __name__)
ATTACKS = [
    {"ip": "41.13.45.2", "lat": -26.2041, "lng": 28.0473, "city": "Johannesburg", "type": "Brute-force"},
    {"ip": "102.67.12.5", "lat": 40.7128, "lng": -74.006, "city": "New York", "type": "SQLi"},
    {"ip": "197.210.54.8", "lat": 51.5074, "lng": -0.1278, "city": "London", "type": "XSS"},
]
@siem_bp.route('/api/threats')
def threats():
    return jsonify(ATTACKS)
@siem_bp.route('/siem')
def dashboard():
    return render_template('siem_globe.html')
