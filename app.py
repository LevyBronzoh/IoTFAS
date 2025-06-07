from flask import Flask, render_template, abort
import json
import os
import re
from integrity import verify_data_integrity

app = Flask(__name__)

DEFAULT_OUTPUT_DIR = "output"

def get_latest_json_file():
    """Finds the newest JSON file with proper sorting by timestamp"""
    json_files = []
    for f in os.listdir(DEFAULT_OUTPUT_DIR):
        if f.endswith('_processed.json'):
            try:
                # Extract timestamp from filename
                timestamp = re.search(r'(\d{8}_\d{6})', f).group(1)
                json_files.append((f, timestamp))
            except:
                continue
    
    if not json_files:
        return None
        
    # Sort by timestamp (newest first)
    json_files.sort(key=lambda x: x[1], reverse=True)
    return json_files[0][0]  # Return filename of newest file

@app.route('/')
def display_data():
    try:
        # Get the latest JSON file
        latest_json = get_latest_json_file()
        if not latest_json:
            abort(404, description="No processed data found")
            
        print(f"Loading data from: {latest_json}")  # Debug
        
        data_file = os.path.join(DEFAULT_OUTPUT_DIR, latest_json)
        
        # Load JSON data
        with open(data_file, "r") as f:
            data = json.load(f)
            
        if not data:
            abort(404, description="No packet data found in file")
            
        # Get corresponding PCAP file
        base_name = latest_json.replace('_processed.json', '')
        pcap_file = os.path.join(DEFAULT_OUTPUT_DIR, f"{base_name}.pcap")
        
        # Calculate hashes
        pcap_hash = verify_data_integrity(pcap_file) if os.path.exists(pcap_file) else "PCAP file not found"
        json_hash = verify_data_integrity(data_file)
        
        return render_template(
            'index.html',
            data=data,
            pcap_hash=pcap_hash,
            json_hash=json_hash,
            pcap_filename=os.path.basename(pcap_file),
            json_filename=os.path.basename(data_file)
        )
        
    except Exception as e:
        abort(500, description=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)