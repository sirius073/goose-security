#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string
import json
import os

app = Flask(__name__)
LOG_FILE = "metrics/hacker_log.json"

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Adversary Vision - Live Feed</title>
    <style>
        body { 
            background-color: #0d1117; 
            color: #c9d1d9; 
            font-family: 'Courier New', Courier, monospace; 
            padding: 30px; 
            margin: 0;
        }
        h1 { 
            color: #ff7b72; 
            border-bottom: 2px solid #30363d; 
            padding-bottom: 15px; 
            margin-top: 0;
            font-size: 2em;
            text-shadow: 0 0 5px rgba(255, 123, 114, 0.4);
        }
        .header-sub { color: #8b949e; margin-bottom: 30px; }
        .log-container { 
            background-color: #161b22; 
            border: 1px solid #30363d; 
            border-radius: 8px; 
            padding: 20px; 
            height: 65vh; 
            overflow-y: auto; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .log-entry { 
            margin-bottom: 12px; 
            padding: 12px 15px; 
            border-left: 5px solid #8b949e; 
            background-color: #0d1117;
            border-radius: 0 4px 4px 0;
            animation: fadeIn 0.3s ease-in-out;
        }
        .time { color: #8b949e; font-size: 0.9em; font-weight: bold; }
        .title { font-weight: bold; margin-left: 10px; font-size: 1.1em; }
        .detail { margin-top: 8px; margin-left: 0; color: #a5d6ff; word-wrap: break-word; }
        
        /* Status Colors */
        .status-danger { border-left-color: #f85149; }
        .status-danger .title { color: #f85149; }
        .status-success { border-left-color: #2ea043; }
        .status-success .title { color: #2ea043; }
        .status-warning { border-left-color: #d29922; }
        .status-warning .title { color: #d29922; }
        .status-info { border-left-color: #58a6ff; }
        .status-info .title { color: #58a6ff; }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateX(-10px); }
            to { opacity: 1; transform: translateX(0); }
        }
    </style>
</head>
<body>
    <h1>[!] ADVERSARY TERMINAL</h1>
    <div class="header-sub">Listening for IEC-61850 GOOSE traffic on <strong>h3-eth0</strong>...</div>
    
    <div class="log-container" id="logBox">
        <p style="color: #8b949e;">Waiting for network traffic...</p>
    </div>

    <script>
        let previousLogCount = 0;

        setInterval(() => {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const logBox = document.getElementById('logBox');
                    
                    // Only update the DOM if we have new logs
                    if (data.length > previousLogCount) {
                        if (previousLogCount === 0) logBox.innerHTML = ''; 
                        
                        // Append only the new entries
                        for (let i = previousLogCount; i < data.length; i++) {
                            const item = data[i];
                            const entry = document.createElement('div');
                            entry.className = `log-entry status-${item.status}`;
                            entry.innerHTML = `
                                <div><span class="time">[${item.time}]</span> <span class="title">${item.title}</span></div>
                                <div class="detail">> ${item.detail}</div>
                            `;
                            logBox.appendChild(entry);
                        }
                        
                        // Auto-scroll to the newest entry at the bottom
                        logBox.scrollTop = logBox.scrollHeight;
                        previousLogCount = data.length;
                    }
                })
                .catch(err => console.error("Error fetching logs:", err));
        }, 800); // Polls every 800ms for that snappy real-time feel
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/api/logs')
def get_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])
    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
            return jsonify(data)
    except Exception:
        return jsonify([])

if __name__ == '__main__':
    print("[*] ==============================================")
    print("[*] HACKER DASHBOARD ONLINE")
    print("[*] Open your browser to: http://127.0.0.1:5001")
    print("[*] ==============================================")
    app.run(host='0.0.0.0', port=5001, debug=False)
