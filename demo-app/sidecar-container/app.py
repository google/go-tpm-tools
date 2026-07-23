import os
import sys
import requests
from flask import Flask, request, render_template_string, Response

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure TEE Communication Demo</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #ffffff; text-align: center; padding: 40px; }
        .container { max-width: 600px; margin: 0 auto; background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        input[type="text"] { padding: 12px; width: 60%; border-radius: 6px; border: 1px solid #555; background: #333; color: white; font-size: 16px; margin-right: 10px; }
        button { padding: 12px 24px; border: none; border-radius: 6px; background-color: #bb86fc; color: #000; font-weight: bold; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #9965f4; }
        #viewer { margin-top: 30px; min-height: 100px; padding: 20px; background: #2c2c2c; border-radius: 8px; font-size: 24px; font-weight: bold; color: #03dac6; }
    </style>
</head>
<body>
    <div class="container">
        <h2>TLS Terminating Sidecar Demo</h2>
        <p>Enter your name below. This Sidecar will decrypt your HTTPS request, forward it to the Main Container securely over HTTP, and return the greeting!</p>
        
        <input type="text" id="nameInput" placeholder="Enter your name..." />
        <button onclick="sendName()">Send Securely</button>
        
        <div id="viewer">
            <p style="color: #888; font-size: 16px;">Response will appear here...</p>
        </div>
    </div>
    
    <script>
        function sendName() {
            const name = document.getElementById('nameInput').value;
            if (!name) return;
            
            document.getElementById('viewer').innerHTML = '<span style="color: #888; font-size: 16px;">Sending...</span>';
            
            fetch(`/proxy/hello?name=${encodeURIComponent(name)}`)
            .then(res => res.text())
            .then(text => {
                document.getElementById('viewer').innerHTML = text;
            })
            .catch(err => {
                document.getElementById('viewer').innerHTML = `<span style="color: red; font-size: 16px;">Error: ${err}</span>`;
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/proxy/hello')
def proxy_hello():
    name = request.args.get('name', 'Guest')
    
    # 1. Log that Sidecar received the encrypted request
    print(f"\n[SIDECAR] 🛡️ Received encrypted HTTPS request from user for name: '{name}'")
    print(f"[SIDECAR] 🔓 Decrypted request. Forwarding as plaintext HTTP to main container...")
    sys.stdout.flush()
    
    # 2. Forward to Main Container
    url = f"http://localhost:80/hello?name={name}"
    try:
        resp = requests.get(url)
        
        # 3. Log that Sidecar received the response from Main Container
        print(f"[SIDECAR] 📥 Received plaintext HTTP response from main container: '{resp.text}'")
        print(f"[SIDECAR] 🔐 Encrypting response and sending back to user over HTTPS.\n")
        sys.stdout.flush()
        
        return Response(resp.content, content_type=resp.headers.get('Content-Type'))
        
    except Exception as e:
        print(f"[SIDECAR] ❌ Failed to reach Main Container: {e}\n")
        sys.stdout.flush()
        return f"Failed to reach Main Container: {e}", 502

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('/app/cert.pem', '/app/key.pem'))
