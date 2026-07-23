import os
import sys
from flask import Flask, request

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # Print exactly what the user wants to see in the logs
    print(f"\n[MAIN CONTAINER] ⭐ Received plaintext HTTP request from sidecar for name: '{name}'")
    print(f"[MAIN CONTAINER] 🔒 Processing business logic securely inside TEE...")
    
    import random
    greetings = [
        f"Hello {name}!",
        f"It's a pleasure to meet you, {name}.",
        f"Welcome to the Confidential Space, {name}!"
    ]
    response = random.choice(greetings)
    
    print(f"[MAIN CONTAINER] 📤 Sending response: '{response}' back to sidecar.\n")
    sys.stdout.flush() # Ensure logs show up immediately in serial console
    
    return response

if __name__ == '__main__':
    # Listen on port 80 (plaintext HTTP)
    app.run(host='0.0.0.0', port=80)
