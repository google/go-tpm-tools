import requests
import requests_unixsocket
import json
import base64
from urllib.parse import quote

# Configure the session to use the UDS adapter
session = requests_unixsocket.Session()

# Define the socket path
# Note: requests_unixsocket requires URL-encoding the path slashes
# The KMS and AS are mounted at /run/container_launcher in the workload VM.
kms_socket_path = "/run/container_launcher/kmaserver.sock"
kms_encoded_path = quote(kms_socket_path, safe='')
kms_base_url = f"http+unix://{kms_encoded_path}"
as_socket_path = "/run/container_launcher/teeserver.sock"
as_encoded_path = quote(as_socket_path, safe='')
as_base_url = f"http+unix://{as_encoded_path}"

def get_capabilities():
    """Check supported algorithms."""
    resp = session.get(f"{kms_base_url}/v1/capabilities")
    resp.raise_for_status()
    print("Capabilities:", json.dumps(resp.json(), indent=2))

def generate_key():
    """Generate a new KEM key."""
    payload = {
        "algorithm": {
            "type": "kem",
            "params": {
                "kem_id": "DHKEM_X25519_HKDF_SHA256",
                }
            },
            "lifespan": 3600
    }
    resp = session.post(f"{kms_base_url}/v1/keys:generate_key", json=payload)
    resp.raise_for_status()
    key_handle = resp.json()["key_handle"]
    print(f"Generated Key: {key_handle['handle']}")
    return key_handle

def get_key_endorsement(challenge, key_handle):
    """Generates a fresh key endorsement."""
    challange_base64 = base64.b64encode(challenge).decode('utf-8')
    payload = {
        "challenge": challange_base64,
        "key_handle": key_handle
    }
    resp = session.post(f"{as_base_url}/v1/keys:getEndorsement", json=payload)
    print(f"resp: {resp}")
    resp.raise_for_status()
    return resp.json()


def decapsulate_secret(key_handle, encapsulated_key):
    """Simulate decapsulation."""
    # In a real scenario, 'encapsulated_key' is the result of a DHKEM
    # encapsulation operation against the KPS public key, typically
    # received from the trusted proxy.
    
    encoded_encap_key = base64.b64encode(encapsulated_key).decode('utf-8')
    
    payload = {
        "key_handle": key_handle,
        "ciphertext": {
            "algorithm": "DHKEM_X25519_HKDF_SHA256",
            "ciphertext": encoded_encap_key
        }
    }
    
    resp = session.post(f"{kms_base_url}/v1/keys:decap", json=payload)
    resp.raise_for_status()
    
    secret_b64 = resp.json()["shared_secret"]["secret"]
    secret = base64.b64decode(secret_b64)
    print(f"Decapsulated Secret (hex): {secret.hex()}")

def destroy_key(key_handle):
    """Cleanup the key."""
    payload = {"key_handle": key_handle}
    resp = session.post(f"{kms_base_url}/v1/keys:destroy", json=payload)
    resp.raise_for_status()
    print(f"Key {key_handle['handle']} destroyed successfully.")

if __name__ == "__main__":
    try:
        print("--- 1. Checking Capabilities ---")
        get_capabilities()
        print("\n--- 2. Generating Key ---")
        handle = generate_key()
        # Simulate some encapsulated key (32 bytes for X25519)
        dummy_ciphertext = b'\x00' * 32
        print("\n--- 3. Generating Key Endorsement ---")
        challenge = b'\x00' * 32 

        print(get_key_endorsement(challenge, handle))
        print("\n--- 4. Decapsulating ---")
        decapsulate_secret(handle, dummy_ciphertext.decode('utf-8'))
        print("\n--- 5. Destroying Key ---")
        destroy_key(handle)

    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to socket at {kms_socket_path}.")
        print("Ensure the Workload Services Daemon is running.")
    except Exception as e:
        print(f"An error occurred: {e}")
