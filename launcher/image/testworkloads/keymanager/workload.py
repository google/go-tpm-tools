import base64
import json
import os
import re
import sys
import time
from urllib.parse import quote
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from pyhpke.consts import Mode
import requests
import requests_unixsocket
import jsonschema


session = requests_unixsocket.Session()
# Use the correct socket path for confidential space environment
socket_path = "/run/container_launcher/kmaserver.sock"
encoded_path = quote(socket_path, safe='')
base_url = f"http+unix://{encoded_path}"

# Define JSON Schemas for API responses
KEY_HANDLE_SCHEMA = {
    "type": "object",
    "properties": {
        "handle": {"type": "string"}
    },
    "required": ["handle"],
    "additionalProperties": False
}

ALGORITHM_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["kem"]},
        "params": {
            "type": "object",
            "properties": {
                "kem_id": {"type": "string"}
            },
            "required": ["kem_id"],
            "additionalProperties": False
        }
    },
    "required": ["type", "params"],
    "additionalProperties": False
}

PUB_KEY_SCHEMA = {
    "type": "object",
    "properties": {
        "algorithm": ALGORITHM_SCHEMA,
        "public_key": {"type": "string"}
    },
    "required": ["algorithm", "public_key"],
    "additionalProperties": False
}

KEY_INFO_SCHEMA = {
    "type": "object",
    "properties": {
        "key_handle": KEY_HANDLE_SCHEMA,
        "pub_key": PUB_KEY_SCHEMA,
        "key_protection_mechanism": {"type": "string"},
        "expiration_time": {"type": "integer"}
    },
    "required": ["key_handle", "pub_key", "key_protection_mechanism", "expiration_time"],
    "additionalProperties": False
}

GET_CAPABILITIES_SCHEMA = {
    "type": "object",
    "properties": {
        "supported_algorithms": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "algorithm": ALGORITHM_SCHEMA
                },
                "required": ["algorithm"],
                "additionalProperties": False
            }
        }
    },
    "required": ["supported_algorithms"],
    "additionalProperties": False
}

DECAPS_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "shared_secret": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string"},
                "secret": {"type": "string"}
            },
            "required": ["algorithm", "secret"],
            "additionalProperties": False
        }
    },
    "required": ["shared_secret"],
    "additionalProperties": False
}

ENUMERATE_KEYS_SCHEMA = {
    "type": "object",
    "properties": {
        "key_infos": {
            "type": "array",
            "items": KEY_INFO_SCHEMA
        }
    },
    "required": ["key_infos"],
    "additionalProperties": False
}

def destroy_key(key_handle):
  print(f"\n--- Destroying Key {key_handle['handle']} ---")
  payload = {"key_handle": key_handle}
  resp = session.post(f"{base_url}/v1/keys:destroy", json=payload)
  if resp.status_code not in (200, 204):
    print(f"Error: {resp.status_code} - {resp.text}")
  resp.raise_for_status()
  # Destroy has no response body to validate
  print("Key destroyed successfully.")


def generate_key():
  print("\n--- Generating Key ---")
  payload = {
      "algorithm": {
          "type": "kem",
          "params": {
              "kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"
          }
      },
      "lifespan": 3600,
  }
  resp = session.post(f"{base_url}/v1/keys:generate_key", json=payload)
  if resp.status_code != 200:
    print(f"Error: {resp.status_code} - {resp.text}")
  resp.raise_for_status()
  data = resp.json()
  jsonschema.validate(instance=data, schema=KEY_INFO_SCHEMA)
  key_handle = data["key_handle"]
  print(f"Generated Key: {key_handle['handle']}")
  return key_handle


def get_capabilities():
  print("\n--- Getting Capabilities ---")
  resp = session.get(f"{base_url}/v1/capabilities")
  if resp.status_code != 200:
    print(f"Error: {resp.status_code} - {resp.text}")
  resp.raise_for_status()
  caps = resp.json()
  jsonschema.validate(instance=caps, schema=GET_CAPABILITIES_SCHEMA)
    
  print(f"Capabilities:\n{json.dumps(caps, indent=2)}")
  return caps


def do_encap(pub_key_b64):
  print("\n--- Performing HPKE Encapsulation ---")
  pub_key_bytes = base64.b64decode(pub_key_b64)
  suite = CipherSuite.new(
      KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
  )
  kem_pub_key = suite.kem.deserialize_public_key(pub_key_bytes)
  # Match the Go test behavior by passing empty info for encap
  enc, sender_context = suite.create_sender_context(kem_pub_key, b"")

  # Let's encrypt a dummy plaintext
  plaintext = b"authentic-secret-32-bytes-value!"  # 32 bytes
  print(f"Encrypting plaintext payload: '{plaintext.decode('utf-8')}'")
  ciphertext = sender_context.seal(plaintext)

  # We only send `enc` (encapsulated key) to the `decap` endpoint.
  # We return `ciphertext` and `plaintext` so we can verify them after Decap.
  return enc, ciphertext, plaintext


def decap_key(key_handle, enc_bytes):
  print(f"\n--- Decapping Key {key_handle['handle']} ---")
  enc_b64 = base64.b64encode(enc_bytes).decode("utf-8")
  payload = {
      "key_handle": key_handle,
      "ciphertext": {
          "algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256",
          "ciphertext": enc_b64,
      },
  }
  resp = session.post(f"{base_url}/v1/keys:decap", json=payload)
  if resp.status_code != 200:
    print(f"Error: {resp.status_code} - {resp.text}")
  resp.raise_for_status()
  data = resp.json()
  jsonschema.validate(instance=data, schema=DECAPS_RESPONSE_SCHEMA)
  
  decap = data["shared_secret"]
  print(f"Decapped shared secret:\n{json.dumps(decap, indent=2)}")
  return base64.b64decode(decap["secret"])


def verify_payload(shared_secret_bytes, ciphertext, expected_plaintext):
  print("\n--- Verifying Decapped Payload ---")
  suite = CipherSuite.new(
      KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
  )
  print("Initializing HPKE receiver context from the decapped shared secret...")
  # We construct the receiver context directly from the KEM shared secret
  # since we simulate the receiver unsealing the AEAD ciphertext.
  recipient_context = suite._key_schedule_r(Mode.BASE, shared_secret_bytes, b"", b"", b"")

  print("Opening the ciphertext locally using the returned shared secret...")
  decrypted = recipient_context.open(ciphertext)
  print(f"Decrypted payload: '{decrypted.decode('utf-8')}'")

  if decrypted == expected_plaintext:
    print("SUCCESS: The decrypted payload matches the originally sent payload!")
  else:
    print("ERROR: Payload mismatch!")
    raise ValueError("Payload mismatch")


def enumerate_keys():
  print("\n--- Enumerating Keys ---")
  resp = session.get(f"{base_url}/v1/keys")
  if resp.status_code != 200:
    print(f"Error: {resp.status_code} - {resp.text}")
  resp.raise_for_status()
  data = resp.json()
  jsonschema.validate(instance=data, schema=ENUMERATE_KEYS_SCHEMA)
    
  keys = data["key_infos"]
  print(f"Enumerated Keys:\n{json.dumps(keys, indent=2)}")
  return keys


if __name__ == "__main__":
  # Retry loop waiting for socket to exist since order of startup isn't guaranteed
  max_retries = 30
  retry_interval = 2
  socket_ready = False
  for i in range(max_retries):
    if os.path.exists(socket_path):
      socket_ready = True
      print(f"Socket {socket_path} found after {i*retry_interval} seconds")
      break
    print(f"Waiting for socket {socket_path}... (attempt {i+1}/{max_retries})")
    time.sleep(retry_interval)
    
  if not socket_ready:
    print(f"ERROR: timed out waiting for socket {socket_path}")
    exit(1)

  try:
    get_capabilities()
    handle = generate_key()
    
    # Use enumerate to fetch the public key using the handle we just generated
    keys = enumerate_keys()
    if not keys:
      raise ValueError("No keys returned by enumerate")
    
    # Verify that the key we generated in the generate_key step is included in the enumerated list
    pub_key_b64 = None
    for k in keys:
      if k["key_handle"]["handle"] == handle["handle"]:
        pub_key_b64 = k["pub_key"]["public_key"]
        break

    if pub_key_b64 is None:
      raise ValueError(f"Could not find generated key {handle['handle']} in enumerated keys!")
    
    enc_bytes, ciphertext, plaintext = do_encap(pub_key_b64)
    shared_secret_bytes = decap_key(handle, enc_bytes)
    verify_payload(shared_secret_bytes, ciphertext, plaintext)

    # Destroy the key and check if it's successfully removed
    destroy_key(handle)
    keys_after_destroy = enumerate_keys()
    for k in keys_after_destroy:
      if k["key_handle"]["handle"] == handle["handle"]:
        raise ValueError(f"Key {handle['handle']} was not destroyed from the list!")

    print("\nSuccess! Flow completed.")
  except Exception as e:
    print(f"An error occurred: {e}")
    exit(1)
