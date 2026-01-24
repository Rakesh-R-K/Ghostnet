import threading
import time
import os
import hashlib
import sys

# Add parent directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from server import ghostnet_server
from client import ghostnet_client

def calculate_checksum(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def run_server():
    print("[Test] Starting Server...")
    ghostnet_server.start_server()

def run_test():
    # Cleanup old files
    for f in os.listdir('.'):
        if f.startswith("received_") and f.endswith(".bin"):
            try:
                os.remove(f)
            except:
                pass

    # Create a dummy file
    test_file = "test_document.txt"
    with open(test_file, "w") as f:
        f.write("This is a secret document sent via GhostNet DNS Tunneling! " * 100)
    
    original_checksum = calculate_checksum(test_file)
    print(f"[Test] Original Checksum: {original_checksum}")

    # Start server in a thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(1)
    
    # Run client
    print("[Test] Starting Client...")
    ghostnet_client.send_file(test_file)
    
    # Wait for processing (in a real test we'd poll for file existence)
    time.sleep(2)
    
    # Check for received file
    # The server saves it as received_<session_id>.bin
    # We need to find the latest received file
    files = [f for f in os.listdir('.') if f.startswith("received_") and f.endswith(".bin")]
    if not files:
        print("[Test] FAILED: No file received.")
        return

    received_file = files[0] # Assuming only one for this test
    print(f"[Test] Checking file: {received_file}")
    
    received_checksum = calculate_checksum(received_file)
    print(f"[Test] Received Checksum: {received_checksum}")
    
    # Debug sizes
    orig_size = os.path.getsize(test_file)
    recv_size = os.path.getsize(received_file)
    print(f"[Test] Original Size: {orig_size}, Received Size: {recv_size}")
    
    # Debug content
    with open(test_file, 'rb') as f:
        print(f"[Test] Original Start: {f.read(50)}")
    with open(received_file, 'rb') as f:
        print(f"[Test] Received Start: {f.read(50)}")
    
    if original_checksum == received_checksum:
        print("[Test] SUCCESS: File transfer verified!")
    else:
        print("[Test] FAILED: Checksum mismatch.")

    # Cleanup
    # os.remove(test_file)
    # os.remove(received_file)

if __name__ == "__main__":
    # Override config for local testing if needed, but defaults are 127.0.0.1:53
    # Ensure we have permission to bind to port 53 or change it in config.json
    # For this test, we assume the user has rights or changed port to 5353 in config.
    run_test()
