import pytest
import threading
import time
import os
import zlib
from pathlib import Path

from server.ghostnet_server import GhostServer
from client.ghostnet_client import GhostClient
from common import config

@pytest.mark.parametrize("mode", ["A", "TXT", "RANDOM"])
def test_full_transfer_modes(tmp_path, mode):
    # Setup test config
    test_port = 5556 + (1 if mode == "TXT" else 2 if mode == "RANDOM" else 0)
    config._config_data['server_port'] = test_port
    config._config_data['server_ip'] = '127.0.0.1'
    config._config_data['chunk_size'] = 16
    
    # Initialize server
    server = GhostServer(reaper_interval=1, session_timeout=5)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    
    # Wait for server to bind
    time.sleep(1)
    
    # Create a test file
    test_file = tmp_path / f"secret_{mode}.txt"
    test_content = f"Secret message for mode {mode}!".encode() * 10
    test_file.write_bytes(test_content)
    
    # Initialize client and send file
    client = GhostClient()
    client.send_file(str(test_file), mode=mode)
    
    # Wait for reassembly
    time.sleep(3)
    
    # Success check
    found_file = None
    for file in os.listdir("."):
        if file.startswith("received_") and file.endswith(".bin"):
            found_file = file
            break
            
    assert found_file is not None, f"Reassembled file not found for mode {mode}"
    
    with open(found_file, "rb") as f:
        received_content = f.read()
        
    assert received_content == test_content
    
    # Cleanup
    os.remove(found_file)
    server._stop_reaper.set()
