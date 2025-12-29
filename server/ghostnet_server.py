import socket
import struct
import json
import os
import zlib
import sys
import logging
from collections import defaultdict

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common import encryption_utils, dns_utils
# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

CONFIG = load_config()
DOMAIN = CONFIG['domain']
SERVER_IP = CONFIG['server_ip']
PORT = CONFIG['server_port']
KEY = CONFIG['encryption_key'].encode() # In real usage, handle this securely

# Session storage: session_id -> {seq_num: data}
sessions = defaultdict(dict)
# Session metadata: session_id -> {'total_chunks': N, 'received_last': False}
session_meta = defaultdict(lambda: {'received_last': False, 'max_seq': -1})

def parse_dns_query(data):
    """
    Minimal DNS parser to extract QNAME.
    """
    # Header is 12 bytes
    header = data[:12]
    # ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    # We only care about the Question section which follows immediately
    
    # Parse QNAME
    idx = 12
    parts = []
    while True:
        length = data[idx]
        if length == 0:
            break
        idx += 1
        parts.append(data[idx:idx+length].decode('utf-8', errors='ignore'))
        idx += length
    
    qname = ".".join(parts)
    idx += 1 # Skip null byte
    
    # QTYPE (2 bytes) and QCLASS (2 bytes)
    qtype = struct.unpack(">H", data[idx:idx+2])[0]
    
    return header, qname, qtype

def build_dns_response(query_data, ip_address):
    """
    Minimal DNS response builder (A record).
    """
    # Transaction ID
    tid = query_data[:2]
    
    # Flags: QR=1, Opcode=0, AA=1, TC=0, RD=0, RA=0, Z=0, RCODE=0
    # 0x8400 (Standard Query Response, No Error)
    flags = b'\x81\x80' 
    
    # Counts: QD=1, AN=1, NS=0, AR=0
    counts = struct.pack(">HHHH", 1, 1, 0, 0)
    
    # Header
    header = tid + flags + counts
    
    # Question Section (copy from query)
    # Find end of question section
    idx = 12
    while query_data[idx] != 0:
        idx += query_data[idx] + 1
    idx += 1 + 4 # Null byte + QTYPE + QCLASS
    question = query_data[12:idx]
    
    # Answer Section
    # Name (pointer to question name at offset 12)
    name = b'\xc0\x0c'
    # Type (A = 1)
    rtype = struct.pack(">H", 1)
    # Class (IN = 1)
    rclass = struct.pack(">H", 1)
    # TTL (60 seconds)
    ttl = struct.pack(">I", 60)
    # RDLENGTH (4 bytes for IPv4)
    rdlength = struct.pack(">H", 4)
    # RDATA
    rdata = socket.inet_aton(ip_address)
    
    answer = name + rtype + rclass + ttl + rdlength + rdata
    
    return header + question + answer

def handle_chunk(session_id, seq_num, data, is_last):
    logging.debug(f"Session {session_id}: Received chunk {seq_num} (Last: {is_last})")
    
    sessions[session_id][seq_num] = data
    if is_last:
        session_meta[session_id]['received_last'] = True
        session_meta[session_id]['max_seq'] = seq_num

    # Check if we have all chunks
    meta = session_meta[session_id]
    if meta['received_last']:
        max_seq = meta['max_seq']
        current_chunks = sessions[session_id]
        if len(current_chunks) == max_seq + 1:
            logging.info(f"Session {session_id}: All chunks received. Reassembling...")
            reassemble_file(session_id)

def reassemble_file(session_id):
    chunks = sessions[session_id]
    sorted_seq = sorted(chunks.keys())
    full_data = b"".join([chunks[seq] for seq in sorted_seq])
    
    # Decrypt
    try:
        # We need to generate the key same way as client.
        # For POC, we use the hardcoded key from config.
        # In real app, key exchange or pre-shared key logic needed.
        # Here we assume the data sent was encrypted.
        
        # Wait, the client encrypts *before* chunking? Or chunks then encrypts?
        # The plan said: "Client: Reads file -> Compresses -> Encrypts -> Splits".
        # So we reassemble *encrypted* chunks, then decrypt the whole blob.
        
        decrypted_data = encryption_utils.decrypt_data(full_data, KEY)
        decompressed_data = zlib.decompress(decrypted_data)
        
        # Save to file
        output_filename = f"received_{session_id}.bin"
        with open(output_filename, "wb") as f:
            f.write(decompressed_data)
        
        logging.info(f"File saved: {output_filename}")
        
        # Cleanup
        del sessions[session_id]
        del session_meta[session_id]
        
    except Exception as e:
        logging.error(f"Decryption failed for session {session_id}: {e}")

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((SERVER_IP, PORT))
    except PermissionError:
        logging.error(f"Permission denied binding to port {PORT}. Try running as sudo/admin.")
        return

    logging.info(f"GhostNet Server listening on {SERVER_IP}:{PORT}")
    
    while True:
        try:
            data, addr = sock.recvfrom(512) # DNS packets usually < 512 bytes
            header, qname, qtype = parse_dns_query(data)
            
            if qtype != 1: # Only handle A records for now
                continue
                
            logging.debug(f"Query: {qname}")
            
            try:
                session_id, encoded_payload = dns_utils.parse_subdomain(qname, DOMAIN)
                payload = dns_utils.decode_chunk(encoded_payload)
                seq_num, chunk_data, is_last = dns_utils.parse_payload(payload)
                
                handle_chunk(session_id, seq_num, chunk_data, is_last)
                
                # Respond with A record (IP doesn't matter, just ACK)
                response = build_dns_response(data, "127.0.0.1")
                sock.sendto(response, addr)
                
            except ValueError as e:
                # Not a GhostNet query or malformed
                # logging.debug(f"Ignored query {qname}: {e}")
                pass
            except Exception as e:
                logging.error(f"Error processing query: {e}")

        except Exception as e:
            logging.error(f"Server error: {e}")

if __name__ == "__main__":
    start_server()
