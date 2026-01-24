import base64
import struct
import math
from typing import List, Tuple

# Constants
MAX_LABEL_LENGTH = 63
# DNS Record Types
QTYPE_A = 1
QTYPE_TXT = 16

# Struct format: Flags (1 byte) + SeqNum (4 bytes) + Data (variable)
# Flags: 0x01 = Last Chunk
HEADER_FORMAT = ">BI" 
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def encode_chunk(data: bytes) -> str:
    """
    Encodes bytes to Base32 string, removing padding for DNS compatibility.
    """
    return base64.b32encode(data).decode('utf-8').rstrip('=')

def decode_chunk(encoded_str: str) -> bytes:
    """
    Decodes Base32 string, adding necessary padding.
    """
    padding = len(encoded_str) % 8
    if padding:
        encoded_str += '=' * (8 - padding)
    return base64.b32decode(encoded_str.upper())

def prepare_chunks(data: bytes, chunk_size: int) -> List[Tuple[int, bytes, bool]]:
    """
    Splits data into chunks.
    Returns a list of (seq_num, chunk_data, is_last).
    """
    chunks = []
    total_len = len(data)
    num_chunks = math.ceil(total_len / chunk_size)
    
    for i in range(num_chunks):
        start = i * chunk_size
        end = start + chunk_size
        chunk_data = data[start:end]
        is_last = (i == num_chunks - 1)
        chunks.append((i, chunk_data, is_last))
        
    return chunks

def build_payload(seq_num: int, data: bytes, is_last: bool) -> bytes:
    """
    Packs metadata and data into a single byte stream.
    """
    flags = 0
    if is_last:
        flags |= 0x01
    
    header = struct.pack(HEADER_FORMAT, flags, seq_num)
    return header + data

def parse_payload(payload: bytes) -> Tuple[int, bytes, bool]:
    """
    Unpacks metadata and data from a byte stream.
    Returns (seq_num, data, is_last).
    """
    if len(payload) < HEADER_SIZE:
        raise ValueError("Payload too short")
        
    flags, seq_num = struct.unpack(HEADER_FORMAT, payload[:HEADER_SIZE])
    data = payload[HEADER_SIZE:]
    is_last = bool(flags & 0x01)
    
    return seq_num, data, is_last

def build_subdomain(encoded_payload: str, session_id: str, domain: str) -> str:
    """
    Constructs the full FQDN.
    Splits encoded payload into 63-char labels if necessary.
    Format: <part1>.<part2>...<session_id>.<domain>
    """
    labels = []
    for i in range(0, len(encoded_payload), MAX_LABEL_LENGTH):
        labels.append(encoded_payload[i:i+MAX_LABEL_LENGTH])
    
    return ".".join(labels + [session_id, domain])

def parse_subdomain(qname: str, domain: str) -> Tuple[str, str]:
    """
    Extracts session_id and encoded_payload from the query name.
    """
    # Remove trailing dot
    qname = qname.rstrip('.')
    if not qname.endswith(domain):
        raise ValueError("Domain mismatch")
    
    # Remove domain part
    prefix = qname[:-len(domain)-1] # -1 for the dot
    parts = prefix.split('.')
    
    if len(parts) < 2:
        raise ValueError("Invalid format")
        
    session_id = parts[-1]
    encoded_payload = "".join(parts[:-1])
    
    return session_id, encoded_payload

if __name__ == "__main__":
    # Test
    data = b"Hello World" * 5
    chunks = prepare_chunks(data, 10)
    for seq, chunk, is_last in chunks:
        payload = build_payload(seq, chunk, is_last)
        encoded = encode_chunk(payload)
        fqdn = build_subdomain(encoded, "sess1", "ghost.net")
        print(f"FQDN: {fqdn}")
        
        # Decode
        sid, enc_pl = parse_subdomain(fqdn, "ghost.net")
        pl = decode_chunk(enc_pl)
        s, d, l = parse_payload(pl)
        print(f"Decoded: Seq={s}, Data={d}, Last={l}")
        assert s == seq
        assert d == chunk
        assert l == is_last
