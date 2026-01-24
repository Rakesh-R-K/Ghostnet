import pytest
from common import dns_utils

def test_chunk_encoding_decoding():
    data = b"Hello Ghostnet!"
    encoded = dns_utils.encode_chunk(data)
    decoded = dns_utils.decode_chunk(encoded)
    assert decoded == data

def test_prepare_chunks():
    data = b"0123456789"
    chunk_size = 4
    chunks = dns_utils.prepare_chunks(data, chunk_size)
    
    # 10 bytes / 4 = 3 chunks (4, 4, 2)
    assert len(chunks) == 3
    assert chunks[0] == (0, b"0123", False)
    assert chunks[1] == (1, b"4567", False)
    assert chunks[2] == (2, b"89", True)

def test_payload_building_parsing():
    seq = 42
    data = b"chunk_data"
    is_last = True
    
    payload = dns_utils.build_payload(seq, data, is_last)
    p_seq, p_data, p_is_last = dns_utils.parse_payload(payload)
    
    assert p_seq == seq
    assert p_data == data
    assert p_is_last == is_last

def test_subdomain_building_parsing():
    payload = "ABCDEF"
    session_id = "sess123"
    domain = "ghost.net"
    
    fqdn = dns_utils.build_subdomain(payload, session_id, domain)
    assert fqdn.endswith("sess123.ghost.net")
    
    parsed_session, parsed_payload = dns_utils.parse_subdomain(fqdn, domain)
    assert parsed_session == session_id
    assert parsed_payload == payload

def test_parse_subdomain_mismatch():
    with pytest.raises(ValueError, match="Domain mismatch"):
        dns_utils.parse_subdomain("some.evil.com", "ghost.net")
