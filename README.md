# GhostNet

GhostNet is a covert file transfer system that tunnels data through DNS queries. It allows for secure, stealthy file exfiltration or transfer by mimicking normal DNS traffic.

## Architecture

GhostNet consists of two main components:

1.  **Client (`ghostnet_client.py`)**:
    *   Reads a file.
    *   Compresses it (zlib).
    *   Encrypts it (ChaCha20-Poly1305).
    *   Splits it into small chunks.
    *   Encodes chunks into Base32.
    *   Sends chunks as DNS A-record queries (e.g., `<chunk>.<session_id>.ghost.net`).

2.  **Server (`ghostnet_server.py`)**:
    *   Listens on UDP port 53 (or custom).
    *   Parses incoming DNS queries.
    *   Extracts and decodes chunks.
    *   Reassembles the encrypted stream.
    *   Decrypts and decompresses the file.
    *   Saves the reconstructed file.

## Features

*   **End-to-End Encryption**: Uses ChaCha20-Poly1305 for authenticated encryption.
*   **Stealth**:
    *   Randomized delays between packets.
    *   Looks like standard DNS traffic.
*   **Reliability**:
    *   Sequence numbers for reassembly.
    *   Retries on packet loss.
*   **Compression**: Reduces data volume using zlib.

## Installation

1.  **Prerequisites**:
    *   Python 3.10+
    *   `cryptography` library: `pip install cryptography`

2.  **Configuration**:
    *   Edit `config.json` to set the `server_ip`, `server_port`, and `encryption_key`.
    *   **IMPORTANT**: Change the `encryption_key` to a secure random 32-byte string.

## Usage

### 1. Start the Server
On the receiving machine (e.g., Kali Linux):
```bash
sudo python server/ghostnet_server.py
```
*Note: Port 53 requires root privileges. You can change the port in `config.json` for testing.*

### 2. Send a File
On the client machine:
```bash
python client/ghostnet_client.py /path/to/secret_file.pdf
```

## Testing Locally
You can run the included test script to simulate a transfer on localhost:
```bash
python test_ghostnet.py
```

## Security Notes
*   **Metadata Leakage**: The `session_id` is visible in plaintext DNS queries.
*   **Traffic Analysis**: While individual packets look like DNS, the volume of queries might trigger IDS/IPS if not throttled (adjust `delay_min`/`delay_max` in config).
*   **Key Management**: The encryption key is currently stored in `config.json`. In a production environment, use environment variables or a secure key exchange mechanism.

## Disclaimer
This tool is for educational and authorized testing purposes only. Misuse of this software for malicious activities is illegal.
