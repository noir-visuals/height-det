#!/usr/bin/env python3
"""
STATURE - Local Network HTTPS Server
Generates a self-signed SSL cert and serves over HTTPS so
navigator.mediaDevices.getUserMedia works on mobile browsers.

Usage:
    pip install flask pyopenssl
    python serve.py

Then open the printed HTTPS URL on your phone (same Wi-Fi).
Accept the browser's SSL warning (it's safe — self-signed).
"""

import os
import socket
from flask import Flask, send_file

app = Flask(__name__)

HTML_FILE = os.path.join(os.path.dirname(__file__), "height-predictor.html")

@app.route("/")
def index():
    return send_file(HTML_FILE)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_cert(ip, cert_file="cert.pem", key_file="key.pem"):
    """Generate a self-signed certificate valid for the local IP."""
    from OpenSSL import crypto

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("  [SSL] Using existing cert.pem / key.pem")
        return cert_file, key_file

    print("  [SSL] Generating self-signed certificate...")
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = ip
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)

    # Add Subject Alternative Name for IP
    san = f"IP:{ip},IP:127.0.0.1".encode()
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, san),
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
    ])

    cert.sign(k, "sha256")

    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    print("  [SSL] Certificate generated!")
    return cert_file, key_file

if __name__ == "__main__":
    PORT = 5000
    local_ip = get_local_ip()

    cert_file, key_file = generate_cert(local_ip)

    print()
    print("=" * 55)
    print("  STATURE — Height Predictor  (HTTPS)")
    print("=" * 55)
    print()
    print(f"  Local:    https://127.0.0.1:{PORT}")
    print(f"  Network:  https://{local_ip}:{PORT}  ← open on phone")
    print()
    print("  ⚠️  Your browser will warn about the certificate.")
    print("  On Android Chrome: tap 'Advanced' → 'Proceed'")
    print("  On iOS Safari:     tap 'Show Details' → 'visit website'")
    print()
    print("  Make sure your phone is on the same Wi-Fi!")
    print("  Press Ctrl+C to stop.")
    print()
    print("=" * 55)

    app.run(
        host="0.0.0.0",
        port=PORT,
        ssl_context=(cert_file, key_file),
        debug=False
    )
