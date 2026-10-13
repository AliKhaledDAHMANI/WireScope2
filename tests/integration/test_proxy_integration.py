"""Opt-in real-socket tests for HTTP + TLS interception using only a loopback lab."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

pytest.importorskip("mitmproxy", reason="install the runtime dependency to run proxy integration tests")
cryptography = pytest.importorskip("cryptography", reason="install the dev dependency to run local HTTPS lab tests")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

from wirescope.proxy import ProxyService
from wirescope.store import Store


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"lab-response:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args): pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_listening(port: int, timeout: float = 8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"listener on port {port} did not start")


def make_local_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    key_path, cert_path = directory / "lab-key.pem", directory / "lab-cert.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def wait_for_flow(store: Store, url_fragment: str):
    deadline = time.time() + 5
    while time.time() < deadline:
        rows = store.list_flows(search=url_fragment, limit=100)
        if rows and rows[0].get("status") is not None:
            return rows[0]
        time.sleep(0.05)
    raise AssertionError(f"No completed flow recorded for {url_fragment}")


class TLSLabServer(ThreadingHTTPServer):
    def __init__(self, address, handler, context):
        self.tls_context = context
        super().__init__(address, handler)
    def get_request(self):
        sock, address = super().get_request()
        return self.tls_context.wrap_socket(sock, server_side=True), address


def test_http_and_https_are_intercepted_in_local_lab(tmp_path: Path):
    http_lab = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    http_thread = Thread(target=http_lab.serve_forever, daemon=True); http_thread.start()
    cert, key = make_local_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    https_lab = TLSLabServer(("127.0.0.1", 0), LabHandler, server_context)
    https_thread = Thread(target=https_lab.serve_forever, daemon=True); https_thread.start()

    store = Store(tmp_path / "history.sqlite3")
    proxy = ProxyService(store, tmp_path, upstream_insecure=True)  # self-signed upstream cert, lab only
    proxy_port = free_port()
    try:
        proxy.start(port=proxy_port)
        wait_listening(proxy_port)
        http_url = f"http://127.0.0.1:{http_lab.server_port}/http-check"
        http_client = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=4)
        http_client.request("GET", http_url, headers={"Host": f"127.0.0.1:{http_lab.server_port}"})
        http_response = http_client.getresponse()
        assert http_response.read() == b"lab-response:/http-check"
        http_client.close()
        saved_http = wait_for_flow(store, "/http-check")
        assert saved_http["status"] == 200

        deadline = time.time() + 5
        while time.time() < deadline and not proxy.ca_cert_path.is_file():
            time.sleep(0.05)
        assert proxy.ca_cert_path.is_file(), "mitmproxy should generate a local CA certificate"
        client_tls = ssl.create_default_context(cafile=str(proxy.ca_cert_path))
        https_client = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=5, context=client_tls)
        https_client.set_tunnel("127.0.0.1", https_lab.server_port)
        https_client.request("GET", "/https-check", headers={"Host": f"127.0.0.1:{https_lab.server_port}"})
        https_response = https_client.getresponse()
        assert https_response.read() == b"lab-response:/https-check"
        https_client.close()
        saved_https = wait_for_flow(store, "/https-check")
        assert saved_https["status"] == 200
        assert saved_https["url"].startswith("https://127.0.0.1:")
    finally:
        proxy.stop()
        http_lab.shutdown(); http_lab.server_close(); http_thread.join(timeout=2)
        https_lab.shutdown(); https_lab.server_close(); https_thread.join(timeout=2)
