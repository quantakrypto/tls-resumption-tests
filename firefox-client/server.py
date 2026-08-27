"""
Does Firefox resume a TLS 1.3 session after the server certificate has expired?

Method
  1. Mint a local CA and a leaf certificate that is valid for LEAF_SECONDS only.
  2. Serve HTTPS on localhost with that leaf. Every response carries
     Connection: close and a meta refresh, so each page load is a NEW TCP
     connection and therefore a new TLS handshake, from the SAME long-lived
     Firefox process (its session cache is in memory, so the process must live).
  3. Log, per connection: whether OpenSSL reports the session as RESUMED, and
     whether the certificate is still inside its validity window at that moment.

Reading the result
  connections after expiry that are RESUMED  -> Firefox does NOT re-verify the
                                                certificate on resumption
  connections after expiry that FAIL or are  -> Firefox DOES check validity on
  full handshakes                               the resumption path
"""
import datetime, os, socket, ssl, sys, threading, time, pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = pathlib.Path(__file__).parent
PORT = 8443
LEAF_SECONDS = int(os.environ.get("LEAF_SECONDS", "75"))
RELOAD_EVERY = int(os.environ.get("RELOAD_EVERY", "15"))
LOG = HERE / "connections.log"


def mint():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "anchorage-test-ca")])
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(
              digital_signature=True, content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=True,
              crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    nb = now - datetime.timedelta(seconds=30)          # tolerate clock skew
    na = now + datetime.timedelta(seconds=LEAF_SECONDS)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))

    (HERE / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (HERE / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (HERE / "leaf.key").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return na


PAGE = ("<!doctype html><meta http-equiv=refresh content={r}>"
        "<title>anchor age test</title><body style='font-family:sans-serif'>"
        "<h2>connection {n}</h2><p>resumed: {res}</p><p>cert valid: {ok}</p>")


def main():
    expiry = mint()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(HERE / "leaf.pem", HERE / "leaf.key")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT)); srv.listen(16)
    start = time.time()
    n = 0
    LOG.write_text("")
    print(f"serving on https://localhost:{PORT}  leaf expires in {LEAF_SECONDS}s", flush=True)

    def handle(raw, addr):
        nonlocal n
        try:
            c = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            n += 1
            now = datetime.datetime.now(datetime.timezone.utc)
            line = (f"{n}\t{time.time()-start:6.1f}\tHANDSHAKE_FAILED\t"
                    f"cert_valid={now < expiry}\t{type(e).__name__}: {e}")
            print(line, flush=True); LOG.open("a").write(line + "\n")
            return
        n += 1
        now = datetime.datetime.now(datetime.timezone.utc)
        resumed = c.session_reused
        valid = now < expiry
        line = (f"{n}\t{time.time()-start:6.1f}\t"
                f"{'RESUMED ' if resumed else 'FULL    '}\tcert_valid={valid}")
        print(line, flush=True); LOG.open("a").write(line + "\n")
        try:
            c.recv(4096)
            body = PAGE.format(r=RELOAD_EVERY, n=n, res=resumed, ok=valid).encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                      b"Cache-Control: no-store\r\nConnection: close\r\n"
                      + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        except OSError:
            pass
        finally:
            try: c.close()
            except OSError: pass

    while True:
        try:
            raw, addr = srv.accept()
        except KeyboardInterrupt:
            break
        threading.Thread(target=handle, args=(raw, addr), daemon=True).start()


if __name__ == "__main__":
    main()
