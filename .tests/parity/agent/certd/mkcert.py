import datetime as dt, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out, names = sys.argv[1], sys.argv[2:]
now = dt.datetime.now(dt.timezone.utc)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake LE R3")]))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=89))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256()))
pem = cert.public_bytes(serialization.Encoding.PEM)
for f in ("cert.pem", "fullchain.pem"):
    open(os.path.join(out, f), "wb").write(pem)
open(os.path.join(out, "privkey.pem"), "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
