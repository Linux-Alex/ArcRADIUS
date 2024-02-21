import os
from datetime import datetime, timedelta
from OpenSSL import crypto

def is_certificate_valid(cert_file, key_file):
    # Check if certificate and key files exist
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        return False

    # Check if the certificate is still valid
    with open(cert_file, "rb") as f:
        cert_data = f.read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    expiry_date = datetime.strptime(cert.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
    if expiry_date < datetime.now():
        return False

    return True

def ensure_certificate(cert_file, key_file):
    # Check if certificate files already exist and are valid
    if is_certificate_valid(cert_file, key_file):
        print("Certificate and key files are already valid.")
        return

    # Generate a new private key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a new self-signed certificate
    cert = crypto.X509()
    cert.set_serial_number(1000)
    cert.get_subject().C = "SI"
    cert.get_subject().ST = "Maribor"
    cert.get_subject().L = "Maribor"
    cert.get_subject().O = "ArcRADIUS"
    cert.get_subject().OU = "IT Department"
    cert.get_subject().CN = "localhost"
    cert.set_notBefore(datetime.now().strftime('%Y%m%d%H%M%SZ').encode())
    cert.set_notAfter((datetime.now() + timedelta(days=365)).strftime('%Y%m%d%H%M%SZ').encode())
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    # Write the certificate and private key to files
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    print("Certificate and key files generated successfully.")

if __name__ == "__main__":
    cert_file = "certs/cert.pem"
    key_file = "certs/key.pem"
    ensure_certificate(cert_file, key_file)
