import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

CERT_PATH = ''

def decode_certificate(file_path):
    with open(file_path, 'rb') as certificate_file:
        certificate_data = certificate_file.read()

    certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())

    return certificate

def print_attributes(cert):
    expiration_check(cert.not_valid_after)
    print("Subject:", cert.subject)
    print("Issuer:", cert.issuer)
    print("Serial Number:", cert.serial_number)
    print("Valid From:", cert.not_valid_before)
    print("Valid Until:", cert.not_valid_after.date())
    print("Version:", cert.version.name)
    print("Signature Algorithm:", cert.signature_algorithm_oid._name)
    print("Public Key:", cert.public_key().public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

def expiration_check(valid_until):
    now = datetime.datetime.now()
    time_remaining = valid_until - now

    if time_remaining.days < 5:
        print(f"\nWARNING! Certificate has {time_remaining.days} days left until expiration!\n")

if __name__ == '__main__':
    decoded_certificate = decode_certificate(CERT_PATH)

    print_attributes(decoded_certificate)
