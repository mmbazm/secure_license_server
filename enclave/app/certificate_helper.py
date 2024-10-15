
"""
certificate_helper.py - Certificate and Key Management Utilities

This module provides a collection of functions for generating, managing, and working with
X.509 certificates and cryptographic keys. It's designed to support various certificate
operations, including root CA creation, server certificate generation, and attestation
key.

Functions:
    generate_self_signed_cert(subject_name, *args, **kwargs) -> Tuple[Certificate, RSAPrivateKey]
        Generate a self-signed certificate with the given subject name.

    generate_root_certificate() -> Tuple[Certificate, RSAPrivateKey]
        Create a new self-signed root CA certificate and private key.

    generate_server_certificate(root_cert_path, root_key_path, server_name) -> Tuple[Certificate, RSAPrivateKey]
        Generate a server certificate signed by a root CA.

    extract_public_key(cert_path: str) -> RSAPublicKey
        Extract the public key from a given X.509 certificate file.

    hash_crt_file(file_path: str) -> str
        Calculate the SHA-256 hash of a .crt certificate file.

    generate_attestation_keys(private_key_name: str, public_key_name: str) -> Tuple[RSAPrivateKey, RSAPublicKey]
        Generate an RSA key pair for attestation purposes and save to files.

    sign_certificate(cert_path: str, ak_private_key_path: str, output_path: str) -> None
        Sign a X.509 certificate using an Attestation Key (AK) private key.

    verify_signature(cert_path: str, signature_path: str, ak_public_key_path: str) -> None
        Verify the signature of a X.509 certificate using an AK public key.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
from OpenSSL import crypto
import binascii
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


def generate_root_certificate():
    """
    Generate a self-signed root certificate authority (CA) certificate and private key.

    This function creates a new root CA certificate and its corresponding private key.
    The generated certificate can be used to sign other certificates, such as server
    or client certificates.

    Returns:
        None
    """

    # Create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "FR"
    cert.get_subject().ST = "California"
    cert.get_subject().L = "San Francisco"
    cert.get_subject().O = "My Company"
    cert.get_subject().OU = "My Organization"
    cert.get_subject().CN = "Root CA"

    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)

    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier",
                             False, b"hash", subject=cert),
    ])

    cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier",
                             False, b"keyid:always", issuer=cert),
    ])

    cert.sign(key, "sha256")

    # Save the certificate and private key
    with open("../files/root_ca.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open("../files/root_ca.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    print("Root certificate generated successfully.")


def generate_server_certificate(root_cert_path, root_key_path, server_name):
    """
    Generate a server certificate signed by a root certificate authority (CA).

    This function creates a new server certificate using the provided root CA certificate
    and private key. The generated certificate is suitable for use in SSL/TLS connections.

    Args:
        root_cert_path (str): Path to the root CA certificate file (.pem or .crt).
        root_key_path (str): Path to the root CA private key file (.pem).
        server_name (str): Common Name (CN) for the server certificate. Typically, this
                           is the domain name of the server.

    Returns:
        None
    """

    # Load the root CA certificate and key
    with open(root_cert_path, 'rb') as f:
        root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(root_key_path, 'rb') as f:
        root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Create a key pair for the server
    server_key = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a certificate signing request (CSR)
    csr = crypto.X509Req()
    subject = csr.get_subject()
    subject.CN = server_name
    csr.set_pubkey(server_key)
    csr.sign(server_key, 'sha256')

    # Create the server certificate
    server_cert = crypto.X509()
    server_cert.set_serial_number(1000)
    server_cert.gmtime_adj_notBefore(0)
    server_cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
    server_cert.set_issuer(root_cert.get_subject())
    server_cert.set_subject(csr.get_subject())
    server_cert.set_pubkey(csr.get_pubkey())

    server_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(
            b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
        crypto.X509Extension(b"subjectAltName", False,
                             f"DNS:{server_name}".encode()),
    ])

    server_cert.sign(root_key, 'sha256')

    # Save the server certificate and private key
    with open(f"{server_name}.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))

    with open(f"{server_name}.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))

    print(f"Server certificate for {server_name} generated successfully.")


def extract_public_key(root_cert_path):
    """
    Extract the public key from a given X.509 certificate file.

    This function reads a certificate file and extracts its public key.
    The public key can be used for various cryptographic operations such as
    signature verification or encryption.

    Args:
        root_cert_path (str): Path to the X.509 certificate file (.pem or .crt).

    Returns:
        None
    """

    # Read the certificate file
    with open(root_cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()

    # Load the certificate
    cert = x509.load_pem_x509_certificate(cert_data)

    # Extract the public key
    public_key = cert.public_key()

    # Serialize the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the public key to a file
    public_key_path = "extracted_public_key.pem"
    with open(public_key_path, 'wb') as key_file:
        key_file.write(pem_public_key)

    print(f"Public key extracted and saved to {public_key_path}")
    return public_key_path


def generate_hash_crt_file(crt_file_path):
    """
    Calculate the SHA-256 hash of a .crt certificate file.

    This function reads the contents of a certificate file and computes its SHA-256 hash.
    The hash can be used for integrity verification or as a unique identifier for the certificate.

    Args:
        file_path (str): Path to the certificate file (.crt).

    Returns:
        str: The hexadecimal representation of the SHA-256 hash of the file contents.
    """

    # Create a sha256 object
    sha256_hash = hashlib.sha256()

    # Open crt file in binary mode
    with open(crt_file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    # Return hexadecimaldigest of the hash
    return sha256_hash.hexdigest()


def generate_attestation_keys(attestation_private_key_name, attestation_public_key_name):
    """
    Generate an RSA key pair for attestation purposes and save them to files.

    This function creates a new RSA key pair, typically used for attestation in TPM-like scenarios.
    The private and public keys are saved to separate files in PEM format.

    Args:
        attestation_private_key_name (str): Filename to save the private key (e.g., 'ak_private.pem').
        attestation_public_key_name (str): Filename to save the public key (e.g., 'ak_public.pem').

    Returns:
        None
    """

    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Extract the public key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the public key to a file
    with open(f"{attestation_public_key_name}.pem", "wb") as f:
        f.write(pem_public_key)

    # Serialize and Save the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{attestation_private_key_name}.pem", "wb") as f:
        f.write(private_pem)

    print("Attestation keys generated and saved.")


def sign_certificate(cert_path, ak_private_key_path, output_path):
    """
    Sign a X.509 certificate using an Attestation Key (AK) private key.

    This function loads a certificate from a file, signs it 
    using the provided Attestation Key private key, and saves the 
    resulting signature to a file.

    Args:
        cert_path (str): Path to the X.509 certificate file (.crt) to be signed.
        ak_private_key_path (str): Path to the Attestation Key private key file (.pem).
        output_path (str): Path where the resulting signature will be saved.

    Returns:
        None
    """

    # Load the certificate
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Load the AK private key from PEM file
    with open(ak_private_key_path, 'rb') as key_file:
        ak_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Assume the key is not password protected
            backend=default_backend()
        )

    # Sign the certificate
    signature = ak_private_key.sign(
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Write the signature to a file
    with open(output_path, 'wb') as sig_file:
        sig_file.write(signature)

    print(f"Certificate signed. Signature saved to {output_path}")


def verify_signature(cert_path, signature_path, ak_public_key_path):
    """
    Verify the signature of a X.509 certificate using an Attestation Key (AK) public key.

    This function loads a certificate, its corresponding signature, and the AK public key.
    It then verifies whether the signature is valid for the certificate's.

    Args:
        cert_path (str): Path to the X.509 certificate file (.crt) that was signed.
        signature_path (str): Path to the signature file (.bin) generated during signing.
        ak_public_key_path (str): Path to the Attestation Key public key file (.pem).

    Returns:
        None
    """

    # Load the certificate
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Load the signature
    with open(signature_path, 'rb') as sig_file:
        signature = sig_file.read()

    # Load the AK public key from PEM file
    with open(ak_public_key_path, 'rb') as key_file:
        ak_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    try:
        # Verify the signature
        ak_public_key.verify(
            signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception:
        print("Signature is invalid.")


def sign_hash_with_private_key(hash_value, private_key_path):
    """
    Sign a hash value using an RSA private key.

    This function takes a hash value and signs it using the RSA private key
    stored in the specified file. The signing process uses PKCS#1 v1.5 padding
    and SHA-256 as the hash algorithm.

    Args:
        hash_value (bytes): The hash value to be signed. This should be a byte
                            string representing the hash.
        private_key_path (str): The file path to the PEM-encoded RSA private key.

    Returns:
        bytes: The signature of the hash value, encoded as bytes.
    """

    # Load the private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Encrypt the hash value
    encrypted = private_key.sign(
        hash_value.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Encode the encrypted value to base64 for easier handling
    return base64.b64encode(encrypted)


def verify_hash_with_public_key(encrypted_hash, original_hash, public_key_path):
    """
    Verify a signed hash using an RSA public key.

    This function takes an encrypted (signed) hash, the original hash, and verifies
    the signature using the RSA public key stored in the specified file. The verification
    process uses PKCS#1 v1.5 padding and SHA-256 as the hash algorithm.

    Args:
        encrypted_hash (str): The base64-encoded signed hash value.
        original_hash (bytes): The original hash value to verify against. This should be
                               a byte string representing the hash.
        public_key_path (str): The file path to the PEM-encoded RSA public key.

    Returns:
        bool: True if the signature is valid (i.e., the encrypted hash corresponds to
              the original hash), False otherwise.
    """

    # Load the public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Decode the base64 encoded encrypted hash
    encrypted_hash_bytes = base64.b64decode(encrypted_hash)

    # Verify the signature
    try:
        public_key.verify(
            encrypted_hash_bytes,
            original_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verification successful. The hash is authentic.")
        return True
    except Exception as e:
        print(f"Signature verification failed: {str(e)}")
        return False


print(generate_hash_crt_file('tls.crt'))
