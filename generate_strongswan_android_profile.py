#!/usr/bin/env python3
#Generate JSON-file to import to StrongSwan Android client
#https://docs.strongswan.org/docs/latest/os/androidVpnClientProfiles.html
import argparse
import base64
import getpass
import uuid
import json
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend


class Globals:
    issued_to = None


def load_pem_cert(path):
    data = Path(path).read_bytes()
    cert = x509.load_pem_x509_certificate(data, backend=default_backend())
    try:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attr:
            Globals.issued_to = cn_attr[0].value
    except Exception as e:
        print(f"Warning: could not extract CN from certificate: {e}", file=sys.stderr)
    return cert


def load_pem_key(path, password=None):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())


def strip_pem_headers(pem_text):
    lines = pem_text.strip().splitlines()
    cert_body = [line for line in lines if "CERTIFICATE" not in line]
    return "".join(cert_body)


def create_pkcs12(cert_path, key_path, ca_path=None, key_password=None, p12_password=None):
    try:
        cert = load_pem_cert(cert_path)
        key = load_pem_key(key_path, password=key_password.encode() if key_password else None)
        ca_certs = []
        if ca_path:
            ca_data = Path(ca_path).read_bytes()
            ca_certs = [x509.load_pem_x509_certificate(ca_data, backend=default_backend())]
        p12 = pkcs12.serialize_key_and_certificates(
            name=b"vpn",
            key=key,
            cert=cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=serialization.BestAvailableEncryption(
                p12_password.encode() if p12_password else b''
            )
        )
        return base64.b64encode(p12).decode('utf-8')
    except Exception as e:
        print(f"Error generating PKCS#12: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate Android StrongSwan VPN profile JSON")
    parser.add_argument("--cert", required=True, help="Path to client certificate PEM file")
    parser.add_argument("--key", required=True, help="Path to client private key PEM file")
    parser.add_argument("--ca", help="Path to CA certificate PEM file. Will be used as remote.cert")
    parser.add_argument("--server", required=True, help="VPN server address")
    parser.add_argument("--remote-id", required=True, help="Remote ID for VPN server")
    parser.add_argument("--ike-proposal", default="aes256-sha256-modp2048", help="IKE proposal string")
    parser.add_argument("--ipsec-proposal", default="aes256-sha256-modp2048", help="IPsec proposal string")
    parser.add_argument("--split-tunneling", nargs='+', help="List of subnets for split-tunneling (CIDR)")
    parser.add_argument("--key-password", help="Password for encrypted private key PEM")
    parser.add_argument("--p12-password", help="Password for generated PKCS#12 container")
    parser.add_argument("--uuid", help="Optional: specify UUID manually (otherwise auto-generated)")

    args = parser.parse_args()

    if args.key_password is None:
        try:
            args.key_password = getpass.getpass("Enter password for private key (leave blank if not encrypted): ")
            if args.key_password == '':
                args.key_password = None
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    p12_b64 = create_pkcs12(
        cert_path=args.cert,
        key_path=args.key,
        ca_path=args.ca,
        key_password=args.key_password,
        p12_password=args.p12_password
    )

    try:
        remote_cert_pem = Path(args.ca).read_text()
        remote_cert_stripped = strip_pem_headers(remote_cert_pem)
    except Exception as e:
        print(f"Failed to read or process remote certificate: {e}", file=sys.stderr)
        sys.exit(1)

    profile = {
        "uuid": args.uuid or str(uuid.uuid4()),
        "name": Globals.issued_to,
        "type": "ikev2-cert",
        "local": {
            "p12": p12_b64
        },
        "remote": {
            "addr": args.server,
            "remote-id": args.remote_id,
            "cert": remote_cert_stripped,
            "certreq": "true",
            "revocation": {
                "ocsp": "false",
                "crl": "false"
            }
        },
        "ike-proposal": args.ike_proposal,
        "esp-proposal": args.ipsec_proposal,
        "split-tunneling": {
            "block-ipv6": "true",
            "subnets": args.split_tunneling if args.split_tunneling else []
        },
        "nat-keepalive": "15"
    }

    print(json.dumps(profile, indent=2))


if __name__ == "__main__":
    main()
