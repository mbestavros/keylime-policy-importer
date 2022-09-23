import base64
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import UnsupportedAlgorithm
from os.path import exists

# Signs an artifact with private key located at keypath.
def sign(artifact, keypath):
    if not exists(keypath):
        print(f"Private key not found at {keypath}")
        exit(1)
    with open(keypath, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, backends.default_backend())

    artifact_b64 = base64.b64encode(json.dumps(artifact))

    artifact_signature = private_key.sign(
        artifact_b64.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    public_key = private_key.public_key()
    public_key_hash = hashlib.sha256(public_key).hexdigest()

    return {
        "keyid": public_key_hash,
        "keytype": "ecdsa",
        "sig": base64.b64encode(artifact_signature)
    }

# Keylime keyring functions
def get_pubkey(filedata):
    """Get the public key from the filedata; if an x509 certificate is
    given, also determine the keyidv2 from the Subject Key Identifier,
    otherwise return None
    To make it easy for the user, we try to parse the filedata as
    PEM- or DER-encoded public key, x509 certificate, or even private key.
    This function then returns the public key object or None if the file
    contents could not be interpreted as a key.
    """
    default_be = backends.default_backend()
    for func in [
        _get_pubkey_from_der_x509_certificate,
        _get_pubkey_from_pem_x509_certificate,
        _get_pubkey_from_der_public_key,
        _get_pubkey_from_pem_public_key,
        _get_pubkey_from_der_private_key,
        _get_pubkey_from_pem_private_key,
    ]:
        pubkey, keyidv2 = func(filedata, default_be)
        if pubkey:
            return pubkey, keyidv2

    return None, None


def get_pubkey_from_file(filename):
    """Get the public key object from a file"""
    try:
        with open(filename, "rb") as fobj:
            filedata = fobj.read()
            pubkey, keyidv2 = get_pubkey(filedata)
            if pubkey:
                return pubkey, keyidv2
    except Exception:
        pass

    return None, None

def _get_pubkey_from_der_public_key(filedata, backend):
    """Load the filedata as a DER public key"""
    try:
        return serialization.load_der_public_key(filedata, backend=backend), None
    except Exception:
        return None, None


def _get_pubkey_from_pem_public_key(filedata, backend):
    """Load the filedata as a PEM public key"""
    try:
        return serialization.load_pem_public_key(filedata, backend=backend), None
    except Exception:
        return None, None


def _get_pubkey_from_der_private_key(filedata, backend):
    """Load the filedata as a DER private key"""
    try:
        privkey = serialization.load_der_private_key(filedata, None, backend=backend)
        return privkey.public_key(), None
    except Exception:
        return None, None


def _get_pubkey_from_pem_private_key(filedata, backend):
    """Load the filedata as a PEM private key"""
    try:
        privkey = serialization.load_pem_private_key(filedata, None, backend=backend)
        return privkey.public_key(), None
    except Exception:
        return None, None

def _get_pubkey_from_der_x509_certificate(filedata, backend):
    """Load the filedata as a DER x509 certificate"""
    try:
        cert = x509.load_der_x509_certificate(filedata, backend=backend)
        return cert.public_key(), _get_keyidv2_from_cert(cert)
    except Exception:
        return None, None


def _get_pubkey_from_pem_x509_certificate(filedata, backend):
    """Load the filedata as a PEM x509 certificate"""
    try:
        cert = x509.load_pem_x509_certificate(filedata, backend=backend)
        return cert.public_key(), _get_keyidv2_from_cert(cert)
    except Exception:
        return None, None

def _get_keyidv2_from_cert(cert):
    """Get the keyidv2 from the cert's Subject Key Identifier"""
    if not cert.extensions:
        return None

    skid = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if skid and skid.value and len(skid.value.digest) >= 4:
        keyidv2 = int.from_bytes(skid.value.digest[-4:], "big")
        return keyidv2
    return None

class ImaKeyring:
    """ImaKeyring models an IMA keyring where keys are indexed by their keyid"""

    def __init__(self):
        """Constructor"""
        self.ringv2 = {}

    @staticmethod
    def _get_keyidv2(pubkey):
        """Calculate the keyidv2 of a given public key object. The keyidv2
        are the lowest 4 bytes of the sha1 hash over the public key bytes
        of a DER-encoded key in PKCS1 format.
        """
        if isinstance(pubkey, RSAPublicKey):
            fmt = serialization.PublicFormat.PKCS1
            pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.DER, format=fmt)
        elif isinstance(pubkey, EllipticCurvePublicKey):
            fmt = serialization.PublicFormat.UncompressedPoint
            pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.X962, format=fmt)
        else:
            raise UnsupportedAlgorithm(f"Unsupported public key type {type(pubkey)}")

        default_be = backends.default_backend()
        digest = hashes.Hash(hashes.SHA1(), backend=default_be)
        digest.update(pubbytes)
        keydigest = digest.finalize()
        return int.from_bytes(keydigest[16:], "big")

    def add_pubkey(self, pubkey, keyidv2):
        """Add a public key object to the keyring; a keyidv2 may be passed in
        and if it is 'None' it will be determined using the commonly used
        sha1 hash function for calculating the Subject Key Identifier.
        """
        if not keyidv2:
            keyidv2 = ImaKeyring._get_keyidv2(pubkey)
        # it's unlikely that two different public keys have the same 32 bit keyidv2
        self.ringv2[keyidv2] = pubkey

    def to_string(self):
        """Generate a string representation"""
        return json.dumps(self.to_json())
