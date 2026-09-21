import typing
from os import PathLike
from pathlib import Path

try:
    import salt.utils.x509 as x509util
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import SSHCertificate
    from cryptography.hazmat.primitives.serialization import SSHCertificateType
    from cryptography.hazmat.primitives.serialization import SSHPublicKeyTypes
    from cryptography.hazmat.primitives.serialization import load_ssh_private_key
    from cryptography.hazmat.primitives.serialization import load_ssh_public_identity

    Privkey: typing.TypeAlias = (
        ec.EllipticCurvePrivateKey
        | rsa.RSAPrivateKey
        | dsa.DSAPrivateKey
        | ed25519.Ed25519PrivateKey
    )

    CERT_CHECK = True
except ImportError:
    CERT_CHECK = False

    Privkey = SSHCertificate = SSHPublicKeyTypes = typing.Any  # type: ignore  # pylint: disable=invalid-name


def get_cert(
    cert: str | bytes | PathLike[str],
    typ: typing.Literal["user", "host"] | None = None,
) -> "SSHCertificate":
    """
    Load an SSH certificate from disk. Optionally assert that it is of user/host type before returning.
    """
    data = None
    if not isinstance(cert, bytes):
        try:
            p = Path(cert)
            if p.exists():
                data = p.read_bytes()
        except Exception:  # pylint: disable=broad-except
            pass
    if data is None:
        cert = typing.cast(str | bytes, cert)
        if isinstance(cert, str):
            data = cert.encode()
        else:
            data = cert
    ret = load_ssh_public_identity(data)
    if not isinstance(ret, SSHCertificate):
        raise ValueError(f"Expected SSHCertificate, got {ret.__class__.__name__}")
    if not typ:
        return ret
    if typ == "user":
        assert ret.type == SSHCertificateType.USER
    elif typ == "host":
        assert ret.type == SSHCertificateType.HOST
    else:
        raise ValueError(f"Unknown cert typ: {typ}")
    return ret


def get_privkey(
    pk: str | bytes | PathLike[str] | Privkey, passphrase: str | None = None
) -> Privkey:
    """
    Load an SSH private key from disk, optionally encrypted
    """
    if hasattr(pk, "private_bytes"):
        return pk  # type: ignore
    pk = typing.cast(str | bytes | PathLike[str], pk)
    data = password = None
    if not isinstance(pk, bytes):
        try:
            p = Path(pk)
            if p.exists():
                data = p.read_bytes()
        except Exception:  # pylint: disable=broad-except
            pass
    if data is None:
        pk = typing.cast(str | bytes, pk)
        if isinstance(pk, str):
            data = pk.encode()
        else:
            data = pk
    if passphrase is not None:
        password = passphrase.encode()

    return load_ssh_private_key(data, password=password)


def belongs_to(cert_or_pubkey: SSHCertificate | SSHPublicKeyTypes, privkey: Privkey) -> bool:
    """
    Check whether an SSH certificate or public key is a pair with a private key
    """
    if isinstance(cert_or_pubkey, SSHCertificate):
        cert_or_pubkey = cert_or_pubkey.public_key()
    return x509util.is_pair(cert_or_pubkey, get_privkey(privkey))


def signed_by(cert: SSHCertificate, privkey: Privkey) -> bool:
    """
    Check whether an SSH certificate was signed by a private key.
    """
    cert.verify_cert_signature()
    return x509util.is_pair(cert.signature_key(), get_privkey(privkey))
