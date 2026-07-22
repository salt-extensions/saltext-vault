"""
Interface with the `Vault GPG secret engine <https://github.com/LeSuisse/vault-gpg-plugin/tree/main>`_.

The API docs can be found `here <https://github.com/LeSuisse/vault-gpg-plugin/blob/main/docs/http-api.md>`_.

.. versionadded:: 1.8.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import base64
import logging
import typing
from pathlib import Path

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils import vault
from saltext.vault.utils.vault import helpers

if typing.TYPE_CHECKING:
    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltGrains
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltOpts

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __grains__: SaltGrains


log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__virtualname__ = "vault_gpg"


def __virtual__():
    return __virtualname__


def create_key(
    name,
    real_name=None,
    email=None,
    comment=None,
    key_bits=None,
    exportable=False,
    mount="gpg",
):
    """
    Create a GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.create_key mykey real_name='Foo Bar' email='foo@b.ar'

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys/<name>" {
            capabilities = ["create"]
        }

    name
        Name of the key.

    real_name
        Real name of the identity associated with the GPG key to create.

    email
        Email of the identity associated with the GPG key to create.

    comment
        Comment of the identity associated with the GPG key to create.

    key_bits
        Bitlength of the generated GPG key. Defaults to ``2048``.

    exportable
        If the raw private key is exportable. Defaults to false.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    payload = helpers.filter_unset(
        {
            "generate": True,
            "real_name": real_name,
            "email": email,
            "comment": comment,
            "key_bits": key_bits,
            "exportable": exportable,
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def import_key(
    name,
    text=None,
    path=None,
    fingerprint=None,
    exportable=False,
    user=None,
    gnupghome=None,
    keyring=None,
    use_passphrase=False,
    mount="gpg",
):
    """
    Import a GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.import_key mykey text="lQHYBGOH8R0BBACb1xGmsPqP8..."
            salt '*' vault_gpg.import_key mykey text="-----BEGIN PGP PRIVATE KEY BLOCK..."
            salt-call vault_gpg.import_key mykey path=/root/test.key
            salt-call vault_gpg.import_key mykey fingerprint=3abcf1...

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys/<name>" {
            capabilities = ["create"]
        }

    name
        Name of the key.

    text
        ASCII-armored GPG private key as a string (or Python bytes type) to import.
        Can also be passed as a raw base64 string without markers and newlines.
        Either this, ``path`` or ``fingerprint`` is required.

    path
        Path to a file local to the minion containing the ASCII-armored GPG private key.
        Either this, ``text`` or ``fingerprint`` is required.

    fingerprint
        Fingerprint of a secret key to export from a GnuPG keyring using :py:func:`gpg.export_key <salt.modules.gpg.export_key>`.
        Either this, ``text`` or ``path`` is required.

        .. note::
            This parameter requires the GPG modules from Salt >= 3007.

    exportable
        If the raw private key should be exportable. Defaults to false.

    user
        When ``fingerprint`` is specified, which user's keychain to access.
        Defaults to user Salt is running as.
        Passing the user as ``salt`` sets the GnuPG home directory to ``/etc/salt/gpgkeys``.

    gnupghome
        When ``fingerprint`` is specified, the location where the GPG keyring and related files are stored.
        Defaults to the user's default.

    keyring
        When ``fingerprint`` is specified, limit the operation to this specific keyring,
        specified as a local filesystem path.

    use_passphrase
        When ``fingerprint`` is specified, whether to use a passphrase to export the secret key.
        The passphrase is retrieved from the Pillar key ``gpg_passphrase``.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    helpers.one_of(text=text, path=path, fingerprint=fingerprint)
    if fingerprint:
        key = __salt__["gpg.export_key"](
            fingerprint,
            secret=True,
            user=user,
            gnupghome=gnupghome,
            keyring=keyring,
            use_passphrase=use_passphrase,
            bare=True,
        )
        if not key:
            raise CommandExecutionError(
                "Failed exporting the secret key from GnuPG, see minion log for details"
            )
    else:
        key = _fix_key(_get_file_or_data(text, path), "PGP PRIVATE KEY BLOCK")
    payload = helpers.filter_unset(
        {
            "generate": False,
            "key": key,
            "exportable": exportable,
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def list_keys(mount="gpg"):
    """
    List configured keys.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.list_keys

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys" {
            capabilities = ["list"]
        }

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys"
    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def read_key(name, mount="gpg"):
    """
    Read a configured key's information.
    Returns a dictionary with keys ``exportable``, ``fingerprint`` and ``public_key``.
    Returns ``None`` if it does not exist.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.read_key mykey

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys/<name>" {
            capabilities = ["read"]
        }

    name
        Name of the key.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    try:
        return vault.query("GET", endpoint, __opts__, __context__)["data"]
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def delete_key(name, mount="gpg"):
    """
    Delete a GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.delete_key mykey

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys/<name>" {
            capabilities = ["delete"]
        }

    name
        Name of the key.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/keys/{name}"
    try:
        return vault.query("DELETE", endpoint, __opts__, __context__)
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def export_private_key(
    name, path=None, gnupg=False, user=None, gnupghome=None, keyring=None, mount="gpg"
):
    """
    Export a configured private key (ASCII-armored).
    Requires the key to be exportable.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.export_private_key mykey
            salt '*' vault_gpg.export_private_key mykey path=/root/test.key
            salt '*' vault_gpg.export_private_key mykey gnupg=true

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/export/<name>" {
            capabilities = ["read"]
        }

    name
        Name of the key.

    path
        Export the private key to this file path. Missing parent dirs are created.
        Optional. If set, ``gnupg`` is ignored.

    gnupg
        Import the exported private key into a GnuPG keyring via :py:func:`gpg.import_key <salt.modules.gpg.import_key>`.
        Optional. Ignored when ``path`` is set.

        .. note::
            This parameter requires the GPG modules from Salt >= 3008.

    user
        When ``gnupg`` is ``true``, which user's keychain to access.
        Defaults to user Salt is running as.
        Passing the user as ``salt`` sets the GnuPG home directory to ``/etc/salt/gpgkeys``.

    gnupghome
        When ``gnupg`` is ``true``, the location where the GPG keyring and related files are stored.
        Defaults to the user's default.

    keyring
        When ``gnupg`` is ``true``, limit the operation to this specific keyring,
        specified as a local filesystem path.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/export/{name}"
    try:
        key = vault.query("GET", endpoint, __opts__, __context__)["data"]["key"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

    if path:
        _write_path(path, key)
        return f"Private key written to {path}"
    if gnupg:
        res = __salt__["gpg.import_key"](text=key, user=user, gnupghome=gnupghome, keyring=keyring)
        if not res["res"]:
            raise CommandExecutionError(res["message"])
        return "Private key exported to GnuPG keyring"
    return key


def export_public_key(
    name, path=None, gnupg=False, user=None, gnupghome=None, keyring=None, mount="gpg"
):
    """
    Export the public key of a configured private key (ASCII-armored).
    This is a convenience wrapper around :py:func:`read_key <saltext.vault.modules.vault_gpg.read_key>`.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.export_public_key mykey
            salt '*' vault_gpg.export_public_key mykey path=/root/test.pub
            salt '*' vault_gpg.export_public_key mykey gnupg=True

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/keys/<name>" {
            capabilities = ["read"]
        }

    name
        Name of the key.

    path
        Export the public key to this file path. Missing parent dirs are created.
        Optional.

    gnupg
        Import the exported public key into a GnuPG keyring via :py:func:`gpg.import_key <salt.modules.gpg.import_key>`.
        Optional.

        .. note::
            This parameter requires the GPG modules from Salt >= 3008.

    user
        When ``gnupg`` is ``true``, which user's keychain to access.
        Defaults to user Salt is running as.
        Passing the user as ``salt`` sets the GnuPG home directory to ``/etc/salt/gpgkeys``.

    gnupghome
        When ``gnupg`` is ``true``, the location where the GPG keyring and related files are stored.
        Defaults to the user's default.

    keyring
        When ``gnupg`` is ``true``, limit the operation to this specific keyring,
        specified as a local filesystem path.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    key = read_key(name, mount=mount)["public_key"]

    if path:
        _write_path(path, key)
        return f"Public key written to {path}"
    if gnupg:
        res = __salt__["gpg.import_key"](text=key, user=user, gnupghome=gnupghome, keyring=keyring)
        if not res["res"]:
            raise CommandExecutionError(res["message"])
        return "Public key exported to GnuPG keyring"
    return key


def sign(
    name, message=None, message_encoded=None, path=None, algorithm=None, encoding=None, mount="gpg"
):
    """
    Sign data with a configured GPG key. Returns the (detached) signature.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.sign mykey message="Hello there"
            salt '*' vault_gpg.sign mykey path=/my/important/file

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/sign/<name>" {
            capabilities = ["create", "update"]
        }

        # or algorithm-dependent
        path "<mount>/sign/<name>/<algorithm>" {
            capabilities = ["create", "update"]
        }

    name
        Name of the key.

    message
        Data to sign. Can be a string (or a Python bytes type).
        Either this, ``message_encoded`` or ``path`` is required.

    message_encoded
        Data to sign. Can be a string (or a Python bytes type).
        Decoded from Base64 before signing.
        Either this, ``message`` or ``path`` is required.

    path
        Path to a file local to the minion with data to sign.
        Mind that the data is read into memory, which might be relevant
        if you are signing a very large file.
        Either this, ``message`` or ``message_encoded`` is required.

    algorithm
        Hash algorithm to use. Valid: ``sha2-224``, ``sha2-256``, ``sha2-384``, ``sha2-512``.
        Defaults to ``sha2-256``.

    encoding
        Encoding format for the returned signature. Valid: ``base64``, ``ascii-armor``.
        Defaults to ``base64``.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    helpers.one_of(message=message, message_encoded=message_encoded, path=path)
    message_data = _get_file_or_data(message, path, b64=message_encoded)
    endpoint = f"{mount}/sign/{name}"
    payload = helpers.filter_unset(
        {
            "algorithm": algorithm,
            "format": encoding,
            "input": base64.b64encode(message_data).decode(),
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"][
            "signature"
        ]
    except vault.VaultPermissionDeniedError:
        algorithm = payload.pop("algorithm", "sha2-256")
        endpoint = f"{mount}/sign/{name}/{algorithm}"
        try:
            return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"][
                "signature"
            ]
        except vault.VaultException as err:
            raise CommandExecutionError(f"{err.__class__}: {err}") from err
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def verify(
    name, message=None, sig=None, message_encoded=None, path=None, sig_path=None, mount="gpg"
):
    """
    Verify signed data with a configured GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.verify mykey message="Hello there" sig="wsBcBAABCgAQBQJZme..."
            salt '*' vault_gpg.verify mykey message="Hello there" sig="-----BEGIN PGP SIGNATURE..."
            salt '*' vault_gpg.verify mykey path=/my/important/file sig_path=/my/important/file.asc

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/verify/<name>" {
            capabilities = ["create", "update"]
        }

    name
        Name of the key.

    message
        Signed data as a string (or a Python bytes type).
        Either this or ``path`` is required.

    sig
        Detached signature to verify as a string (or a Python bytes type).
        Can also be passed as a raw base64 string without markers and newlines.
        Either this or ``sig_path`` is required.

    message_encoded
        Data to verify, encoded as Base64. Can be a string (or a Python bytes type).
        Decoded before verifying. Either this, ``message`` or ``path`` is required.

    path
        Path to a file local to the minion containing the signed data.
        Mind that the data is read into memory, which might be relevant
        if you are signing a very large file.
        Either this, ``message`` or ``message_encoded`` is required.

    sig_path
        Path to a file local to the minion containing the detached signature
        to verify. Either this or ``sig`` is required.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    helpers.one_of(message=message, message_encoded=message_encoded, path=path)
    helpers.one_of(sig=sig, sig_path=sig_path)

    message_data = _get_file_or_data(message, path, b64=message_encoded)
    sig_data = _get_file_or_data(sig, sig_path)
    sig_encoded, sig_format = _norm_format(sig_data, "PGP SIGNATURE")
    endpoint = f"{mount}/verify/{name}"
    payload = helpers.filter_unset(
        {
            "signature": sig_encoded,
            "format": sig_format,
            "input": base64.b64encode(message_data).decode(),
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"][
            "valid"
        ]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def decrypt(
    name,
    message=None,
    signer_key=None,
    path=None,
    signer_key_path=None,
    signer_key_fingerprint=None,
    user=None,
    gnupghome=None,
    keyring=None,
    decode=True,
    decode_utf8=True,
    mount="gpg",
):
    """
    Decrypt a message with a configured GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.decrypt mykey message="wsBcBAABCgAQBQJZme..."
            salt '*' vault_gpg.decrypt mykey message="-----BEGIN PGP MESSAGE..."
            salt '*' vault_gpg.decrypt mykey path=/my/important/file

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/decrypt/<name>" {
            capabilities = ["create", "update"]
        }

    name
        Name of the key.

    message
        Ciphertext as a string (or a Python bytes type).
        Can also be passed as a raw base64 string.
        Either this or ``path`` is required.

    signer_key
        (ASCII-armored) GPG key of the signer as a string.
        Can also be passed as a raw base64 string without markers and newlines.
        Optional. If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption fails.

    path
        Path to a file local to the minion containing the encrypted data.
        Mind that the data is read into memory, which might be relevant
        if you are decrypting a very large file.
        Either this or ``message`` is required.

    signer_key_path
        Path to a file local to the minion containing the (ASCII-armored) GPG key of the signer.
        Optional. If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption fails.

    signer_key_fingerprint
        Fingerprint of the signer key. Used to fetch key via :py:func:`gpg.export_key <salt.modules.gpg.export_key>`.
        Optional. If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption fails.

        .. note::
            This parameter requires the GPG modules from Salt >= 3007.

    user
        When ``signer_key_fingerprint`` is specified, which user's keychain to access.
        Defaults to user Salt is running as.
        Passing the user as ``salt`` sets the GnuPG home directory to ``/etc/salt/gpgkeys``.

    gnupghome
        When ``signer_key_fingerprint`` is specified, the location where the GPG keyring and related files are stored.
        Defaults to the user's default.

    keyring
        When ``signer_key_fingerprint`` is specified, limit the operation to this specific keyring,
        specified as a local filesystem path.

    decode
        The API endpoint responds with the plaintext encoded in base64.
        Decode the return value using base64. Defaults to true.

    decode_utf8
        When decode is true, also decode the bytes returned by decoding base64
        into a string (using UTF-8). Defaults to true.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/decrypt/{name}"
    try:
        res = _decrypt_cmd(
            endpoint=endpoint,
            message=message,
            path=path,
            signer_key=signer_key,
            signer_key_path=signer_key_path,
            signer_key_fingerprint=signer_key_fingerprint,
            user=user,
            gnupghome=gnupghome,
            keyring=keyring,
        )["plaintext"]
        if not decode:
            return res
        res = base64.b64decode(res)
        if not decode_utf8:
            return res
        return res.decode("utf-8")
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def show_session_key(
    name,
    message=None,
    signer_key=None,
    path=None,
    signer_key_path=None,
    mount="gpg",
):
    """
    Decrypt and return the session key of the provided ciphertext using the configured GPG key.

    CLI Example:

    .. code-block:: bash

            salt '*' vault_gpg.show_session_key mykey message="wsBcBAABCgAQBQJZme..."
            salt '*' vault_gpg.show_session_key mykey message="-----BEGIN PGP MESSAGE..."
            salt '*' vault_gpg.show_session_key mykey path=/my/important/file

    Required policy:

    .. code-block:: vaultpolicy

        path "<mount>/show-session-key/<name>" {
            capabilities = ["create", "update"]
        }

    name
        Name of the key.

    message
        Ciphertext as a string (or a Python bytes type).
        Can also be passed as a raw base64 string.
        Either this or ``path`` is required.

    signer_key
        (ASCII-armored) GPG key of the signer as a string.
        Can also be passed as a raw base64 string without markers and newlines.
        Optional. If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption fails.

        .. important::
            This is how it's documented, but an invalid signature was ignored
            when this module was written.

    path
        Path to a file local to the minion containing the encrypted data.
        Mind that the data is read into memory, which might be relevant
        if you are decrypting a very large file.
        Either this or ``message`` is required.

    signer_key_path
        Path to a file local to the minion containing the (ASCII-armored)
        GPG key of the signer.
        Optional. If present, the ciphertext must be signed
        and the signature valid, otherwise the decryption fails.

        .. important::
            This is how it's documented, but an invalid signature was ignored
            when this module was written.

    mount
        Mount path the GPG backend is mounted to. Defaults to ``gpg``.
    """
    endpoint = f"{mount}/show-session-key/{name}"
    try:
        return _decrypt_cmd(
            endpoint=endpoint,
            message=message,
            path=path,
            signer_key=signer_key,
            signer_key_path=signer_key_path,
        )["session_key"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def _norm_format(
    data: bytes, blocktype: str
) -> tuple[str, typing.Literal["ascii-armor"] | typing.Literal["base64"]]:
    """
    Pass some raw bytes. This function checks whether it's
      a) ASCII-armored and returns the string
      b) Base64-encoded and returns the string
      c) Raw bytes data, encodes it to Base64 and returns the string
    Also returns which kind of ``format`` to pass to ``vault-gpg-plugin``.

    Used for signatures and encrypted messages because the plugin supports
    both ascii-armored and base64 inputs there.
    """
    if data.strip().startswith(f"-----BEGIN {blocktype}".encode()):
        return data.decode(), "ascii-armor"
    data_raw, _ = helpers.try_base64(data)
    return base64.b64encode(data_raw).decode(), "base64"


def _decrypt_cmd(
    endpoint: str,
    message: str | bytes | None,
    path: str | None,
    signer_key: str | bytes | None,
    signer_key_path: str | None,
    signer_key_fingerprint: str | None = None,
    user: str | None = None,
    gnupghome: str | None = None,
    keyring: str | None = None,
) -> dict[str, str]:
    """
    The semantics of decrypt and show-session-key are very similar, hence keep this DRY.
    """
    helpers.one_of(message=message, path=path)
    helpers.x_of(
        signer_key=signer_key,
        signer_key_path=signer_key_path,
        signer_key_fingerprint=signer_key_fingerprint,
        _min=0,
    )
    message_data = _get_file_or_data(message, path)
    signer_data = None
    if signer_key_fingerprint:
        signer_data = __salt__["gpg.export_key"](
            signer_key_fingerprint, user=user, gnupghome=gnupghome, keyring=keyring, bare=True
        )
    elif signer_key or signer_key_path:
        signer_data = _fix_key(
            _get_file_or_data(signer_key, signer_key_path), "PGP PUBLIC KEY BLOCK"
        )
    message_encoded, message_format = _norm_format(message_data, "PGP MESSAGE")
    payload = helpers.filter_unset(
        {
            "signer_key": signer_data,
            "format": message_format,
            "ciphertext": message_encoded,
        }
    )
    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err


def _get_file_or_data(
    data: str | bytes | None, path: str | None, b64: str | bytes | None = None
) -> bytes:
    """
    If ``data`` is defined, turn it into bytes and optionally decode Base64.
    Otherwise, return file contents as bytes. Overridden in the wrapper.

    Used for all key/sig/message/raw data inputs.

    data
        Raw data value

    path
        Path to a file to load

    b64
        Base64-encoded data
    """
    if data is not None:
        try:
            ret = typing.cast(bytes, data.encode())  # type: ignore
        except AttributeError:
            ret = typing.cast(bytes, data)  # please don't pass in other stuff :)
        return ret
    if b64 is not None:
        ret, was_b64 = helpers.try_base64(b64)
        if not was_b64:
            raise SaltInvocationError(
                "Received unexpected value for `message_encoded` (not Base64-encoded)"
            )
        return ret
    if path is not None:
        if (file := Path(path)).exists():
            return file.read_bytes()
        raise CommandExecutionError(f"Specified path {path} does not exist")
    raise RuntimeError("This should not have been hit")  # pragma: no cover


def _write_path(path: str, data: str | bytes):
    """
    Atomically write to a safe file. Extracted so it can be overridden in the wrapper.
    """
    dst = Path(path)
    if not dst.parent.exists():
        dst.parent.mkdir(parents=True)
    helpers.safe_atomic_write(path, data)


def _fix_key(key: bytes, blocktype: str) -> str:
    """
    We need to accept raw base64 key blocks without markers/newlines
    in order to be able to easily accept raw keys via the CLI, specifically
    to run wrapper integration tests.

    Used for all raw key inputs.
    """
    key = key.strip()
    if key.startswith(f"-----BEGIN {blocktype}-----\n".encode()) and key.endswith(
        f"\n-----END {blocktype}-----".encode()
    ):
        return key.decode()
    if not helpers.try_base64(key)[1]:
        # it's not base64
        raise CommandExecutionError(
            f"Expected key to be ASCII-armored or raw base64 string, got neither: {key[:5]}..."
        )

    fixed = []
    temp = key.decode()  # we can safely decode base64

    while len(temp) > 0:
        if temp.startswith("-----"):
            # Grab ----(.*)---- blocks
            fixed.append(temp[: temp.index("-----", 5) + 5])
            temp = temp[temp.index("-----", 5) + 5 :]
        else:
            # grab base64 chunks
            if temp[:64].count("-") == 0:
                fixed.append(temp[:64])
                temp = temp[64:]
            else:
                fixed.append(temp[: temp.index("-")])
                temp = temp[temp.index("-") :]
    if fixed[0][0] != "-":
        fixed.insert(0, "")
        fixed.insert(0, "")
        fixed.insert(0, f"-----BEGIN {blocktype}-----")
    if fixed[-1][0] != "-":
        fixed.append(f"-----END {blocktype}-----")
    return "\n".join(fixed)
