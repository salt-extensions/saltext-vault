"""
Manage the Vault (or OpenBao) PKI secret engine and Vault-issued X.509 certificates.

.. versionadded:: 1.1.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import base64
import logging
import os
import tempfile
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from typing import TYPE_CHECKING

from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault import helpers as hlp
from saltext.vault.utils.vault.helpers import timestring_map

try:
    from salt.utils import x509 as x509util

    from saltext.vault.utils.vault import pki

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAS_CRYPTOGRAPHY = False


if TYPE_CHECKING:

    from saltext.vault.utils._types import SaltContext
    from saltext.vault.utils._types import SaltFunctions
    from saltext.vault.utils._types import SaltLogger
    from saltext.vault.utils._types import SaltLow
    from saltext.vault.utils._types import SaltOpts
    from saltext.vault.utils._types import SaltStates

    __opts__: SaltOpts
    __context__: SaltContext
    __salt__: SaltFunctions
    __states__: SaltStates
    __low__: SaltLow

log: "SaltLogger" = logging.getLogger(__name__)  # type: ignore

__virtualname__ = "vault_pki"


def __virtual__():
    try:
        __salt__["x509.encode_certificate"]  # pylint: disable=pointless-statement
    except KeyError:  # pragma: no cover
        return (
            False,
            "This state requires the x509_v2 execution module. "
            "x509_v2 needs to be explicitly enabled by setting `x509_v2: true` "
            "in the minion configuration value `features` until Salt 3008 (Argon).",
        )
    if not HAS_CRYPTOGRAPHY:  # pragma: no cover
        return (False, "Could not load cryptography")
    return __virtualname__


VALID_FILE_ARGS = (
    "user",
    "group",
    "mode",
    "attrs",
    "makedirs",
    "dir_mode",
    "backup",
    "create",
    "follow_symlinks",
    "check_cmd",
    "tmp_dir",
    "tmp_ext",
    "selinux",
    "file_encoding",
    "encoding_errors",
    "win_owner",
    "win_perms",
    "win_deny_perms",
    "win_inheritance",
    "win_perms_reset",
)


def certificate_managed(
    name,
    common_name,
    role_name,
    private_key,
    mount="pki",
    ttl="720h",
    ttl_remaining="168h",
    issuer_ref=None,
    encoding="pem",
    append_ca_chain=False,
    sign_verbatim=False,
    private_key_passphrase=None,
    reissue=False,
    **kwargs,
):
    """
    Ensure an X.509 certificate is present as specified.

    .. note::
        The state can use ``sign-verbatim`` endpoint of Vault in which case CSR subject is fully
        translated. If not used, anything from CSR subject, except CN is ignored.
        Check `this issue <https://github.com/hashicorp/vault/issues/17313>`__ for more information.

    Required policy:

    .. code-block:: vaultpolicy

            # Need to read the role configuration in case of missing issuer_ref
            path "{mount}/roles/{role_name}" {
                capabilities = ["read"]
            }

            path "{mount}/issuer/{issuer_ref}" {
                capabilities = ["read"]
            }

            path "{mount}/issuer/{issuer_ref}/sign/{role_name}" {
                capabilities = ["update"]
            }

            # in case of sign_verbatim
            path "{mount}/issuer/{issuer_ref}/sign-verbatim/{role_name}" {
                capabilities = ["update"]
            }

    name
        Path to the certificate file.

    common_name
        Common name to be set for the certificate.

    role_name
        PKI role to be used for issuing the certificate from Vault.

    private_key
        Path or PEM formatted text of the private key used to sign CSR for the certificate.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    ttl
        Specifies the Time To Live value to be used for the validity period of the requested certificate,
        provided as a string duration with time suffix. Hour is the largest suffix. Defaults to ``720h`` or 30 days.

    ttl_remaining
        Specifies the Time To Live value to be used for checking remaining period before expiration
        after which certificate should be renewed.
        Provided as a string duration with time suffix. Hour is the largest suffix. Defaults to ``168h`` or 7 days.

    issuer_ref
        Override role's issuer for the certificate. Defaults to the one specified in the role.

    encoding
        Encoding to be used for the certificate file. Valid options are ``pem``, ``pkcs7_pem``, ``der``, ``pkcs7_der``. Defaults to ``pem``.

    append_ca_chain
        Whether to append CA chain to the certificate. Defaults to ``false``.

        .. note::
            This appends all CA certificates except self-signed (as they shouldn't be in the chain anyway)!

    sign_verbatim
        If set to true, the resulting certificate follows the CSR exactly.
        Otherwise, only ``CN`` can be set for the subject, any other subject parameters (like ``O``) are ignored.

        .. warning::
            This option is using a potentially dangerous endpoint. Be careful when using that option, as roles
            are not restricting what can be issued anymore.

    private_key_passphrase
        Password for the private key if encrypted.

    reissue
        Always reissue the certificate. Defaults to ``false``.

    kwargs
        Most parameters for the :py:func:`file.managed <salt.states.file.managed>` state or any of the ones for
        the Vault PKI :py:func:`sign_certificate <saltext.vault.modules.vault_pki.sign_certificate>` execution module function
        are passed through.

        .. note::

            ``encoding`` is a valid parameter for both this function and ``file.managed``. If you need to pass
            it to the latter, specify it as ``file_encoding`` instead.
    """

    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "The certificate is in the correct state",
    }

    changes = {}
    ca_chain = []
    verb = "create"
    file_args, cert_args = _split_file_kwargs(hlp.filter_state_internal_kwargs(kwargs))

    try:
        encoding = hlp.in_vals(("der", "pem", "pkcs7_der", "pkcs7_pem"), encoding=encoding)

        if encoding == "der" and append_ca_chain:
            raise SaltInvocationError(
                "Cannot append the CA chain to DER-encoded certificates. "
                "Use pkcs7_der if you need a binary encoding including the chain."
            )

        if timestring_map(ttl_remaining, cast=int) >= timestring_map(ttl, cast=int):
            raise SaltInvocationError("The ttl_remaning cannot be larger or equal to ttl.")

        # check file.managed changes early to avoid using unnecessary resources
        file_managed_test = _run_state("file.managed", name, test=True, replace=False, **file_args)
        if file_managed_test["result"] is False:
            ret["result"] = False
            ret["comment"] = "Problem while testing file.managed changes, see its output"
            _add_sub_state_run(ret, file_managed_test)
            return ret

        if "is not present and is not set for creation" in file_managed_test["comment"]:
            _add_sub_state_run(ret, file_managed_test)
            return ret

        file_exists = None
        # handle follow_symlinks
        if __salt__["file.is_link"](name):
            if file_args.get("follow_symlinks", True):
                name = os.path.realpath(name)
            else:
                if not __opts__["test"]:
                    # workaround https://github.com/saltstack/salt/issues/31802
                    __salt__["file.remove"](name)
                changes["replaced"] = True
                file_exists = False

        if file_exists is None:
            file_exists = __salt__["file.file_exists"](name)

        if issuer_ref is None:
            issuer_ref = (__salt__["vault_pki.read_role"](role_name, mount=mount) or {}).get(
                "issuer_ref"
            )
            if issuer_ref is None:
                raise CommandExecutionError(f"Role {role_name} does not exist.")

        issuer_info = __salt__["vault_pki.read_issuer"](issuer_ref, mount=mount)
        if issuer_info is None:
            raise CommandExecutionError(f"Issuer '{issuer_ref}' does not exist on mount {mount}")

        if append_ca_chain:
            ca_chain = [x509util.load_cert(x) for x in issuer_info["ca_chain"]]
            # Filter self-signed CA, which shouldn't be in the chain.
            ca_chain = [
                cert
                for cert in ca_chain
                if cert.subject.rfc4514_string() != cert.issuer.rfc4514_string()
            ]

        if file_exists:
            if reissue:
                # No need to make any checks, just replace the cert
                changes["replaced"] = True
            else:
                changes = pki.check_cert_for_changes(
                    current=name,
                    append_chain=ca_chain,
                    common_name=common_name,
                    encoding=encoding,
                    issuer=issuer_info["certificate"],
                    private_key=private_key,
                    private_key_passphrase=private_key_passphrase,
                    common_name_only=not sign_verbatim,
                    expire_tolerance=ttl_remaining,
                    **cert_args,
                )

        else:
            changes["created"] = True

        if not changes and file_managed_test["result"] and not file_managed_test["changes"]:
            _add_sub_state_run(ret, file_managed_test)
            return ret

        ret["changes"] = changes
        if changes and file_exists:
            verb = "reissue"

        if __opts__["test"]:
            ret["result"] = None if changes else True
            ret["comment"] = (
                f"The certificate would have been {verb}d" if changes else ret["comment"]
            )
            _add_sub_state_run(ret, file_managed_test)
            return ret

        cert = None
        if changes:
            if not set(changes) - {
                "ca_chain",
                "encoding",
            }:
                verb = "recreate"
                cert = __salt__["x509.encode_certificate"](
                    name,
                    append_certs=ca_chain,
                    encoding=encoding,
                )
            else:
                issued_cert = __salt__["vault_pki.sign_certificate"](
                    common_name=common_name,
                    role_name=role_name,
                    private_key=private_key,
                    private_key_passphrase=private_key_passphrase,
                    ttl=ttl,
                    issuer_ref=issuer_ref,
                    mount=mount,
                    sign_verbatim=sign_verbatim,
                    remove_roots_from_chain=False,
                    **cert_args,
                )
                cert = __salt__["x509.encode_certificate"](
                    issued_cert["certificate"],
                    append_certs=ca_chain,
                    encoding=encoding,
                )

            ret["comment"] = f"The certificate has been {verb}d"

            if encoding not in ["pem", "pkcs7_pem"]:
                # file.managed does not support binary contents, so create
                # an empty file first (makedirs). This does not work with check_cmd!
                file_managed_ret = _run_state("file.managed", name, replace=False, **file_args)
                _add_sub_state_run(ret, file_managed_ret)
                if not _check_file_ret(file_managed_ret, ret, file_exists):
                    return ret
                hlp.safe_atomic_write(
                    name,
                    base64.b64decode(cert),
                    __salt__["config.backup_mode"](file_args.get("backup", "")),
                    __opts__["cachedir"],
                )

        if not changes or encoding in ["pem", "pkcs7_pem"]:
            replace = bool(encoding in ["pem", "pkcs7_pem"] and changes)
            contents = cert if replace else None
            file_managed_ret = _run_state(
                "file.managed", name, contents=contents, replace=replace, **file_args
            )
            _add_sub_state_run(ret, file_managed_ret)
            if not _check_file_ret(file_managed_ret, ret, file_exists):
                return ret

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_managed(name, mount="pki", issuer_ref=None, ttl=None, max_ttl=None, **kwargs):
    """
    Ensures PKI role is present and configured as required.

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    issuer_ref
        Issuer reference for the role. Can be name, id or literal ``default``.

    ttl
        Specifies the Time To Live value to be used for the validity period of the requested certificate,
        provided as a string duration with time suffix. Hour is the largest suffix.
        The value specified is strictly used for future validity.
        If not set, uses the system default value or the value of ``max_ttl``, whichever is shorter.

    max_ttl
        Specifies the maximum Time To Live provided as a string duration with time suffix.
        Hour is the largest suffix. If not set, defaults to the system maximum lease TTL.

    kwargs
        Any other parameter accepted by the Vault :py:func:`write_role <saltext.vault.modules.vault_pki.write_role>`
        execution module function or Vault update role API method.
    """

    ret = {
        "name": name,
        "result": True,
        "comment": "The role is present as specified",
        "changes": {},
    }

    kwargs = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    def _diff_params(current):
        nonlocal issuer_ref, ttl, max_ttl, kwargs
        diff_params = (
            ("issuer_ref", issuer_ref),
            ("ttl", timestring_map(ttl, cast=int)),
            ("max_ttl", timestring_map(max_ttl, cast=int)),
        )
        changed = {}
        for param, arg in diff_params:
            if arg is None:
                continue
            if current[param] != arg:
                changed.update(
                    {
                        param: {
                            "old": current.get(param),
                            "new": arg,
                        }
                    }
                )
        for param, arg in kwargs.items():
            if param not in current:
                continue
            curr_val = current[param]
            # Compare normalized values: The API normalizes scalars for
            # list-type parameters and duration strings into seconds.
            if isinstance(curr_val, list) and isinstance(arg, str):
                arg = hlp.deserialize_csl(arg)
            elif (
                isinstance(curr_val, (int, float))
                and not isinstance(curr_val, bool)
                and isinstance(arg, str)
            ):
                try:
                    arg = timestring_map(arg, cast=type(curr_val))
                except SaltInvocationError:
                    pass
            if curr_val != arg:
                changed.update(
                    {
                        param: {
                            "old": curr_val,
                            "new": arg,
                        }
                    }
                )
        return changed

    changes = {}

    try:
        current = __salt__["vault_pki.read_role"](name, mount=mount)

        if current:
            changes = _diff_params(current)
            if not changes:
                return ret

        ret["changes"].update(changes)
        if not current:
            ret["changes"]["created"] = name
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                f"PKI role `{name}` would have been {'updated' if current else 'created'}"
            )
            return ret
        __salt__["vault_pki.write_role"](
            name=name, mount=mount, issuer_ref=issuer_ref, ttl=ttl, max_ttl=max_ttl, **kwargs
        )

        ret["comment"] = f"PKI role `{name}` has been {'updated' if current else 'created'}"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def role_absent(name, mount="pki"):
    """
    Ensure PKI role is absent.

    name
        Name of the role.

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.

    """

    ret = {
        "name": name,
        "result": True,
        "comment": "",
        "changes": {},
    }

    try:
        current = __salt__["vault_pki.read_role"](name, mount=mount)

        if current is None:
            ret["comment"] = f"PKI role `{name}` is already absent."
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"PKI role `{name}` would have been deleted"
            return ret

        __salt__["vault_pki.delete_role"](name, mount=mount)

        ret["comment"] = f"PKI role `{name}` has been deleted."

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def intermediate_ca_present(
    name,
    days_remaining=30,
    key_ref=None,
    rotate_key=False,
    key_type=None,
    key_algo=None,
    key_bits=None,
    max_path_length=0,
    managed_key_name=None,
    managed_key_id=None,
    issuer_name=None,
    leaf_not_after_behavior=None,
    usage=None,
    revocation_signature_algorithm=None,
    aia_urls=None,
    crl_endpoints=None,
    delta_crl_endpoints=None,
    ocsp_servers=None,
    aia_url_templating=None,
    mount="pki",
    **kwargs,
):
    """
    .. versionadded:: 1.9.0

    Ensure an issuer representing an intermediate CA is present **as the default issuer** on the mount.
    Rotates the issuer when necessary by generating a new certificate via :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`.
    Does not support certificate import.

    Required policy:

    .. code-block:: vaultpolicy

        # read default issuer to check for necessary changes
        path "<mount>/issuer/default" {
            capabilities = ["read"]
        }

        # when key_ref is not set
        path "<mount>/keys/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

        # generate a CSR to derive the public key
        path "<mount>/intermediate/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

        # import the signed cert
        path "<mount>/intermediate/set-signed" {
            capabilities = ["create", "update"]
        }

        # set default issuer
        path "<mount>/config/issuers" {
            capabilities = ["create", "update"]
        }

        # update issuer configuration
        path "<mount>/issuer/<name>" {
            capabilities = ["patch"]
        }

    **Certificate/Key configuration:**

    name
        Common name (CN) of the certificate subject.

    days_remaining
        Attempt to recreate the certificate if the number of days the certificate
        is valid for is less than the number specified. Defaults to ``30``.

    key_ref
        Instead of managing the key, use the one associated with this key ID/name.
        When specified, disables key generation/rotation.

    rotate_key
        When rotating the default issuer, rotate its key along with it. Defaults to false.
        Not respected when ``key_ref`` is specified.

        .. note::

            Key parameters are not managed statefully, meaning changes to ``key_type``, ``key_algo``
            and ``key_bits`` are only applied when generating a new key.
            ``key_ref`` changes are applied though.

    key_type
        Type of key to generate when necessary and ``key_ref`` is not specified.
        Either ``internal``, ``exported`` or ``kms``.
        Defaults to ``internal``.

    key_algo
        Key algorithm. Either ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Number of bits to use for the generated keys. Valid values depend on the ``key_algo``.

        * ``rsa``: 2048 (default), 3072, 4096, 8192.
        * ``ec``: 224, 256 (default), 384, 521
        * ``ed25519``: ignored

        Defaults to ``0`` (universal default).

    managed_key_name
        When ``key_type`` is ``kms``, the managed key's configured name. Either this or ``managed_key_id`` is required then.

    managed_key_id
        When ``key_type`` is ``kms``, the managed key's UUID. Either this or ``managed_key_name`` is required then.

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit, unless the issuer certificate has a maximum path length,
        in which case it means one less than the issuer's pathlen.
        Defaults to ``0``.

    kwargs
        Unknown keyword arguments are passed to :py:func:`x509.create_certificate <salt.modules.x509_v2.create_certificate>`.
        See there for details.

        The following arguments are enforced by this function:

        * ``CN``
        * ``basicConstraints``
        * ``csr``
        * ``format``
        * ``private_key`` (empty)
        * ``public_key`` (empty)
        * ``raw`` (empty)

        These receive defaults if not specified:

        * ``keyUsage``: ``[critical, cRLSign, keyCertSign]``
        * ``subjectKeyIdentifier``: ``hash``
        * ``authorityKeyIdentifier``: ``keyid:always,issuer``

    **Issuer configuration:**

    issuer_name
        Custom name for the issuer. Must be unique and not equal to ``default``.

    leaf_not_after_behavior
        Behavior of a leaf's ``NotAfter`` field during issuance when it exceeds the issuer's validity.
        Valid options:

        * ``err``: Error, unless during CA/ACME issuance. (default)
        * ``always_enforce_err``: Error, including during CA/ACME issuance.
        * ``truncate``: Silently truncate the requested NotAfter to that of the issuer.
        * ``permit``: Allow signed certificate validities to exceed that of the issuer.

    usage
        Allowed usages for this issuer. Valid options are:

        * ``read-only`` - to allow this issuer to be read; implict; always allowed;
        * ``issuing-certificates`` - to allow this issuer to be used for issuing other certificates;
        * ``crl-signing`` -  to allow this issuer to be used for signing CRLs.
          This is separate from the CRLSign KeyUsage on the x509 certificate, but this usage cannot be set
          unless that KeyUsage is allowed on the x509 certificate;
        * ``ocsp-signing`` -  to allow this issuer to be used for signing OCSP responses.

    revocation_signature_algorithm
        Which signature algorithm to use when building CRLs.
        See Go's `x509.SignatureAlgorithm <https://pkg.go.dev/crypto/x509#SignatureAlgorithm>`__ constant for possible values.
        Default (empty string) is to autoselect.

    aia_urls
        Specifies the URL values for the Issuing Certificate field as an array.

    crl_endpoints
        Specifies the URL values for the CRL Distribution Points field as an array.

    delta_crl_endpoints
        (Requires Vault 1.20+ or OpenBao)
        Specifies the URL values for the Delta CRL Distribution Points field.
        This can be an array or a comma- separated string list.

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as an array.

    aia_url_templating
        Render ``aia_urls``/``crl_endpoints``/``ocsp_servers``/``delta_crl_endpoints`` as templates.
        Supported variables: `{{issuer_id}}`, ``{{cluster_path}}``, ``{{cluster_aia_path}}``

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "Intermediate CA issuer is present as specified",
        "changes": {},
    }
    changes = {}
    cert_affected = issuer_affected = False
    issuer_id = None
    msg = []

    basic_constraints = {"critical": True, "ca": True}
    if max_path_length is not None:
        basic_constraints["pathlen"] = max_path_length
    kwargs["basicConstraints"] = basic_constraints
    kwargs["CN"] = name
    kwargs["format"] = "pem"
    kwargs.pop("path", None)
    kwargs.pop("private_key", None)
    kwargs.pop("public_key", None)
    kwargs.pop("csr", None)
    kwargs.setdefault("keyUsage", ["critical", "cRLSign", "keyCertSign"])
    kwargs.setdefault("subjectKeyIdentifier", "hash")
    kwargs.setdefault("authorityKeyIdentifier", "keyid:always,issuer")

    try:
        key_type = hlp.in_vals(("internal", "exported", "kms", None), key_type=key_type)
        if key_ref is not None:
            key_type = "existing"
            rotate_key = False
        if not (current := __salt__["vault_pki.read_issuer"](mount=mount)):
            changes["created"] = name
            cert_affected = True
            issuer_affected = any(
                val is not None
                for val in (
                    issuer_name,
                    leaf_not_after_behavior,
                    usage,
                    revocation_signature_algorithm,
                    aia_urls,
                    crl_endpoints,
                    delta_crl_endpoints,
                    ocsp_servers,
                    aia_url_templating,
                )
            )
        else:
            issuer_id = current["issuer_id"]
            if key_ref is None:
                key_ref = current.get("key_id")
                if key_ref is None:  # pragma: no cover
                    # Unsure if this is allowed to happen, need to check
                    raise CommandExecutionError("Default issuer key_id not set")
            kwargs["csr"] = __salt__["vault_pki.generate_intermediate_csr"](
                "existing", key_ref=key_ref, mount=mount
            )["csr"]
            with tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "issuer.pem"
                path.write_text("".join(current["ca_chain"]))
                x509_ret = _run_state(
                    "x509.certificate_managed",
                    str(path),
                    test=True,
                    days_remaining=days_remaining,
                    **kwargs,
                )
            if x509_ret["result"] is False:
                ret["result"] = False
                ret["comment"] = f"Failed running x509.certificate_managed: {x509_ret['comment']}"
                return ret
            cert_changes = x509_ret["changes"]

            if cert_changes and rotate_key:
                cert_changes["private_key"] = True
                ext_changes = cert_changes.setdefault(
                    "extensions", {"added": [], "changed": [], "removed": []}
                )
                if "subjectKeyIdentifier" not in ext_changes["changed"]:
                    ext_changes["changed"].append("subjectKeyIdentifier")
            if cert_changes:
                changes["cert"], cert_affected = cert_changes, True

            if issuer_changes := _check_issuer_config_changes(
                current,
                issuer_name=issuer_name,
                leaf_not_after_behavior=leaf_not_after_behavior,
                usage=usage,
                revocation_signature_algorithm=revocation_signature_algorithm,
                aia_urls=aia_urls,
                crl_endpoints=crl_endpoints,
                delta_crl_endpoints=delta_crl_endpoints,
                ocsp_servers=ocsp_servers,
                aia_url_templating=aia_url_templating,
            ):
                changes["issuer"], issuer_affected = issuer_changes, True

        if not changes:
            return ret

        if __opts__["test"]:
            ret["result"] = None
            if cert_affected:
                msg.append(
                    f"Intermediate CA certificate would have been {'rotated' if current else 'created'}"
                )
            if issuer_affected:
                msg.append(
                    f"Intermediate CA issuer would have been {'updated' if current else 'created'}"
                )
            ret["comment"] = ". ".join(msg) + "."
            ret["changes"] = changes
            return ret

        if cert_affected:
            if key_ref is None or rotate_key:
                key_ref = __salt__["vault_pki.generate_key"](
                    key_type or "internal",
                    key_algo=key_algo,
                    key_bits=key_bits,
                    managed_key_name=managed_key_name,
                    managed_key_id=managed_key_id,
                    mount=mount,
                )["key_id"]
            if "csr" not in kwargs or rotate_key:
                kwargs["csr"] = __salt__["vault_pki.generate_intermediate_csr"](
                    "existing", key_ref=key_ref, mount=mount
                )["csr"]

            cert = __salt__["x509.create_certificate"](**kwargs)
            res = __salt__["vault_pki.import_issuer_intermediate"](cert, mount=mount)
            try:
                issuer_id = res["imported_issuers"][0]
            except (IndexError, KeyError) as err:  # pragma: no cover
                raise CommandExecutionError(
                    "Generated certificate, but failed importing it"
                ) from err

            try:
                __salt__["vault_pki.set_default_issuer"](issuer_id, mount=mount)
            except CommandExecutionError as err:
                ret["result"] = False
                ret["comment"] = (
                    f"Generated and imported certificate as issuer `{issuer_id}`, but failed to set it as default issuer: {err}"
                )
                ret["changes"]["imported"] = issuer_id
                return ret
            if current is not None:
                ret["changes"]["cert"] = changes["cert"]
            msg.append(
                f"Intermediate CA certificate has been {'rotated' if current else 'created'}"
            )

        if issuer_affected:
            __salt__["vault_pki.update_issuer"](
                ref=issuer_id,
                name=issuer_name,
                leaf_not_after_behavior=leaf_not_after_behavior,
                usage=usage,
                revocation_signature_algorithm=revocation_signature_algorithm,
                aia_urls=aia_urls,
                crl_endpoints=crl_endpoints,
                delta_crl_endpoints=delta_crl_endpoints,
                ocsp_servers=ocsp_servers,
                aia_url_templating=aia_url_templating,
                mount=mount,
            )
            if current is not None:
                ret["changes"]["issuer"] = changes["issuer"]
            msg.append(f"Intermediate CA issuer has been {'updated' if current else 'created'}")

        if current is None:
            ret["changes"]["created"] = name
        ret["comment"] = ". ".join(msg) + "."
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        if msg:
            ret["comment"] = ". ".join(msg) + f", but received an exception later: {err}"
        else:
            ret["comment"] = str(err)

    return ret


def root_ca_present(  # pylint: disable=too-many-locals,too-many-arguments
    name,
    days_remaining=90,
    key_ref=None,
    rotate_key=False,
    key_type=None,
    key_algo=None,
    key_bits=None,
    managed_key_name=None,
    managed_key_id=None,
    alt_names=None,
    days_valid=3650,
    max_path_length=-1,
    key_usage=None,
    exclude_cn_from_sans=False,
    permitted_alt_names=None,
    excluded_alt_names=None,
    ou=None,
    organization=None,
    country=None,
    locality=None,
    province=None,
    street_address=None,
    postal_code=None,
    subject_serial_number=None,
    signature_bits=0,
    not_before_duration=30,
    not_after=None,
    issuer_name=None,
    leaf_not_after_behavior=None,
    usage=None,
    revocation_signature_algorithm=None,
    aia_urls=None,
    crl_endpoints=None,
    delta_crl_endpoints=None,
    ocsp_servers=None,
    aia_url_templating=None,
    mount="pki",
):
    """
    .. versionadded:: 1.9.0

    Ensure an issuer representing a root CA is present **as the default issuer** on the mount.
    Rotates the issuer when necessary.

    Required policy:

    .. code-block:: vaultpolicy

        # read default issuer to check for necessary changes
        path "<mount>/issuer/default" {
            capabilities = ["read"]
        }

        # read urls to account for cert extensions
        path "<mount>/config/urls" {
            capabilities = ["read"]
        }

        # when key_ref is not set
        path "<mount>/keys/generate/<key_type>" {
            capabilities = ["create", "update"]
        }

        # when key_ref is set
        path "<mount>/keys" {
            capabilities = ["list"]
        }

        # set default issuer
        path "<mount>/config/issuers" {
            capabilities = ["create", "update"]
        }

        # update issuer configuration
        path "<mount>/issuer/<name>" {
            capabilities = ["patch"]
        }

    **Certificate/Key configuration:**

    name
        Common name (CN) of the certificate subject.

    days_remaining
        Attempt to recreate the certificate if the number of days the certificate
        is valid for is less than the number specified. Defaults to ``30``.

    key_ref
        Instead of managing the key, use the one associated with this key ID/name.
        When specified, disables key generation/rotation.

    rotate_key
        When rotating the default issuer, rotate its key along with it. Defaults to false.
        Not respected when ``key_ref`` is specified.

        .. note::

            Key parameters are not managed statefully, meaning changes to ``key_type``, ``key_algo``
            and ``key_bits`` are only applied when generating a new key.
            ``key_ref`` changes are applied though.

    key_type
        Type of key to generate when necessary and ``key_ref`` is not specified.
        Either ``internal``, ``exported`` or ``kms``.
        Defaults to ``internal``.

    key_algo
        Key algorithm. Either ``rsa``, ``ed25519`` or ``ec``. Defaults to ``rsa``.

    key_bits
        Number of bits to use for the generated keys. Valid values depend on the ``key_algo``.

        * ``rsa``: 2048 (default), 3072, 4096, 8192.
        * ``ec``: 224, 256 (default), 384, 521
        * ``ed25519``: ignored

        Defaults to ``0`` (universal default).

    managed_key_name
        When ``key_type`` is ``kms``, the managed key's configured name. Either this or ``managed_key_id`` is required then.

    managed_key_id
        When ``key_type`` is ``kms``, the managed key's UUID. Either this or ``managed_key_name`` is required then.

    signature_bits
        Number of bits to use in the signature algorithm.
        Valid: ``256`` (SHA-2-256), ``384`` (SHA-2-384), ``512`` (SHA-2-512).
        Defaults to ``0``, which automatically selects an algorithm based on
        ``key_algo`` and ``key_bits`` of the issuer's private key.

    days_valid
        Number of days the certificate should be valid for when (re-)issued.
        Not respected when ``not_after`` is set explicitly.
        Defaults to 3650 (10 years).

    not_before_duration
        Duration by which to backdate the NotBefore property. Defaults to ``30s``.

    not_after
        Absolute value of the Not After field of the certificate in UTC format ``YYYY-MM-ddTHH:MM:SSZ``.
        When set, ``days_valid`` is ignored.

    alt_names
        Any alternative names to be added to the certificate.
        Can be specified either as dict (``{ "<type>": "<value>" }``),
        a dict of lists(``{ "<type>": ["<value1>", "<value2>", ...] }``)
        or list of SAN strings (``["<type>:<value>"]``).

        ``<type>`` can be ``dns``, ``email``, ``uri``, ``ip`` or any OID for otherName SANs.
        ``<value>`` is the corresponding value. Note that otherName SANs need to omit ``UTF8:``.

    max_path_length
        basicConstraints ``pathlen`` parameter, which indicates the maximum number of CAs that can appear below this one in a chain.
        If set to ``0``, this CA can only issue leaf certificates, not other CAs.
        A negative value means no limit, unless the issuer certificate has a maximum path length,
        in which case it means one less than the issuer's pathlen.
        Defaults to ``0``.

    key_usage
        (Requires Vault 1.20+ or OpenBao)
        List of key usages to add to the existing set of key usages (CRLSign,CertSign).
        Per the CA/B Forum, Vault ignores additional values other than DigitalSignature.

    exclude_cn_from_sans
        If set to true, the Common Name is not part of the SANs.

    permitted_alt_names
        List of alternative names for which certificates are allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.

        .. important::

            Types other than ``dns`` require Vault 1.19+.

    excluded_alt_names
        (Vault 1.19+ only)
        List of alternative names for which certificates are not allowed to be issued
        or signed by this CA certificate. The format is similar to the one for ``alt_names``,
        but ``<type>`` can only be ``dns``, ``email``, ``uri`` and ``ip``.

    Subject DN fields
        Most of these can be single strings or lists of strings (for multiple values).

        * ou
        * organization
        * country
        * locality
        * province
        * street_address
        * postal_code
        * subject_serial_number (only a single value)

    **Issuer configuration:**

    issuer_name
        Custom name for the issuer. Must be unique and not equal to ``default``.

    leaf_not_after_behavior
        Behavior of a leaf's ``NotAfter`` field during issuance when it exceeds the issuer's validity.
        Valid options:

        * ``err``: Error, unless during CA/ACME issuance. (default)
        * ``always_enforce_err``: Error, including during CA/ACME issuance.
        * ``truncate``: Silently truncate the requested NotAfter to that of the issuer.
        * ``permit``: Allow signed certificate validities to exceed that of the issuer.

    usage
        Allowed usages for this issuer. Valid options are:

        * ``read-only`` - to allow this issuer to be read; implict; always allowed;
        * ``issuing-certificates`` - to allow this issuer to be used for issuing other certificates;
        * ``crl-signing`` -  to allow this issuer to be used for signing CRLs.
          This is separate from the CRLSign KeyUsage on the x509 certificate, but this usage cannot be set
          unless that KeyUsage is allowed on the x509 certificate;
        * ``ocsp-signing`` -  to allow this issuer to be used for signing OCSP responses.

    revocation_signature_algorithm
        Which signature algorithm to use when building CRLs.
        See Go's `x509.SignatureAlgorithm <https://pkg.go.dev/crypto/x509#SignatureAlgorithm>`__ constant for possible values.
        Default (empty string) is to autoselect.

    aia_urls
        Specifies the URL values for the Issuing Certificate field as an array.

    crl_endpoints
        Specifies the URL values for the CRL Distribution Points field as an array.

    delta_crl_endpoints
        (Requires Vault 2.0+ or OpenBao)
        Specifies the URL values for the Delta CRL Distribution Points field.
        This can be an array or a comma- separated string list.

        .. note::

            This parameter is supported in Vault 1.20+, but not added as a FreshestCRL extension
            to the root issuer certificate, leading to non-idempotency of this state.

    ocsp_servers
        Specifies the URL values for the OCSP Servers field as an array.

    aia_url_templating
        Render ``aia_urls``/``crl_endpoints``/``ocsp_servers``/``delta_crl_endpoints`` as templates.
        Supported variables: `{{issuer_id}}`, ``{{cluster_path}}``, ``{{cluster_aia_path}}``

    mount
        Mount path the PKI backend is mounted to. Defaults to ``pki``.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "Root CA issuer is present as specified",
        "changes": {},
    }
    changes = {}
    cert_affected = issuer_affected = False
    issuer_id = None
    msg = []

    try:
        key_type = hlp.in_vals(("internal", "exported", "kms", None), key_type=key_type)
        if key_ref is not None:
            key_type = "existing"
            rotate_key = False
        if not (current := __salt__["vault_pki.read_issuer"](mount=mount)):
            changes["created"] = name
            cert_affected = True
            issuer_affected = any(
                val is not None
                for val in (
                    issuer_name,
                    leaf_not_after_behavior,
                    usage,
                    revocation_signature_algorithm,
                    aia_urls,
                    crl_endpoints,
                    delta_crl_endpoints,
                    ocsp_servers,
                    aia_url_templating,
                )
            )
        else:
            issuer_id = current["issuer_id"]
            try:
                urls = __salt__["vault_pki.read_urls"](mount=mount)
            except CommandExecutionError:
                urls = {}
            cert_changes = pki.check_root_issuer_for_changes(
                "".join(current["ca_chain"]),
                common_name=name,
                alt_names=alt_names,
                days_valid=days_valid,
                max_path_length=max_path_length,
                key_usage=key_usage,
                exclude_cn_from_sans=exclude_cn_from_sans,
                permitted_alt_names=permitted_alt_names,
                excluded_alt_names=excluded_alt_names,
                ou=ou,
                organization=organization,
                country=country,
                locality=locality,
                province=province,
                street_address=street_address,
                postal_code=postal_code,
                subject_serial_number=subject_serial_number,
                signature_bits=signature_bits,
                not_before_duration=not_before_duration,
                not_after=not_after,
                days_remaining=days_remaining,
                urls=urls,
            )
            if (cert_changes and rotate_key) or (
                key_ref is not None
                and current["key_id"] != __salt__["vault_pki.get_key_id"](key_ref, mount=mount)
            ):
                cert_changes["private_key"] = True
                ext_changes = cert_changes.setdefault(
                    "extensions", {"added": [], "changed": [], "removed": []}
                )
                if "subjectKeyIdentifier" not in ext_changes["changed"]:
                    ext_changes["changed"].append("subjectKeyIdentifier")
            if cert_changes:
                changes["cert"], cert_affected = cert_changes, True

            if issuer_changes := _check_issuer_config_changes(
                current,
                issuer_name=issuer_name,
                leaf_not_after_behavior=leaf_not_after_behavior,
                usage=usage,
                revocation_signature_algorithm=revocation_signature_algorithm,
                aia_urls=aia_urls,
                crl_endpoints=crl_endpoints,
                delta_crl_endpoints=delta_crl_endpoints,
                ocsp_servers=ocsp_servers,
                aia_url_templating=aia_url_templating,
            ):
                changes["issuer"], issuer_affected = issuer_changes, True

        if not changes:
            return ret

        if __opts__["test"]:
            ret["result"] = None
            if cert_affected:
                msg.append(
                    f"Root CA certificate would have been {'rotated' if current else 'created'}"
                )
            if issuer_affected:
                msg.append(f"Root CA issuer would have been {'updated' if current else 'created'}")
            ret["comment"] = ". ".join(msg)
            ret["changes"] = changes
            return ret

        if cert_affected:
            if key_ref is None or rotate_key:
                key_ref = __salt__["vault_pki.generate_key"](
                    key_type or "internal",
                    key_algo=key_algo,
                    key_bits=key_bits,
                    managed_key_name=managed_key_name,
                    managed_key_id=managed_key_id,
                    mount=mount,
                )["key_id"]

            if not_after is None:
                not_after_dt = datetime.now(tz=timezone.utc) + timedelta(days=days_valid)
                not_after = not_after_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            dns_sans, ip_sans, uri_sans, other_sans = pki.split_sans(pki.norm_sans(alt_names or []))

            dns_nc_allowed = email_nc_allowed = ip_nc_allowed = uri_nc_allowed = None
            if permitted_alt_names is not None:
                dns_nc_allowed, email_nc_allowed, ip_nc_allowed, uri_nc_allowed = (
                    pki.split_name_constraints(
                        pki.norm_sans(permitted_alt_names or [], allow_other_name=False)
                    )
                )
            dns_nc_denied = email_nc_denied = ip_nc_denied = uri_nc_denied = None
            if excluded_alt_names is not None:
                dns_nc_denied, email_nc_denied, ip_nc_denied, uri_nc_denied = (
                    pki.split_name_constraints(
                        pki.norm_sans(excluded_alt_names or [], allow_other_name=False)
                    )
                )

            res = __salt__["vault_pki.generate_root"](
                common_name=name,
                mount=mount,
                key_type="existing",
                key_ref=key_ref,
                alt_names=dns_sans and ",".join(dns_sans) or None,
                ip_sans=ip_sans and ",".join(ip_sans) or None,
                uri_sans=uri_sans and ",".join(uri_sans) or None,
                other_sans=other_sans and ",".join(other_sans) or None,
                exclude_cn_from_sans=exclude_cn_from_sans,
                max_path_length=max_path_length,
                key_usage=key_usage,
                permitted_dns_domains=dns_nc_allowed,
                excluded_dns_domains=dns_nc_denied,
                permitted_ip_ranges=ip_nc_allowed,
                excluded_ip_ranges=ip_nc_denied,
                permitted_email_addresses=email_nc_allowed,
                excluded_email_addresses=email_nc_denied,
                permitted_uri_domains=uri_nc_allowed,
                excluded_uri_domains=uri_nc_denied,
                ou=ou,
                organization=organization,
                country=country,
                locality=locality,
                province=province,
                street_address=street_address,
                postal_code=postal_code,
                serial_number=subject_serial_number,
                signature_bits=signature_bits,
                not_before_duration=not_before_duration,
                not_after=not_after,
            )
            issuer_id = res["issuer_id"]

            try:
                __salt__["vault_pki.set_default_issuer"](issuer_id, mount=mount)
            except CommandExecutionError as err:
                ret["result"] = False
                ret["changes"]["generated"] = issuer_id
                ret["comment"] = (
                    f"Generated issuer `{issuer_id}`, but failed to set it as default issuer: {err}"
                )
                return ret
            if current is not None:
                ret["changes"]["cert"] = changes["cert"]
            msg.append(f"Root CA certificate has been {'rotated' if current else 'created'}")

        if issuer_affected:
            __salt__["vault_pki.update_issuer"](
                ref=issuer_id,
                name=issuer_name,
                leaf_not_after_behavior=leaf_not_after_behavior,
                usage=usage,
                revocation_signature_algorithm=revocation_signature_algorithm,
                aia_urls=aia_urls,
                crl_endpoints=crl_endpoints,
                delta_crl_endpoints=delta_crl_endpoints,
                ocsp_servers=ocsp_servers,
                aia_url_templating=aia_url_templating,
                mount=mount,
            )
            if current is not None:
                ret["changes"]["issuer"] = changes["issuer"]
            msg.append(f"Root CA issuer has been {'updated' if current else 'created'}")

        ret["comment"] = ". ".join(msg) + "."
        if current is None:
            ret["changes"]["created"] = name
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        if msg:
            ret["comment"] = ". ".join(msg) + f", but received an exception later: {err}"
        else:
            ret["comment"] = str(err)

    return ret


def _check_issuer_config_changes(
    current,
    *,
    issuer_name: str | None = None,
    leaf_not_after_behavior: str | None = None,
    usage: list[str] | str | None = None,
    revocation_signature_algorithm: str | None = None,
    aia_urls: list[str] | str | None = None,
    crl_endpoints: list[str] | str | None = None,
    delta_crl_endpoints: list[str] | str | None = None,
    ocsp_servers: list[str] | str | None = None,
    aia_url_templating: bool | None = None,
):
    changes = {}
    for vault_param, saltext_param, val in (
        ("issuer_name", "issuer_name", issuer_name),
        ("leaf_not_after_behavior", "leaf_not_after_behavior", leaf_not_after_behavior),
        (
            "revocation_signature_algorithm",
            "revocation_signature_algorithm",
            revocation_signature_algorithm,
        ),
        ("enable_aia_url_templating", "aia_url_templating", aia_url_templating),
    ):
        if val is not None:
            # At least on OpenBao and older Vault releases, this is not reported if no URLs are set
            if vault_param == "enable_aia_url_templating" and vault_param not in current:
                current["enable_aia_url_templating"] = False
            if vault_param not in current:
                log.warning(
                    "Ignoring specified param %s during changes check, the server likely does not support it",
                    saltext_param,
                )
                continue
            if current[vault_param] != val:
                changes[saltext_param] = {"old": current[vault_param], "new": val}
    if usage is not None:
        wanted = set(hlp.deserialize_csl(usage))
        cur = set(hlp.deserialize_csl(current["usage"]))
        cur.discard("read-only")  # always allowed
        wanted.discard("read-only")
        if cur != wanted:
            changes["usage"] = {
                "added": list(sorted(wanted - cur)),
                "removed": list(sorted(cur - wanted)),
            }
    for vault_param, saltext_param, val in (
        ("issuing_certificates", "aia_urls", hlp.deserialize_csl(aia_urls)),
        ("crl_distribution_points", "crl_endpoints", hlp.deserialize_csl(crl_endpoints)),
        (
            "delta_crl_distribution_points",
            "delta_crl_endpoints",
            hlp.deserialize_csl(delta_crl_endpoints),
        ),
        ("ocsp_servers", "ocsp_servers", hlp.deserialize_csl(ocsp_servers)),
    ):
        if val is not None:
            # At least on OpenBao and older Vault releases, none of these are reported if all are unset
            if vault_param not in current:
                current[vault_param] = []
            if current[vault_param] != val:
                changes[saltext_param] = {
                    "added": list(sorted(set(val) - set(current[vault_param]))),
                    "removed": list(sorted(set(current[vault_param]) - set(val))),
                }
    return changes


def _split_file_kwargs(kwargs):
    file_args = {"show_changes": False}
    extra_args = {}
    for k, v in kwargs.items():
        if k in VALID_FILE_ARGS:
            file_args[k] = v
        else:
            extra_args[k] = v

    if "file_encoding" in file_args:
        file_args["encoding"] = file_args.pop("file_encoding")
    return file_args, extra_args


def _add_sub_state_run(ret, sub):
    sub["low"] = {
        "name": ret["name"],
        "state": "file",
        "__id__": __low__["__id__"],
        "fun": "managed",
    }
    if "sub_state_run" not in ret:
        ret["sub_state_run"] = []
    ret["sub_state_run"].append(sub)


def _run_state(func, name, test=None, **kwargs):
    if test not in (None, True):  # pragma: no cover
        raise SaltInvocationError("test param can only be None or True")
    test = test or __opts__["test"]
    res = __salt__["state.single"](func, name, test=test, concurrent=True, **kwargs)
    if not isinstance(res, dict):
        raise CommandExecutionError(f"Failed running {func}: {res}")
    return res[next(iter(res))]


def _check_file_ret(fret, ret, current):
    if fret["result"] is False:
        ret["result"] = False
        ret["comment"] = (
            f"Could not {'create' if not current else 'update'} file, see file.managed output"
        )
        ret["changes"] = {}
        return False
    return True
