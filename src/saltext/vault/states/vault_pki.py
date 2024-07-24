"""
Manage the Vault PKI secret engine.

.. versionadded:: 1.1.0

.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import base64
import logging
import os

import salt.utils.files
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError

from saltext.vault.utils.vault.helpers import filter_state_internal_kwargs
from saltext.vault.utils.vault.helpers import timestring_map
from saltext.vault.utils.vault.pki import check_cert_for_changes

try:
    import salt.utils.x509 as x509util

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


log = logging.getLogger(__name__)

__virtualname__ = "vault_pki"


def __virtual__():
    if "x509.encode_certificate" not in __salt__:
        return (
            False,
            "x509_v2 needs to be explicitly enabled by setting `x509_v2: true` "
            "in the minion configuration value `features` until Salt 3008 (Argon).",
        )
    if not HAS_CRYPTOGRAPHY:
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
        Check `this issue <https://github.com/hashicorp/vault/issues/20719>`__ for more information.

    Required policy:

    .. code-block:: vaultpolicy

            # Need to read the role configuration in case of missing issuer_ref
            path "{mount}/roles/*" {
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
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

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
        If set to true will append CA chain to the certificate. Defaults to ``false``.

        .. note::
            This will append all CA certificates except self-signed (as they shouldn't be in the chain anyway)!

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
        Any other parameter accepted by ``file_managed`` execution module or Vault PKI
        :obj:`sign_certificate <saltext.vault.modules.vault_pki.sign_certificate>` execution module.
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
    file_args, cert_args = _split_file_kwargs(filter_state_internal_kwargs(kwargs))

    try:
        if encoding not in ["der", "pem", "pkcs7_der", "pkcs7_pem"]:
            raise SaltInvocationError(
                f"Invalid value '{encoding}' for encoding. Valid: der, pem, pkcs7_der, pkcs7_pem"
            )

        if timestring_map(ttl_remaining, cast=int) >= timestring_map(ttl, cast=int):
            raise SaltInvocationError("The ttl_remaning cannot be larger or equal to ttl.")

        # check file.managed changes early to avoid using unnecessary resources
        file_managed_test = _file_managed(name, test=True, replace=False, **file_args)
        if file_managed_test["result"] is False:
            ret["result"] = False
            ret["comment"] = "Problem while testing file.managed changes, see its output"
            _add_sub_state_run(ret, file_managed_test)
            return ret

        if "is not present and is not set for creation" in file_managed_test["comment"]:
            _add_sub_state_run(ret, file_managed_test)
            return ret

        # handle follow_symlinks
        if __salt__["file.is_link"](name):
            if file_args.get("follow_symlinks", True):
                name = os.path.realpath(name)
            else:
                # workaround https://github.com/saltstack/salt/issues/31802
                __salt__["file.remove"](name)
                changes["replaced"] = True

        replace = False
        file_exists = __salt__["file.file_exists"](name)

        if issuer_ref is None:
            issuer_ref = __salt__["vault_pki.read_role"](role_name, mount=mount)["issuer_ref"]
            if issuer_ref is None:
                raise CommandExecutionError(f"role {role_name} does not exists.")

        issuer_info = __salt__["vault_pki.read_issuer"](issuer_ref, mount=mount)

        if append_ca_chain:
            ca_chain = [x509util.load_cert(x) for x in issuer_info["ca_chain"]]

        if file_exists:
            if reissue:
                # No need to make any checks, just replace the cert
                changes["replaced"] = True
            else:

                changes = check_cert_for_changes(
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
                    append_certs=ca_chain if encoding in ["pem", "pkcs7_pem"] else [],
                    encoding=encoding,
                )

            ret["comment"] = f"The certificate has been {verb}d"

            if encoding not in ["pem", "pkcs7_pem"]:
                # file.managed does not support binary contents, so create
                # an empty file first (makedirs). This will not work with check_cmd!
                file_managed_ret = _file_managed(name, replace=False, **file_args)
                _add_sub_state_run(ret, file_managed_ret)
                if not _check_file_ret(file_managed_ret, ret, name):
                    return ret
                _safe_atomic_write(name, base64.b64decode(cert), file_args.get("backup", ""))

        if not changes or encoding in ["pem", "pkcs7_pem"]:
            replace = bool(encoding in ["pem", "pkcs7_pem"] and changes)
            contents = cert if replace else None
            file_managed_ret = _file_managed(name, contents=contents, replace=replace, **file_args)
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
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

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
        Any other parameter accepted by Vault
        :obj:`write_role <saltext.vault.modules.vault_pki.write_role>` execution module or Vault update role API method.
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
            if param in current and current[param] != arg:
                changed.update(
                    {
                        param: {
                            "old": current.get(param),
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
        The name of the role.

    mount
        The mount path the PKI backend is mounted to. Defaults to ``pki``.

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
            ret["comment"] = f"Role `{name}` is already absent."
            return ret

        ret["changes"]["deleted"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = f"PKI role `{name}` would have been deleted"
            return ret

        __salt__["vault_pki.delete_role"](name, mount=mount)

        ret["comment"] = f"Connection `{name}` has been deleted."

    except CommandExecutionError as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


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


def _file_managed(name, test=None, **kwargs):
    if test not in [None, True]:
        raise SaltInvocationError("test param can only be None or True")
    # work around https://github.com/saltstack/salt/issues/62590
    test = test or __opts__["test"]
    res = __salt__["state.single"]("file.managed", name, test=test, **kwargs)
    return res[next(iter(res))]


def _safe_atomic_write(dst, data, backup):
    """
    Create a temporary file with only user r/w perms and atomically
    copy it to the destination, honoring ``backup``.
    """
    tmp = salt.utils.files.mkstemp(prefix=salt.utils.files.TEMPFILE_PREFIX)
    with salt.utils.files.fopen(tmp, "wb") as tmp_:
        tmp_.write(data)
    salt.utils.files.copyfile(
        tmp, dst, __salt__["config.backup_mode"](backup), __opts__["cachedir"]
    )
    salt.utils.files.safe_rm(tmp)


def _check_file_ret(fret, ret, current):
    if fret["result"] is False:
        ret["result"] = False
        ret["comment"] = (
            f"Could not {'create' if not current else 'update'} file, see file.managed output"
        )
        ret["changes"] = {}
        return False
    return True
