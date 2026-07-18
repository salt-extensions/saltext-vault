from pathlib import Path

import pytest

from tests.support.vault import vault_create_secret_id
from tests.support.vault import vault_delete
from tests.support.vault import vault_get_role_id
from tests.support.vault import vault_read
from tests.support.vault import vault_write

try:
    from cryptography.hazmat.primitives.serialization import SSHCertificate
    from cryptography.hazmat.primitives.serialization import SSHCertificateType
    from cryptography.hazmat.primitives.serialization import load_ssh_public_identity

    CERT_CHECK = True
except ImportError:
    CERT_CHECK = False

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "ca_setup", "roles_setup"),
]


@pytest.fixture(scope="module", autouse=True)
def check_ssh_pki_available(loaders):
    try:
        loaders.states.ssh_pki
    except AttributeError:
        # Salt < 3008
        pytest.skip("ssh_pki modules are not available")


@pytest.fixture(scope="module")
def entity_metadata():
    return {"bar": "bar"}


@pytest.fixture(scope="module")
def group1_metadata():
    return {"baz": "baz"}


@pytest.fixture(scope="module")
def group2_metadata():
    return {"quux": "quux"}


@pytest.fixture(scope="module")
def entity(
    entity_metadata, group1_metadata, group2_metadata, container
):  # pylint: disable=unused-argument
    """
    We need an entity with metadata to run principal templating tests.
    """
    # need to depend on container for this fixture to be rerun when parametrizing container
    try:
        entity = vault_write("identity/entity", metadata=entity_metadata)
        group1 = vault_write(
            "identity/group",
            name="group1",
            metadata=group1_metadata,
            member_entity_ids=[entity["data"]["id"]],
        )
        group2 = vault_write(
            "identity/group",
            name="group2",
            metadata=group2_metadata,
            member_entity_ids=[entity["data"]["id"]],
        )
        vault_write("auth/salt-minions/role/foobar", token_policies=["ssh_admin"])
        mount = vault_read("sys/auth/salt-minions")
        role_id = vault_get_role_id("foobar", "salt-minions")
        alias = vault_write(
            "identity/entity-alias",
            name=role_id,
            canonical_id=entity["data"]["id"],
            mount_accessor=mount["data"]["accessor"],
        )
        secret_id = vault_create_secret_id("foobar", "salt-minions")
        yield {
            "role_id": role_id,
            "secret_id": secret_id,
            "entity_id": entity["data"]["id"],
            "group1_id": group1["data"]["id"],
            "group2_id": group2["data"]["id"],
        }
    finally:
        try:
            vault_delete("identity/entity-alias/id/" + alias["data"]["id"], silent=True)
        except UnboundLocalError:
            pass
        vault_delete("auth/salt-minions/role/foobar", silent=True)
        try:
            vault_delete("identity/group/id/" + group1["data"]["id"], silent=True)
        except UnboundLocalError:
            pass
        try:
            vault_delete("identity/group/id/" + group2["data"]["id"], silent=True)
        except UnboundLocalError:
            pass
        try:
            vault_delete("identity/entity/id/" + entity["data"]["id"], silent=True)
        except UnboundLocalError:
            pass


@pytest.fixture(scope="module")
def minion_config_overrides(entity):
    return {
        "vault": {
            "auth": {
                "method": "approle",
                "role_id": entity["role_id"],
                "secret_id": entity["secret_id"],
                "approle_mount": "salt-minions",
            }
        }
    }


@pytest.fixture
def cert_managed(loaders):
    return loaders.states.ssh_pki.certificate_managed


@pytest.fixture
def user_args(tmp_path, ec_priv_file, request):
    defaults = {
        "name": f"{tmp_path}/cert",
        "cert_type": "user",
        "valid_principals": ["foo"],
        "private_key": ec_priv_file,
        "backend": "vault_ssh",
        "signing_policy": "userrole",
        "ttl_remaining": 600,
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


@pytest.fixture
def host_args(tmp_path, ec_priv_file, request):
    defaults = {
        "name": f"{tmp_path}/cert",
        "cert_type": "host",
        "valid_principals": ["foo.bar.baz"],
        "private_key": ec_priv_file,
        "backend": "vault_ssh",
        "signing_policy": "hostrole",
        "ttl": 86400,
        "ttl_remaining": 3600,
    }
    defaults.update(getattr(request, "param", {}))
    return defaults


@pytest.fixture
def existing_cert(cert_managed, request, roles_setup, ca_setup):  # pylint: disable=unused-argument
    if request.function.__name__.startswith("test_user"):
        args = request.getfixturevalue("user_args")
    else:
        args = request.getfixturevalue("host_args")
    _manage(cert_managed, args)
    yield args["name"]


def _manage(cert_managed, args, exp=True, cert_type=None):
    cert_type = cert_type or args["cert_type"]
    ret = cert_managed(**args)
    cert = None
    assert ret.result is exp
    if not exp:
        return ret
    assert Path(args["name"]).exists()
    if CERT_CHECK:
        cert = _get_cert(args["name"])
        assert (
            cert.type == SSHCertificateType.USER if cert_type == "user" else SSHCertificateType.HOST
        )
    return ret, cert


def _requires_ca(cert_managed, args, exp):
    args["signing_policy"] = "iprole"
    ret = cert_managed(**args)
    assert ret.result is False
    assert exp in ret.comment
    assert not ret.changes


def test_requires_ca_new(cert_managed, host_args):
    # Hits sign_key directly
    _requires_ca(cert_managed, host_args, "not allowed by role")


@pytest.mark.usefixtures("existing_cert")
def test_requires_ca_existing(cert_managed, host_args):
    # Hits get_signing_policy first
    _requires_ca(cert_managed, host_args, "not a CA role")


def _basic(cert_managed, args):
    _manage(cert_managed, args)
    ret = cert_managed(**args)
    assert ret.result is True
    assert not ret.changes


def test_user_basic(cert_managed, user_args):
    _basic(cert_managed, user_args)


def test_host_basic(cert_managed, host_args):
    _basic(cert_managed, host_args)


def _principal_change(cert_managed, args, old, new, typ):
    args["valid_principals"] = [new]
    ret, cert = _manage(cert_managed, args, cert_type=typ)
    assert ret.changes == {"principals": {"added": [new], "removed": [old]}}
    assert cert.valid_principals == [new.encode()]


@pytest.mark.usefixtures("existing_cert")
def test_user_principal_change(cert_managed, user_args):
    user_args.pop("cert_type")  # also test autodetermination of cert type
    _principal_change(cert_managed, user_args, "foo", "bar", "user")


@pytest.mark.usefixtures("existing_cert")
def test_host_principal_change(cert_managed, host_args):
    host_args.pop("cert_type")  # also test autodetermination of cert type
    _principal_change(cert_managed, host_args, "foo.bar.baz", "foo.bar.quux", "host")


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    (
        {
            "userrole": {
                "allowed_users_template": True,
                "allowed_users": "foo,foo-{{identity.entity.metadata.bar}}",
            }
        },
    ),
    indirect=True,
)
def test_user_principal_templated(cert_managed, user_args):
    """
    Ensure stateful management works with templated users.
    Note: This behaves slightly different than usual since we cannot filter invalid principals.
    """
    # ensure new principals are applied and reported about successfully
    user_args["valid_principals"] = ["foo", "foo-bar"]
    ret, cert = _manage(cert_managed, user_args)
    assert ret.result is True
    assert ret.changes["principals"] == {"added": ["foo-bar"], "removed": []}
    assert cert.valid_principals == [b"foo", b"foo-bar"]
    # ensure stateful management works with templates
    ret, _ = _manage(cert_managed, user_args)
    assert ret.result is True
    assert not ret.changes
    # document that invalid principals cannot be filtered with templates
    user_args["valid_principals"] = ["foo", "foo-bar", "foo-invalid"]
    ret = _manage(cert_managed, user_args, False)
    assert "not a valid value for valid_principals" in ret.comment


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    (
        {
            "hostrole": {
                "allow_bare_domains": True,
                "allowed_domains_template": True,
                "allowed_domains": "foo.bar.baz,foo.{{identity.entity.metadata.bar}}.quux",
            }
        },
    ),
    indirect=True,
)
def test_host_principal_templated(cert_managed, host_args):
    """
    Ensure stateful management works with templated domains.
    Note: This behaves slightly different than usual since we cannot filter invalid principals.
    """
    # ensure new principals are applied and reported about successfully
    host_args["valid_principals"] = ["foo.bar.baz", "foo.bar.quux"]
    ret, cert = _manage(cert_managed, host_args)
    assert ret.result is True
    assert ret.changes["principals"] == {"added": ["foo.bar.quux"], "removed": []}
    assert cert.valid_principals == [b"foo.bar.baz", b"foo.bar.quux"]
    # ensure stateful management works with templates
    ret, _ = _manage(cert_managed, host_args)
    assert ret.result is True
    assert not ret.changes
    # document that invalid principals cannot be filtered with templates
    host_args["valid_principals"] = ["foo.bar.baz", "foo.bar.quux", "foo.bar.invalid"]
    ret = _manage(cert_managed, host_args, False)
    assert "not a valid value for valid_principals" in ret.comment


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"allow_subdomains": True, "allowed_domains": "bar.baz"}},),
    indirect=True,
)
def test_host_principal_allow_subdomains(cert_managed, host_args):
    """
    Ensure stateful management works with enabled subdomains.
    Note: This behaves slightly different than usual since we cannot filter invalid principals.
    """
    # ensure new principals are applied and reported about successfully
    host_args["valid_principals"] = ["foo.bar.baz", "bar.bar.baz"]
    ret, cert = _manage(cert_managed, host_args)
    assert ret.result is True
    assert ret.changes["principals"] == {"added": ["bar.bar.baz"], "removed": []}
    assert cert.valid_principals == [b"bar.bar.baz", b"foo.bar.baz"]
    # ensure stateful management works with templates
    ret, _ = _manage(cert_managed, host_args)
    assert ret.result is True
    assert not ret.changes
    # document that invalid principals cannot be filtered with templates
    host_args["valid_principals"] = ["foo.bar.baz", "bar.bar.baz", "foo.bar.invalid"]
    ret = _manage(cert_managed, host_args, False)
    assert "not a valid value for valid_principals" in ret.comment


def _principal_invalid(cert_managed, args):
    """
    When creating a new certificate, requesting invalid principals results in an error.
    """
    ret = _manage(cert_managed, args, False)
    assert "not a valid value" in ret.comment
    assert not ret.changes


@pytest.mark.parametrize("roles_setup", ({"userrole": {"allowed_users": "foo"}},), indirect=True)
def test_user_principal_invalid(cert_managed, user_args):
    user_args["valid_principals"] = ["bar"]
    _principal_invalid(cert_managed, user_args)


@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"allowed_domains": "foo.bar.baz", "allow_bare_domains": True}},),
    indirect=True,
)
def test_host_principal_invalid(cert_managed, host_args):
    host_args["valid_principals"] = ["foo.bar.quux"]
    _principal_invalid(cert_managed, host_args)


def _principal_existing_all_invalid(cert_managed, args):
    """
    When checking for changes on an existing certificate, requesting ONLY invalid principals
    results in an error.
    """
    ret = _manage(cert_managed, args, False)
    assert "principals to allow" in ret.comment
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize("roles_setup", ({"userrole": {"allowed_users": "foo"}},), indirect=True)
def test_user_principal_existing_all_invalid(cert_managed, user_args):
    user_args["valid_principals"] = ["bar"]
    _principal_existing_all_invalid(cert_managed, user_args)


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"allowed_domains": "foo.bar.baz", "allow_bare_domains": True}},),
    indirect=True,
)
def test_host_principal_existing_all_invalid(cert_managed, host_args):
    host_args["valid_principals"] = ["foo.bar.quux"]
    _principal_existing_all_invalid(cert_managed, host_args)


def _principal_existing_some_valid(cert_managed, args, existing, invalid, new_valid):
    """
    When checking for changes on an existing certificate, invalid principals are
    filtered silently. This is how the regular ssh_pki execution module would behave.
    This only works because the existing certificate matches the expection.
    When reiussed, Vault still throws an error, failing the state.
    """
    args["valid_principals"] = [existing, invalid]
    ret, cert = _manage(cert_managed, args)
    assert "correct state" in ret.comment
    assert not ret.changes
    assert cert.valid_principals == [existing.encode()]
    args["valid_principals"].append(new_valid)
    ret = _manage(cert_managed, args, False)
    assert "not a valid value for valid_principals" in ret.comment


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup", ({"userrole": {"allowed_users": "foo,baz"}},), indirect=True
)
def test_user_principal_override_existing_some_valid(cert_managed, user_args):
    _principal_existing_some_valid(cert_managed, user_args, "foo", "bar", "baz")


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"allowed_domains": "foo.bar.baz,foo.bar.bar", "allow_bare_domains": True}},),
    indirect=True,
)
def test_host_principal_override_existing_some_valid(cert_managed, host_args):
    _principal_existing_some_valid(
        cert_managed, host_args, "foo.bar.baz", "foo.bar.quux", "foo.bar.bar"
    )


@pytest.mark.parametrize(
    "roles_setup",
    ({"userrole": {"allowed_users": "default_principal", "default_user": "default_principal"}},),
    indirect=True,
)
def test_user_default_principal(cert_managed, user_args):
    """
    Ensure we don't need to specify principals for user certificates.
    """
    user_args.pop("valid_principals")
    _, cert = _manage(cert_managed, user_args)
    assert cert.valid_principals == [b"default_principal"]
    ret, _ = _manage(cert_managed, user_args)
    assert not ret.changes


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    (
        {
            "userrole": {
                "allowed_users": "foo,default_principal",
                "default_user": "default_principal",
            }
        },
    ),
    indirect=True,
)
def test_user_default_principal_change(cert_managed, user_args):
    """
    Ensure default_user is detected and reported.
    """
    user_args.pop("valid_principals")
    ret, cert = _manage(cert_managed, user_args)
    assert ret.changes["principals"] == {"added": ["default_principal"], "removed": ["foo"]}
    assert cert.valid_principals == [b"default_principal"]


@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"allowed_domains": "foo.bar.baz", "allow_bare_domains": True}},),
    indirect=True,
)
def test_host_default_principal(cert_managed, host_args, container):
    """
    Host certificates do not have an equivalent to default_user and require valid_principals to be specified.
    """
    host_args.pop("valid_principals")
    ret = _manage(cert_managed, host_args, False)
    if "openbao" in container:
        assert "globally-valid certificate with no principals specified" in ret.comment
    else:
        assert "empty valid principals not allowed by role" in ret.comment


def _default_opts_exts_override(cert_managed, args, typ):
    """
    Ensure default opts/exts are present in the issued certificate when overrides
    are specified. This contrasts with Vault's usual behavior of dropping all
    default_extensions/default_critical_options when values are specified for extensions/critical_options.
    """
    args[typ] = {"foobar": "baz", "quux": True}
    ret, cert = _manage(cert_managed, args)
    assert ret.changes
    assert getattr(cert, typ) == {b"foobar": b"baz", b"quux": b"", b"keepme": b""}
    # ensure idempotency
    ret, cert = _manage(cert_managed, args)
    assert not ret.changes


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "roles_setup",
    ({"userrole": {"default_critical_options": {"foobar": "foo", "keepme": ""}}},),
    indirect=True,
)
def test_user_default_options_override(cert_managed, user_args):
    _default_opts_exts_override(cert_managed, user_args, "critical_options")


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "roles_setup",
    ({"userrole": {"default_extensions": {"foobar": "foo", "keepme": ""}}},),
    indirect=True,
)
def test_user_default_extensions_override(cert_managed, user_args):
    _default_opts_exts_override(cert_managed, user_args, "extensions")


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"default_critical_options": {"foobar": "foo", "keepme": ""}}},),
    indirect=True,
)
def test_host_default_options_override(cert_managed, host_args):
    _default_opts_exts_override(cert_managed, host_args, "critical_options")


@pytest.mark.usefixtures("roles_setup")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"default_extensions": {"foobar": "foo", "keepme": ""}}},),
    indirect=True,
)
def test_host_default_extensions_override(cert_managed, host_args):
    _default_opts_exts_override(cert_managed, host_args, "extensions")


def _default_opts_exts_change(cert_managed, args, roles_setup, cert_typ, typ):
    """
    Ensure default opts/exts are handled and reported about as expected.
    """
    # change default to check if that's detected
    role = roles_setup[f"{cert_typ}role"]
    role[f"default_{typ}"] = {"foobar": "baz", "quux": ""}
    vault_write(f"ssh/roles/{cert_typ}role", **role)
    ret, cert = _manage(cert_managed, args)
    assert ret.changes[typ] == {"added": ["quux"], "changed": ["foobar"], "removed": ["removeme"]}
    assert getattr(cert, typ) == {b"foobar": b"baz", b"quux": b""}
    # check default override keeps defaults, but allows to unset them
    # (Vault does not keep defaults when overrides are specified, this is ssh_pki behavior specifically)
    args[typ] = {"foobar": "foo", "added": True, "quux": False}
    ret, cert = _manage(cert_managed, args)
    assert ret.changes[typ] == {"added": ["added"], "changed": ["foobar"], "removed": ["quux"]}
    assert getattr(cert, typ) == {b"foobar": b"foo", b"added": b""}


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"userrole": {"default_critical_options": {"foobar": "foo", "removeme": ""}}},),
    indirect=True,
)
def test_user_default_options_change(cert_managed, user_args, roles_setup):
    _default_opts_exts_change(cert_managed, user_args, roles_setup, "user", "critical_options")


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"userrole": {"default_extensions": {"foobar": "foo", "removeme": ""}}},),
    indirect=True,
)
def test_user_default_extensions_change(cert_managed, user_args, roles_setup):
    _default_opts_exts_change(cert_managed, user_args, roles_setup, "user", "extensions")


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"default_critical_options": {"foobar": "foo", "removeme": ""}}},),
    indirect=True,
)
def test_host_default_options_change(cert_managed, host_args, roles_setup):
    _default_opts_exts_change(cert_managed, host_args, roles_setup, "host", "critical_options")


@pytest.mark.usefixtures("existing_cert")
@pytest.mark.parametrize(
    "roles_setup",
    ({"hostrole": {"default_extensions": {"foobar": "foo", "removeme": ""}}},),
    indirect=True,
)
def test_host_default_extensions_change(cert_managed, host_args, roles_setup):
    _default_opts_exts_change(cert_managed, host_args, roles_setup, "host", "extensions")


def _default_exts_templated(cert_managed, args, cert_typ, roles_setup, entity):
    """
    Show that enabling ``default_extensions_template`` works because we can render templates.
    This relies on being able to read one's own entity id.
    """
    # Ensure we test referencing groups both by name and by id
    role = roles_setup[
        f"{cert_typ}role"
    ].copy()  # Copying because there was leakage between tests somehow
    role["default_extensions"] = role["default_extensions"].copy()
    role["default_extensions"][
        "foobar"
    ] += f"{{{{identity.groups.ids.{entity['group2_id']}.metadata.quux}}}}"
    vault_write(f"ssh/roles/{cert_typ}role", **role)
    ret, cert = _manage(cert_managed, args)
    assert getattr(cert, "extensions") == {b"foobar": b"foo-bar-baz-quux"}
    # Show idempotency
    ret, cert = _manage(cert_managed, args)
    assert not ret.changes
    # When we don't have permission or fail otherwise, we report the wrong changes and are not idempotent,
    # but the resulting extensions are still fine.
    # assert ret.changes == {"extensions": {"added": [], "changed": [], "removed": ["foobar"]}}
    assert getattr(cert, "extensions") == {b"foobar": b"foo-bar-baz-quux"}
    # Show that overrides merge with defaults.
    args["extensions"] = {"new": "value"}
    ret, cert = _manage(cert_managed, args)
    assert ret.changes == {"extensions": {"added": ["new"], "changed": [], "removed": []}}
    assert getattr(cert, "extensions") == {b"new": b"value", b"foobar": b"foo-bar-baz-quux"}
    # When we don't have permission or fail otherwise, we don't merge the defaults.
    # assert ret.changes == {"extensions": {"added": ["new"], "changed": [], "removed": ["foobar"]}}
    # assert getattr(cert, "extensions") == {b"new": b"value"}
    ret, _ = _manage(cert_managed, args)
    assert not ret.changes
    # Both ways are consistent here, just that one misses the default


@pytest.mark.parametrize(
    "roles_setup",
    (
        {
            "userrole": {
                "default_extensions_template": True,
                "default_extensions": {
                    "foobar": "foo-{{identity.entity.metadata.bar}}-{{identity.groups.names.group1.metadata.baz}}-"
                },
            }
        },
    ),
    indirect=True,
)
def test_user_default_exts_templated(cert_managed, user_args, roles_setup, entity):
    _default_exts_templated(cert_managed, user_args, "user", roles_setup, entity)


@pytest.mark.parametrize(
    "roles_setup",
    (
        {
            "hostrole": {
                "default_extensions_template": True,
                "default_extensions": {
                    "foobar": "foo-{{identity.entity.metadata.bar}}-{{identity.groups.names.group1.metadata.baz}}-"
                },
            }
        },
    ),
    indirect=True,
)
def test_host_default_exts_templated(cert_managed, host_args, roles_setup, entity):
    _default_exts_templated(cert_managed, host_args, "host", roles_setup, entity)


def _key_id(cert_managed, args, roles_setup, cert_typ):
    """
    Ensure setting key_id is handled correctly.
    """
    # check that overrides are skipped when allow_user_key_ids is not set
    args["key_id"] = "foobar"
    ret, cert = _manage(cert_managed, args)
    assert not ret.changes
    # now allow it
    role = roles_setup[f"{cert_typ}role"]
    role["allow_user_key_ids"] = True
    vault_write(f"ssh/roles/{cert_typ}role", **role)
    ret, cert = _manage(cert_managed, args)
    assert ret.changes["key_id"]["new"] == "foobar"
    assert ret.changes["key_id"]["old"].startswith("vault-")
    assert cert.key_id == b"foobar"


@pytest.mark.usefixtures("existing_cert")
def test_user_key_id(cert_managed, user_args, roles_setup):
    _key_id(cert_managed, user_args, roles_setup, "user")


@pytest.mark.usefixtures("existing_cert")
def test_host_key_id(cert_managed, host_args, roles_setup):
    _key_id(cert_managed, host_args, roles_setup, "host")


def _get_cert(cert):
    try:
        p = Path(cert)
        if p.exists():
            cert = p.read_bytes()
    except Exception:  # pylint: disable=broad-except
        pass
    if isinstance(cert, str):
        cert = cert.encode()
    ret = load_ssh_public_identity(cert)
    if not isinstance(ret, SSHCertificate):
        raise ValueError(f"Expected SSHCertificate, got {ret.__class__.__name__}")
    return ret
