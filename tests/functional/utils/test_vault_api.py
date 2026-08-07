from contextlib import suppress

import pytest
from saltfactories.utils import random_string

from saltext.vault.utils import vault
from tests.support.vault import vault_disable_auth_method
from tests.support.vault import vault_enable_auth_method
from tests.support.vault import vault_read

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container"),
]


@pytest.fixture
def fresh_auth_mount():
    name = random_string("fresh-mount", uppercase=False)
    vault_enable_auth_method("approle", name)
    try:
        yield name
    finally:
        vault_disable_auth_method(name)


@pytest.fixture
def approle_api(minion_opts):
    return vault.get_approle_api(minion_opts, {}, force_local=True)


def test_approle_api_list_empty_mount(approle_api, fresh_auth_mount):
    assert approle_api.list_approles(mount=fresh_auth_mount) == []


@pytest.fixture
def role_name(approle_api, fresh_auth_mount):
    name = random_string("test-role-", uppercase=False)
    approle_api.write_approle(name, mount=fresh_auth_mount, token_ttl="10m", token_policies=["foo"])
    return name


def test_approle_api_write_and_read_approle(approle_api, fresh_auth_mount, role_name):
    assert role_name in approle_api.list_approles(mount=fresh_auth_mount)
    res = approle_api.read_approle(role_name, mount=fresh_auth_mount)
    assert res["token_ttl"] == 600
    assert res["token_policies"] == ["foo"]
    approle_api.write_approle(
        role_name, mount=fresh_auth_mount, token_ttl="20m", token_policies=["foo", "bar"]
    )
    res = approle_api.read_approle(role_name, mount=fresh_auth_mount)
    assert res["token_ttl"] == 1200
    assert res["token_policies"] == ["foo", "bar"]


def test_approle_api_delete_approle(approle_api, fresh_auth_mount, role_name):
    approle_api.delete_approle(role_name, mount=fresh_auth_mount)
    assert role_name not in approle_api.list_approles(mount=fresh_auth_mount)
    with pytest.raises(vault.VaultNotFoundError):
        approle_api.read_approle(role_name, mount=fresh_auth_mount)


@pytest.mark.parametrize("wrap", (False, "30s"))
def test_approle_api_read_role_id(approle_api, fresh_auth_mount, role_name, wrap):
    res = approle_api.read_role_id(role_name, mount=fresh_auth_mount, wrap=wrap)
    if wrap:
        assert isinstance(res, vault.VaultWrappedResponse)
        res = approle_api.client.unwrap(
            res,
            expected_creation_path=f"auth/{fresh_auth_mount}/role/{role_name}/role-id",
        )["data"]["role_id"]
    expected = vault_read(f"auth/{fresh_auth_mount}/role/{role_name}/role-id")["data"]["role_id"]
    assert res == expected


@pytest.mark.parametrize("wrap", (False, "30s"))
def test_approle_api_generate_secret_id(approle_api, fresh_auth_mount, role_name, wrap):
    res = approle_api.generate_secret_id(
        role_name,
        mount=fresh_auth_mount,
        metadata={"foo": "bar"},
        num_uses=3,
        ttl="10m",
        wrap=wrap,
    )
    if wrap:
        assert isinstance(res, vault.VaultWrappedResponse)
        secret_id = approle_api.client.unwrap(
            res,
            expected_creation_path=f"auth/{fresh_auth_mount}/role/{role_name}/secret-id",
        )["data"]["secret_id"]
    else:
        assert isinstance(res, vault.VaultSecretId)
        assert res.is_valid()
        secret_id = str(res)
    info = approle_api.read_secret_id(role_name, mount=fresh_auth_mount, secret_id=secret_id)
    assert info["metadata"] == {"foo": "bar"}
    assert info["secret_id_num_uses"] == 3
    assert info["secret_id_ttl"] == 600


def test_approle_api_read_secret_id_by_accessor(approle_api, fresh_auth_mount, role_name):
    secret_id = approle_api.generate_secret_id(role_name, mount=fresh_auth_mount)
    info = approle_api.read_secret_id(
        role_name, mount=fresh_auth_mount, accessor=secret_id.accessor
    )
    assert info["secret_id_accessor"] == secret_id.accessor


def test_approle_api_read_secret_id_missing(approle_api, fresh_auth_mount, role_name):
    with pytest.raises(vault.VaultNotFoundError):
        approle_api.read_secret_id(role_name, mount=fresh_auth_mount, secret_id="nonexistent")


@pytest.mark.parametrize("by", ("secret_id", "accessor"))
def test_approle_api_destroy_secret_id(approle_api, fresh_auth_mount, role_name, by):
    secret_id = approle_api.generate_secret_id(role_name, mount=fresh_auth_mount)
    kwargs = {by: str(secret_id) if by == "secret_id" else secret_id.accessor}
    approle_api.destroy_secret_id(role_name, mount=fresh_auth_mount, **kwargs)
    with pytest.raises(vault.VaultNotFoundError):
        approle_api.read_secret_id(role_name, mount=fresh_auth_mount, secret_id=str(secret_id))


@pytest.fixture
def identity_api(minion_opts):
    return vault.get_identity_api(minion_opts, {}, force_local=True)


@pytest.fixture
def entity(identity_api):
    name = random_string("test-entity-", uppercase=False)
    identity_api.write_entity(name, metadata={"foo": "bar"})
    try:
        yield name
    finally:
        with suppress(vault.VaultException):
            identity_api.delete_entity(name)


def test_identity_list_entities(identity_api, entity):
    assert entity in identity_api.list_entities()


def test_identity_list_entities_none_exist(identity_api):
    # The identity store is global and shared between test modules,
    # so ensure it is empty first.
    for name in identity_api.list_entities():
        identity_api.delete_entity(name)
    assert identity_api.list_entities() == []


def test_identity_write_and_read_entity(identity_api, entity):
    res = identity_api.read_entity(entity)
    assert res["name"] == entity
    assert res["metadata"] == {"foo": "bar"}
    identity_api.write_entity(entity, metadata={"foo": "baz"}, policies=["entity_policy"])
    res = identity_api.read_entity(entity)
    assert res["metadata"] == {"foo": "baz"}
    assert res["policies"] == ["entity_policy"]


def test_identity_read_entity_by_id(identity_api, entity):
    entity_id = identity_api.read_entity(entity)["id"]
    res = identity_api.read_entity_by_id(entity_id)
    assert res["name"] == entity


def test_identity_read_entity_by_alias(identity_api, entity, approle):
    identity_api.write_entity_alias(entity, alias_name=approle["role_id"], mount=approle["mount"])
    res = identity_api.read_entity_by_alias(alias=approle["role_id"], mount=approle["mount"])
    assert res["name"] == entity


def test_identity_read_entity_by_alias_missing(identity_api, approle):
    with pytest.raises(vault.VaultNotFoundError):
        identity_api.read_entity_by_alias(alias="unknown-alias", mount=approle["mount"])


def test_identity_delete_entity(identity_api, entity):
    identity_api.delete_entity(entity)
    assert entity not in identity_api.list_entities()
    with pytest.raises(vault.VaultNotFoundError):
        identity_api.read_entity(entity)


def test_identity_write_entity_alias(identity_api, entity, approle, fresh_auth_mount):
    """
    Ensure entity aliases are created as expected: An existing alias on the
    same mount is updated in place, aliases on other mounts are untouched.
    """
    identity_api.write_entity_alias(entity, alias_name="unrelated-alias", mount=fresh_auth_mount)
    aliases = identity_api.read_entity(entity)["aliases"]
    assert len(aliases) == 1
    # An alias on a different mount should be kept, a new one created
    identity_api.write_entity_alias(entity, alias_name=approle["role_id"], mount=approle["mount"])
    aliases = identity_api.read_entity(entity)["aliases"]
    assert len(aliases) == 2
    alias_id = next(a["id"] for a in aliases if a["name"] == approle["role_id"])
    # An existing alias on the same mount should be updated in place
    identity_api.write_entity_alias(
        entity,
        alias_name=approle["role_id"],
        mount=approle["mount"],
        custom_metadata={"created-by": "salt"},
    )
    aliases = identity_api.read_entity(entity)["aliases"]
    assert len(aliases) == 2
    updated = next(a for a in aliases if a["id"] == alias_id)
    assert updated["custom_metadata"] == {"created-by": "salt"}
