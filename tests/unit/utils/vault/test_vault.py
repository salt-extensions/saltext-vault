from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

from saltext.vault.utils import vault
from saltext.vault.utils.vault import client as vclient
from saltext.vault.utils.vault import kv as vkv

# Maps the utility functions to the corresponding VaultKV method and arguments
KV_FUNCS = (
    ("read_kv", "read", ("secret/path",)),
    ("read_kv_meta", "read_meta", ("secret/path",)),
    ("write_kv", "write", ("secret/path", {"foo": "bar"})),
    ("patch_kv", "patch", ("secret/path", {"foo": "bar"})),
    ("delete_kv", "delete", ("secret/path",)),
    ("restore_kv", "restore", ("secret/path",)),
    ("destroy_kv", "destroy", ("secret/path", [1])),
    ("wipe_kv", "nuke", ("secret/path",)),
    ("list_kv", "list", ("secret/path",)),
)


@pytest.fixture
def config():
    return {"cache": {"clear_on_unauthorized": True}}


@pytest.fixture
def client():
    _client = Mock(spec=vclient.AuthenticatedVaultClient)
    _client.token_valid.return_value = True
    return _client


@pytest.fixture
def kv(client):
    _kv = Mock(spec=vkv.VaultKV)
    _kv.client = client
    return _kv


@pytest.fixture
def get_authd_client(client, config):
    def _get(
        opts, context, *, force_local=False, get_config=False
    ):  # pylint: disable=unused-argument
        if get_config:
            return client, config
        return client

    with patch(
        "saltext.vault.utils.vault.get_authd_client", autospec=True, side_effect=_get
    ) as _get_authd_client:
        yield _get_authd_client


@pytest.fixture
def get_kv(kv, config):
    def _get(opts, context, *, get_config=False):  # pylint: disable=unused-argument
        if get_config:
            return kv, config
        return kv

    with patch("saltext.vault.utils.vault.get_kv", autospec=True, side_effect=_get) as _get_kv:
        yield _get_kv


@pytest.fixture
def clear_cache():
    with patch("saltext.vault.utils.vault.clear_cache", autospec=True) as _clear_cache:
        yield _clear_cache


@pytest.mark.parametrize(
    "check_clear_cause", ("clear_on_unauthorized", "invalid_token", "auth_expired")
)
def test_query_retries_with_cleared_cache(
    get_authd_client, client, config, clear_cache, check_clear_cause
):
    """
    A permission denied error should cause ``query`` to clear the cache and
    retry with a new client when ``clear_on_unauthorized`` is set or the
    current token is not reported as valid anymore.
    """
    opts = {"conf": "opts"}
    context = {"conf": "context"}
    config["cache"]["clear_on_unauthorized"] = check_clear_cause == "clear_on_unauthorized"
    if check_clear_cause == "invalid_token":
        client.token_valid.return_value = False
    elif check_clear_cause == "auth_expired":
        client.token_valid.side_effect = vault.VaultAuthExpired("expired")
    client.request.side_effect = (
        vault.VaultPermissionDeniedError("permission denied"),
        {"data": {"foo": "bar"}},
    )
    res = vault.query("GET", "secret/path", opts, context)
    assert res == {"data": {"foo": "bar"}}
    clear_cache.assert_called_once_with(opts, context)
    assert client.request.call_count == 2
    assert client.request.call_args_list[0] == client.request.call_args_list[1]
    assert get_authd_client.call_count == 2


@pytest.mark.usefixtures("get_authd_client")
def test_query_raises_permission_denied(client, config, clear_cache):
    """
    A permission denied error should be raised by ``query`` when
    ``clear_on_unauthorized`` is unset and the current token is
    still reported as valid.
    """
    config["cache"]["clear_on_unauthorized"] = False
    client.request.side_effect = vault.VaultPermissionDeniedError("permission denied")
    with pytest.raises(vault.VaultPermissionDeniedError, match="permission denied"):
        vault.query("GET", "secret/path", {}, {})
    client.token_valid.assert_called_once_with(remote=True)
    client.request.assert_called_once()
    clear_cache.assert_not_called()


def test_query_raw_retries_with_cleared_cache(get_authd_client, client, clear_cache):
    """
    A permission denied response should cause ``query_raw`` to clear the
    cache and retry with a new client when ``clear_on_unauthorized`` is set.
    """
    opts = {"conf": "opts"}
    context = {"conf": "context"}
    denied = Mock(spec=requests.Response, status_code=403)
    success = Mock(spec=requests.Response, status_code=200)
    client.request_raw.side_effect = (denied, success)
    res = vault.query_raw("GET", "secret/path", opts, context)
    assert res is success
    clear_cache.assert_called_once_with(opts, context)
    assert client.request_raw.call_count == 2
    assert client.request_raw.call_args_list[0] == client.request_raw.call_args_list[1]
    assert get_authd_client.call_count == 2


def test_query_raw_does_not_retry_other_status_codes(get_authd_client, client, clear_cache):
    """
    An error other than permission denied should not cause ``query_raw`` to clear the
    cache and retry with a new client when ``clear_on_unauthorized`` is set.
    """
    missing = Mock(spec=requests.Response, status_code=404)
    success = Mock(spec=requests.Response, status_code=200)
    client.request_raw.side_effect = (missing, success)
    res = vault.query_raw("GET", "secret/path", {}, {})
    assert res is missing
    clear_cache.assert_not_called()
    assert client.request_raw.call_count == 1
    assert get_authd_client.call_count == 1


@pytest.mark.usefixtures("get_authd_client")
def test_query_raw_returns_denied_response(client, config, clear_cache):
    """
    A permission denied response should be returned by ``query_raw`` when
    ``clear_on_unauthorized`` is unset and the current token is still
    reported as valid.
    """
    config["cache"]["clear_on_unauthorized"] = False
    denied = Mock(spec=requests.Response, status_code=403)
    client.request_raw.return_value = denied
    res = vault.query_raw("GET", "secret/path", {}, {})
    assert res is denied
    client.token_valid.assert_called_once_with(remote=True)
    client.request_raw.assert_called_once()
    clear_cache.assert_not_called()


@pytest.mark.usefixtures("get_authd_client")
def test_query_raw_retry_can_be_disabled(client, clear_cache):
    """
    When ``retry`` is False, ``query_raw`` should return a permission denied
    response as-is, without considering a cache clear.
    """
    denied = Mock(spec=requests.Response, status_code=403)
    client.request_raw.return_value = denied
    res = vault.query_raw("GET", "secret/path", {}, {}, retry=False)
    assert res is denied
    client.request_raw.assert_called_once()
    client.token_valid.assert_not_called()
    clear_cache.assert_not_called()


@pytest.mark.usefixtures("get_kv")
@pytest.mark.parametrize("res", (False, True))
def test_is_v2(kv, res):
    kv.is_v2.return_value = res
    assert vault.is_v2("secret/path", {}, {}) is res


@pytest.mark.parametrize("func,method,args", KV_FUNCS)
def test_kv_funcs_retry_with_cleared_cache(get_kv, kv, clear_cache, func, method, args):
    """
    A permission denied error should cause the KV utility functions to clear
    the cache and retry with a new client when ``clear_on_unauthorized`` is set.
    """
    opts = {"conf": "opts"}
    context = {"conf": "context"}
    getattr(kv, method).side_effect = (
        vault.VaultPermissionDeniedError("permission denied"),
        "success",
    )
    res = getattr(vault, func)(*args, opts, context)
    assert res == "success"
    clear_cache.assert_called_once_with(opts, context)
    assert getattr(kv, method).call_count == 2
    assert getattr(kv, method).call_args_list[0] == getattr(kv, method).call_args_list[1]
    assert get_kv.call_count == 2


@pytest.mark.usefixtures("get_kv")
@pytest.mark.parametrize("func,method,args", KV_FUNCS)
def test_kv_funcs_raise_permission_denied(kv, config, clear_cache, func, method, args):
    """
    A permission denied error should be raised by the KV utility functions
    when ``clear_on_unauthorized`` is unset and the current token is
    still reported as valid.
    """
    config["cache"]["clear_on_unauthorized"] = False
    getattr(kv, method).side_effect = vault.VaultPermissionDeniedError("permission denied")
    with pytest.raises(vault.VaultPermissionDeniedError, match="permission denied"):
        getattr(vault, func)(*args, {}, {})
    kv.client.token_valid.assert_called_once_with(remote=True)
    getattr(kv, method).assert_called_once()
    clear_cache.assert_not_called()


def test_patch_kv_retries_on_auth_expired(get_kv, kv, clear_cache):
    """
    Patching can consume multiple token uses, which can result in an
    expired authentication mid-operation. It should be retried with a
    new client, without clearing the cache.
    """
    kv.patch.side_effect = (vault.VaultAuthExpired("expired"), "success")
    res = vault.patch_kv("secret/path", {"foo": "bar"}, {}, {})
    assert res == "success"
    assert kv.patch.call_count == 2
    assert kv.patch.call_args_list[0] == kv.patch.call_args_list[1]
    assert get_kv.call_count == 2
    clear_cache.assert_not_called()


@pytest.fixture
def entity_response():
    return {
        "id": "entity-uuid",
        "name": "salt_minion_test-minion",
        "metadata": {"minion-id": "test-minion"},
        "aliases": [
            {
                "mount_accessor": "auth_approle_abcd",
                "id": "alias-uuid",
                "name": "alias-name",
                "metadata": {"alias-meta": "alias-meta-val"},
                "custom_metadata": None,
            }
        ],
        "group_ids": ["group-uuid"],
    }


@pytest.fixture
def group_response():
    return {
        "id": "group-uuid",
        "name": "test-group",
        "metadata": {"group-meta": "group-meta-val"},
    }


@pytest.fixture
def identity_ctx(client, entity_response, group_response):
    client.token_entity.return_value = entity_response

    def _group(*, gid=None, name=None):
        if gid == group_response["id"] or name == group_response["name"]:
            return group_response
        return None

    client.token_entity_group.side_effect = _group
    return vault.LazyIdentityContext(client)


@pytest.mark.parametrize(
    "key,expected",
    (
        ("identity.entity.id", "entity-uuid"),
        ("identity.entity.name", "salt_minion_test-minion"),
        ("identity.entity.metadata.minion-id", "test-minion"),
        ("identity.entity.aliases.auth_approle_abcd.id", "alias-uuid"),
        ("identity.entity.aliases.auth_approle_abcd.name", "alias-name"),
        ("identity.entity.aliases.auth_approle_abcd.metadata.alias-meta", "alias-meta-val"),
        ("identity.groups.ids.group-uuid.name", "test-group"),
        ("identity.groups.ids.group-uuid.metadata.group-meta", "group-meta-val"),
        ("identity.groups.names.test-group.id", "group-uuid"),
        ("identity.groups.names.test-group.metadata.group-meta", "group-meta-val"),
    ),
)
def test_identity_ctx_getitem(identity_ctx, key, expected):
    assert identity_ctx[key] == expected


@pytest.mark.parametrize(
    "key",
    (
        42,
        "foo",
        "foo.bar",
        "identity.foo",
        "identity.entity.missing",
        "identity.entity.metadata",
        "identity.entity.metadata.missing",
        "identity.entity.aliases.auth_approle_abcd.custom_metadata.missing",
        "identity.groups.foo.group-uuid.name",
    ),
)
def test_identity_ctx_getitem_missing(identity_ctx, key):
    """
    Invalid keys should be reported as missing, including intermediate
    lookup results (only leaves are valid).
    """
    with pytest.raises(KeyError):
        identity_ctx[key]  # pylint: disable=pointless-statement


def test_identity_ctx_is_lazy_and_caches(identity_ctx, client):
    """
    Entity and group data should only be requested when actually
    accessed and at most once. A group initialized by ID should not
    be requested again when accessed by name (and vice versa).
    """
    client.token_entity.assert_not_called()
    assert identity_ctx["identity.entity.id"] == "entity-uuid"
    assert identity_ctx["identity.entity.name"] == "salt_minion_test-minion"
    client.token_entity.assert_called_once()
    client.token_entity_group.assert_not_called()
    assert identity_ctx["identity.groups.ids.group-uuid.name"] == "test-group"
    assert identity_ctx["identity.groups.ids.group-uuid.metadata.group-meta"] == "group-meta-val"
    assert identity_ctx["identity.groups.names.test-group.id"] == "group-uuid"
    client.token_entity_group.assert_called_once_with(gid="group-uuid")
    # Iteration should not cause any refetches either
    list(identity_ctx)
    client.token_entity.assert_called_once()
    client.token_entity_group.assert_called_once()


def test_identity_ctx_missing_entity(identity_ctx, client):
    client.token_entity.return_value = None
    with pytest.raises(RuntimeError, match="no associated entity"):
        identity_ctx["identity.entity.id"]  # pylint: disable=pointless-statement


@pytest.mark.parametrize(
    "key",
    ("identity.groups.ids.unknown-uuid.name", "identity.groups.names.unknown-group.id"),
)
def test_identity_ctx_unknown_group(identity_ctx, key):
    with pytest.raises(RuntimeError, match="not part of group unknown"):
        identity_ctx[key]  # pylint: disable=pointless-statement


def test_identity_ctx_init_group_requires_name_or_gid(identity_ctx):
    with pytest.raises(TypeError, match="Need name or gid"):
        identity_ctx._init_group()


def test_identity_ctx_init_all_groups_initializes_entity(identity_ctx, client):
    """
    When groups are initialized before anything else has been accessed,
    the entity needs to be fetched first to discover associated group IDs.
    """
    identity_ctx._init_all_groups()
    client.token_entity.assert_called_once()
    client.token_entity_group.assert_called_once_with(gid="group-uuid")


def test_identity_ctx_iter_and_len(identity_ctx):
    """
    Iteration should initialize the entity and all associated groups,
    yielding flattened (dotted) keys for all leaf values.
    """
    expected = [
        "identity.entity.id",
        "identity.entity.name",
        "identity.entity.metadata.minion-id",
        "identity.entity.aliases.auth_approle_abcd.id",
        "identity.entity.aliases.auth_approle_abcd.name",
        "identity.entity.aliases.auth_approle_abcd.metadata.alias-meta",
        "identity.groups.ids.group-uuid.name",
        "identity.groups.ids.group-uuid.metadata.group-meta",
        "identity.groups.names.test-group.id",
        "identity.groups.names.test-group.metadata.group-meta",
    ]
    assert list(identity_ctx) == expected
    assert len(identity_ctx) == len(expected)


def test_identity_ctx_handles_empty_entity_values(identity_ctx, entity_response):
    """
    Entity metadata, aliases and group IDs can be null in API responses.
    """
    entity_response.update({"metadata": None, "aliases": None, "group_ids": None})
    assert list(identity_ctx) == ["identity.entity.id", "identity.entity.name"]


def test_render_identity_template_without_template(get_authd_client):
    """
    Strings without templates should be returned as-is, without
    requesting a client.
    """
    tpl = "salt/minions/some-minion"
    assert vault.render_identity_template(tpl, {}, {}) is tpl
    get_authd_client.assert_not_called()


@pytest.mark.usefixtures("get_authd_client", "identity_ctx")
@pytest.mark.parametrize(
    "tpl,expected",
    (
        ("salt/{{identity.entity.metadata.minion-id}}", "salt/test-minion"),
        ("{{ identity.entity.name }}", "salt_minion_test-minion"),
        (
            "{{identity.entity.id}}/{{identity.groups.names.test-group.id}}",
            "entity-uuid/group-uuid",
        ),
    ),
)
def test_render_identity_template(tpl, expected):
    assert vault.render_identity_template(tpl, {}, {}) == expected


@pytest.mark.usefixtures("get_authd_client", "identity_ctx")
def test_render_identity_template_missing_key():
    """
    Templates referencing data that does not exist should render to None.
    """
    res = vault.render_identity_template("salt/{{identity.entity.metadata.missing}}", {}, {})
    assert res is None


@pytest.mark.usefixtures("get_authd_client", "identity_ctx")
def test_render_identity_template_missing_entity(client):
    """
    Templates referencing identity data of a token without an associated
    entity should render to None.
    """
    client.token_entity.return_value = None
    assert vault.render_identity_template("salt/{{identity.entity.id}}", {}, {}) is None
