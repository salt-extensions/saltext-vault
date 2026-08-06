import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import salt.exceptions

from tests.support.vault import vault_delete
from tests.support.vault import vault_delete_approle
from tests.support.vault import vault_list
from tests.support.vault import vault_read
from tests.support.vault import vault_write

pytest.importorskip("docker")

pytestmark = [
    pytest.mark.skip_if_binaries_missing("vault"),
    pytest.mark.usefixtures("container", "master_approle_mount"),
]

log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def master_config_overrides(master_approle_mount):  # pylint: disable=unused-argument
    return {
        "vault": {
            "issue": {
                "type": "approle",
                "approle": {
                    "params": {
                        "secret_id_ttl": "1h",
                        "token_explicit_max_ttl": "1h",
                    }
                },
                "allow_minion_override_params": True,
            },
        }
    }


def _get_approle(name, mount):
    return vault_read(f"auth/{mount}/role/{name}", raise_errors=True)["data"]


def _get_config(vault, name, impersonated_by_master=False, issue_params=None):
    config = vault.get_config(
        name, signature="", impersonated_by_master=impersonated_by_master, issue_params=issue_params
    )
    assert "error" not in config
    assert all(key in config for key in ("auth", "cache", "client", "server"))
    assert config["auth"]["method"] == "approle"
    assert "role_id" in config["auth"]
    assert "secret_id" in config["auth"]
    assert isinstance(config["auth"]["secret_id"], bool)
    return config


def _generate_secret_id(vault, name, impersonated_by_master=False, issue_params=None):
    secret_id = vault.generate_secret_id(
        name, signature="", impersonated_by_master=impersonated_by_master, issue_params=issue_params
    )
    assert "error" not in secret_id
    assert "server" in secret_id
    assert secret_id["data"] or "wrap_info" in secret_id
    return secret_id


@pytest.fixture(autouse=True)
def reset_approles(master_approle_mount):
    for approle in vault_list(f"auth/{master_approle_mount}/role"):
        vault_delete_approle(approle, mount=master_approle_mount)
    yield
    for approle in vault_list(f"auth/{master_approle_mount}/role"):
        vault_delete_approle(approle, mount=master_approle_mount)


@pytest.fixture(autouse=True)
def vault(runners, master_loaders):
    runner = runners.vault
    with patch.object(
        sys.modules[f"{master_loaders.loaded_base_name}.ext.runners.vault"], "_validate_signature"
    ):
        yield runner


def test_get_config_and_generate_secret_id_do_not_rewrite_approle_with_timestring_config(
    vault, master_loaders
):
    """
    The Vault server always reports seconds in ttl config values.
    If ttl values like secret_id_ttl are configured via a time string like 1h,
    the runner should recognize that 1h equals 3600s and not rewrite the approle.
    """
    _get_config(vault, "foobar")
    # make _manage_approle raise an exception if called
    with patch.object(
        sys.modules[f"{master_loaders.loaded_base_name}.ext.runners.vault"],
        "_manage_approle",
        side_effect=RuntimeError,
    ):
        _get_config(vault, "foobar")
        _generate_secret_id(vault, "foobar")


def test_get_config_and_generate_secret_id_rewrite_approle_when_necessary(
    vault, master_approle_mount
):
    _get_config(vault, "foobar", issue_params={"secret_id_ttl": "1d"})
    approle = _get_approle("foobar", master_approle_mount)
    assert approle["secret_id_ttl"] == 86400
    _generate_secret_id(vault, "foobar", issue_params={"secret_id_ttl": "1h"})
    approle = _get_approle("foobar", master_approle_mount)
    assert approle["secret_id_ttl"] == 3600


@pytest.fixture
def synced_minions(vault, master_opts):
    """
    Ensure two minions with AppRoles and accepted keys exist.
    Their AppRoles carry a minion override, which is reset during a sync.
    No minion is connected, so they are reported as down.
    """
    minions = ("sync-minion-1", "sync-minion-2")
    pki_dir = Path(master_opts["pki_dir"])
    for key_dir in ("minions", "minions_pre", "minions_rejected", "minions_denied"):
        (pki_dir / key_dir).mkdir(parents=True, exist_ok=True)
    try:
        for minion in minions:
            (pki_dir / "minions" / minion).touch()
            _get_config(vault, minion, issue_params={"secret_id_ttl": "30m"})
        yield minions
    finally:
        for minion in minions:
            (pki_dir / "minions" / minion).unlink(missing_ok=True)


@pytest.mark.parametrize(
    "up,down,expected_synced",
    (
        (False, False, True),
        (True, False, False),
        (False, True, True),
        (True, True, True),
    ),
)
def test_sync_approles_minion_selection(
    vault, master_approle_mount, synced_minions, up, down, expected_synced
):
    """
    Ensure sync_approles resets minion overrides for minions that are up
    and/or down when requested and defaults to all known minions.
    Since no minion is connected, they are all reported as down.
    """
    if up or down:
        res = vault.sync_approles(up=up, down=down)
    else:
        res = vault.sync_approles()
    assert res is True
    for minion in synced_minions:
        ttl = _get_approle(minion, master_approle_mount)["secret_id_ttl"]
        assert ttl == (3600 if expected_synced else 1800)


@pytest.mark.parametrize(
    "up,down,expected_synced",
    (
        (False, False, True),
        (True, False, False),
        (False, True, True),
        (True, True, True),
    ),
)
def test_sync_entities_minion_selection(vault, synced_minions, up, down, expected_synced):
    """
    Ensure sync_entities resets entity metadata for minions that are up
    and/or down when requested and defaults to all known minions.
    Since no minion is connected, they are all reported as down.
    """
    for minion in synced_minions:
        vault_write(f"identity/entity/name/salt_minion_{minion}", metadata={"minion-id": "wrong"})
    if up or down:
        res = vault.sync_entities(up=up, down=down)
    else:
        res = vault.sync_entities()
    assert res is True
    for minion in synced_minions:
        meta = vault.show_entity(minion)
        assert meta == {"minion-id": minion if expected_synced else "wrong"}


def test_sync_approles_with_minion_list(vault, master_approle_mount, synced_minions):
    """
    Ensure sync_approles accepts a list of minion IDs and only
    syncs the specified minions
    """
    assert vault.sync_approles([synced_minions[0]]) is True
    assert _get_approle(synced_minions[0], master_approle_mount)["secret_id_ttl"] == 3600
    assert _get_approle(synced_minions[1], master_approle_mount)["secret_id_ttl"] == 1800


def test_sync_entities_with_minion_list(vault, synced_minions):
    """
    Ensure sync_entities accepts a list of minion IDs and only
    syncs the specified minions
    """
    for minion in synced_minions:
        vault_write(f"identity/entity/name/salt_minion_{minion}", metadata={"minion-id": "wrong"})
    assert vault.sync_entities([synced_minions[0]]) is True
    assert vault.show_entity(synced_minions[0]) == {"minion-id": synced_minions[0]}
    assert vault.show_entity(synced_minions[1]) == {"minion-id": "wrong"}


@pytest.mark.parametrize("defect", ("missing", "wrong_entity"))
def test_sync_entities_fixes_alias_association(vault, master_approle_mount, defect):
    """
    Ensure sync_entities recreates the entity alias when it is missing
    and fixes it when it is associated with an unexpected entity.
    """
    minion = "alias-fix-minion"
    _get_config(vault, minion)
    role_id = vault_read(f"auth/{master_approle_mount}/role/{minion}/role-id")["data"]["role_id"]
    accessor = vault_read(f"sys/auth/{master_approle_mount}")["data"]["accessor"]

    def aliased_entity_name():
        res = vault_write(
            "identity/lookup/entity", alias_name=role_id, alias_mount_accessor=accessor
        )
        if res is True:
            # empty response, no aliased entity found
            return None
        return res["data"]["name"]

    assert aliased_entity_name() == f"salt_minion_{minion}"
    alias_id = vault_read(f"identity/entity/name/salt_minion_{minion}")["data"]["aliases"][0]["id"]
    if defect == "missing":
        vault_delete(f"identity/entity-alias/id/{alias_id}")
        assert aliased_entity_name() is None
    else:
        rogue_id = vault_write("identity/entity", name="rogue-entity")["data"]["id"]
        vault_write(
            f"identity/entity-alias/id/{alias_id}",
            name=role_id,
            canonical_id=rogue_id,
            mount_accessor=accessor,
        )
        assert aliased_entity_name() == "rogue-entity"

    assert vault.sync_entities(minion) is True
    assert aliased_entity_name() == f"salt_minion_{minion}"


def test_cleanup_auth(vault, master_opts, master_approle_mount):
    """
    Ensure cleanup_auth removes AppRoles and entities associated with
    unknown minion IDs only, including AppRoles without an entity.
    """
    known = "cleanup-known-minion"
    unknown = "cleanup-unknown-minion"
    unknown_no_entity = "cleanup-unknown-no-entity"
    minions_dir = Path(master_opts["pki_dir"]) / "minions"
    minions_dir.mkdir(parents=True, exist_ok=True)
    try:
        (minions_dir / known).touch()
        for minion in (known, unknown):
            _get_config(vault, minion)
        vault_write(f"auth/{master_approle_mount}/role/{unknown_no_entity}")
        res = vault.cleanup_auth()
        assert set(res["deleted"]["approles"]) == {unknown, unknown_no_entity}
        assert res["deleted"]["entities"] == [unknown]
        approles = vault.list_approles()
        assert known in approles
        assert unknown not in approles
        assert unknown_no_entity not in approles
        entities = vault.list_entities()
        assert f"salt_minion_{known}" in entities
        assert f"salt_minion_{unknown}" not in entities
    finally:
        (minions_dir / known).unlink(missing_ok=True)


def test_show_policies(vault):
    """
    When the master issues AppRoles, show_policies should report the
    token policies attached to the minion's AppRole.
    """
    _get_config(vault, "foobar")
    res = vault.show_policies("foobar")
    assert res == ["salt_minion"]


def test_show_policies_missing_approle(vault):
    """
    When the master issues AppRoles, show_policies should fail with a
    helpful message if the minion's AppRole has not been created yet.
    """
    with pytest.raises(salt.exceptions.SaltRunnerError, match="has not been created yet"):
        vault.show_policies("missing-minion")
