from unittest.mock import Mock

import pytest

from saltext.vault.modules import vault_db as vault_db_exe
from saltext.vault.states import vault_db


@pytest.fixture
def _conns():
    return {}


@pytest.fixture
def _roles():
    return {}


@pytest.fixture
def delete_connection_mock(_conns):
    def _del(name, **kwargs):  # pylint: disable=unused-argument
        _conns.pop(name, None)
        return True

    return Mock(spec=vault_db_exe.delete_connection, side_effect=_del)


@pytest.fixture
def delete_role_mock(_roles):
    def _del(name, **kwargs):  # pylint: disable=unused-argument
        _roles.pop(name, None)
        return True

    return Mock(spec=vault_db_exe.delete_role, side_effect=_del)


@pytest.fixture
def fetch_connection_mock(_conns):
    return Mock(spec=vault_db_exe.fetch_connection, side_effect=lambda x, **kwargs: _conns.get(x))


@pytest.fixture
def fetch_role_mock(_roles):
    return Mock(spec=vault_db_exe.fetch_role, side_effect=lambda x, **kwargs: _roles.get(x))


@pytest.fixture
def rotate_root_mock():
    return Mock(spec=vault_db_exe.rotate_root, return_value=True)


@pytest.fixture
def write_connection_mock(_conns):
    def _write(
        name,
        plugin,
        version="",
        verify=True,
        rotate=True,
        allowed_roles=None,
        root_rotation_statements=None,
        password_policy=None,
        mount="database",
        **kwargs,
    ):  # pylint: disable=unused-argument
        kwargs.pop("password", None)  # password is obviously never returned
        data = {
            "plugin_name": f"{plugin}-database-plugin",
            "plugin_version": version,
            "verify_connection": verify,
            "allowed_roles": allowed_roles or [],
            "root_credentials_rotate_statements": root_rotation_statements or [],
            "password_policy": password_policy or "",
            "connection_details": kwargs,
        }
        _conns[name] = data

    return Mock(spec=vault_db_exe.write_connection, side_effect=_write)


@pytest.fixture
def write_role_mock(_roles):
    def _write(
        name, connection, creation_statements, mount="database", **kwargs
    ):  # pylint: disable=unused-argument
        data = {
            "db_name": connection,
            "creation_statements": creation_statements,
            "default_ttl": kwargs.get("default_ttl") or 0,
            "max_ttl": kwargs.get("max_ttl") or 0,
            "renew_statements": kwargs.get("renew_statements") or [],
            "revocation_statements": kwargs.get("revocation_statements") or [],
            "rollback_statements": kwargs.get("rollback_statements") or [],
            # credential_type/_config are only exposed if the DB plugin supports it
        }
        _roles[name] = data

    return Mock(spec=vault_db_exe.write_role, side_effect=_write)


@pytest.fixture
def write_static_role_mock(_roles):
    def _write(
        name,
        connection,
        username,
        rotation_period,
        rotation_statements=None,
        mount="database",
        **kwargs,
    ):  # pylint: disable=unused-argument
        data = {
            "db_name": connection,
            "username": username,
            "rotation_period": rotation_period,
            "rotation_statements": rotation_statements or [],
            # credential_type/_config are only exposed if the DB plugin supports it
        }
        _roles[name] = data

    return Mock(spec=vault_db_exe.write_static_role, side_effect=_write)


@pytest.fixture
def configure_loader_modules(
    delete_connection_mock,
    delete_role_mock,
    fetch_connection_mock,
    fetch_role_mock,
    rotate_root_mock,
    write_connection_mock,
    write_role_mock,
    write_static_role_mock,
    testmode,
):
    return {
        vault_db: {
            "__opts__": {"test": testmode},
            "__grains__": {"id": "test-minion"},
            "__salt__": {
                "vault_db.delete_connection": delete_connection_mock,
                "vault_db.delete_role": delete_role_mock,
                "vault_db.fetch_connection": fetch_connection_mock,
                "vault_db.fetch_role": fetch_role_mock,
                "vault_db.write_connection": write_connection_mock,
                "vault_db.write_role": write_role_mock,
                "vault_db.write_static_role": write_static_role_mock,
                "vault_db.rotate_root": rotate_root_mock,
            },
        }
    }


@pytest.fixture(params=(False, True), autouse=True)
def testmode(request):
    return request.param


def test_conn_present(testmode, write_connection_mock):
    ret = vault_db.connection_present("conn", "custom")
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "created" in ret["changes"]
    assert (write_connection_mock.call_args is None) is testmode
    assert "created" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode


def test_conn_already_present(write_connection_mock):
    write_connection_mock("conn", "custom")
    ret = vault_db.connection_present("conn", "custom")
    assert ret["result"] is True
    assert not ret["changes"]
    assert "as specified" in ret["comment"]


@pytest.mark.parametrize(
    "kwargs,param",
    (
        ({"version": "1.2.3"}, "plugin_version"),
        ({"allowed_roles": ["*"]}, None),
        ({"root_rotation_statements": ["rotate"]}, "root_credentials_rotate_statements"),
        ({"password_policy": "foo"}, None),
    ),
)
def test_conn_changes(testmode, write_connection_mock, kwargs, param, _conns):
    write_connection_mock("conn", "custom")
    param = param or next(iter(kwargs))
    expected_changes = {"old": _conns["conn"][param], "new": kwargs[next(iter(kwargs))]}
    ret = vault_db.connection_present("conn", "custom", **kwargs)
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert param in ret["changes"]
    assert ret["changes"][param] == expected_changes
    assert (write_connection_mock.call_count == 1) is testmode
    assert "updated" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode


def test_conn_no_password_changes(write_connection_mock, _conns):
    write_connection_mock("conn", "custom", username="foo", password="bar")
    ret = vault_db.connection_present("conn", "custom", username="foo", password="baz")
    assert ret["result"] is True
    assert not ret["changes"]


def test_conn_detail_changes(testmode, write_connection_mock, _conns):
    write_connection_mock("conn", "custom", username="foo", password="bar")
    ret = vault_db.connection_present("conn", "custom", username="bar", password="baz")
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "username" in ret["changes"]
    assert ret["changes"]["username"] == {"old": "foo", "new": "bar"}
    assert (write_connection_mock.call_count == 1) is testmode
    assert "updated" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode
    if not testmode:
        assert "username" in write_connection_mock.call_args[1]
        # for an existing connection, the password should never be updated
        assert "password" not in write_connection_mock.call_args[1]


def test_conn_statements_strip(write_connection_mock):
    write_connection_mock("conn", "custom", root_rotation_statements=["foo"])
    ret = vault_db.connection_present("conn", "custom", root_rotation_statements=["foo\n"])
    assert ret["result"] is True
    assert not ret["changes"]


def test_conn_plugin_change_err(write_connection_mock):
    write_connection_mock("conn", "custom")
    ret = vault_db.connection_present("conn", "custom2")
    assert ret["result"] is False
    assert not ret["changes"]
    assert "Cannot change plugin type without deleting" in ret["comment"]


def test_conn_plugin_change_force(testmode, write_connection_mock, delete_connection_mock):
    write_connection_mock("conn", "custom")
    ret = vault_db.connection_present("conn", "custom2", force=True)
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "deleted_for_plugin_change" in ret["changes"]
    assert (write_connection_mock.call_count == 1) is testmode
    assert "created" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode
    assert (delete_connection_mock.call_count == 0) is testmode


@pytest.mark.parametrize("testmode", (False,), indirect=True)
@pytest.mark.parametrize("present", (False, True))
def test_conn_verification(present, write_connection_mock):
    if present:
        write_connection_mock("conn", "custom")
    write_connection_mock.side_effect = None
    ret = vault_db.connection_present("conn", "custom", allowed_roles=["*"])
    assert ret["result"] is False
    if present:
        assert "reported parameters do not match" in ret["comment"]
    else:
        assert "but it is still reported as absent" in ret["comment"]


def test_conn_absent(testmode, write_connection_mock, delete_connection_mock):
    write_connection_mock("conn", "custom")
    ret = vault_db.connection_absent("conn")
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "deleted" in ret["changes"]
    assert "deleted" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode
    assert (delete_connection_mock.call_count == 0) is testmode


def test_conn_already_absent(delete_connection_mock):
    ret = vault_db.connection_absent("conn", "custom")
    assert ret["result"] is True
    assert not ret["changes"]
    assert "already absent" in ret["comment"]
    delete_connection_mock.assert_not_called()


@pytest.mark.parametrize("testmode", (False,), indirect=True)
def test_conn_absent_verification(write_connection_mock, delete_connection_mock):
    write_connection_mock("conn", "custom")
    delete_connection_mock.side_effect = None
    ret = vault_db.connection_absent("conn", "custom")
    assert ret["result"] is False
    assert "but it is still reported as present" in ret["comment"]


def test_role_present(testmode, write_role_mock):
    ret = vault_db.role_present("role", "conn", [])
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "created" in ret["changes"]
    assert (write_role_mock.call_args is None) is testmode
    assert "created" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode


def test_role_already_present(write_role_mock):
    write_role_mock("role", "conn", [])
    ret = vault_db.role_present("role", "conn", [])
    assert ret["result"] is True
    assert not ret["changes"]
    assert "as specified" in ret["comment"]


@pytest.mark.parametrize(
    "kwargs,param",
    (
        ({"connection": "conn2"}, "db_name"),
        ({"creation_statements": ["foo"]}, None),
        ({"revocation_statements": ["revoke"]}, None),
        ({"rollback_statements": ["back"]}, None),
        ({"renew_statements": ["bling"]}, None),
        ({"default_ttl": 42}, None),
        ({"max_ttl": 1337}, None),
    ),
)
def test_role_changes(testmode, write_role_mock, kwargs, param, _roles):
    write_role_mock("role", "conn", [])
    kwargs = kwargs.copy()
    param = param or next(iter(kwargs))
    expected_changes = {"old": _roles["role"][param], "new": kwargs[next(iter(kwargs))]}
    conn = kwargs.pop("connection", "conn")
    creation_statements = kwargs.pop("creation_statements", [])
    ret = vault_db.role_present("role", conn, creation_statements, **kwargs)
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert param in ret["changes"]
    assert ret["changes"][param] == expected_changes
    assert (write_role_mock.call_count == 1) is testmode
    assert "updated" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode


def test_role_changes_strip(write_role_mock):
    write_role_mock(
        "role",
        "conn",
        creation_statements=["foo"],
        revocation_statements=["foo"],
        rollback_statements=["foo"],
        renew_statements=["foo"],
    )
    ret = vault_db.role_present(
        "role",
        "conn",
        creation_statements=["foo\n"],
        revocation_statements=["foo\n"],
        rollback_statements=["foo\n"],
        renew_statements=["foo\n"],
    )
    assert ret["result"] is True
    assert not ret["changes"]


def test_role_statements_as_strings(write_role_mock):
    write_role_mock(
        "role",
        "conn",
        creation_statements=["foo"],
        revocation_statements=["foo"],
        rollback_statements=["foo"],
        renew_statements=["foo"],
    )
    ret = vault_db.role_present(
        "role",
        "conn",
        creation_statements="foo",
        revocation_statements="foo",
        rollback_statements="foo",
        renew_statements="foo",
    )
    assert ret["result"] is True
    assert not ret["changes"]


@pytest.mark.parametrize("testmode", (False,), indirect=True)
@pytest.mark.parametrize("present", (False, True))
def test_role_verification(present, write_role_mock):
    if present:
        write_role_mock("role", "conn", [])
    write_role_mock.side_effect = None
    ret = vault_db.role_present("role", "conn", ["foo"])
    assert ret["result"] is False
    if present:
        assert "reported parameters do not match" in ret["comment"]
    else:
        assert "but it is still reported as absent" in ret["comment"]


def test_role_absent(testmode, write_role_mock, delete_role_mock):
    write_role_mock("role", "conn", [])
    ret = vault_db.role_absent("role")
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "deleted" in ret["changes"]
    assert "deleted" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode
    assert (delete_role_mock.call_count == 0) is testmode


def test_role_already_absent(delete_role_mock):
    ret = vault_db.role_absent("role")
    assert ret["result"] is True
    assert not ret["changes"]
    assert "already absent" in ret["comment"]
    delete_role_mock.assert_not_called()


@pytest.mark.parametrize("testmode", (False,), indirect=True)
def test_role_absent_verification(write_role_mock, delete_role_mock):
    write_role_mock("role", "conn", [])
    delete_role_mock.side_effect = None
    ret = vault_db.role_absent("role")
    assert ret["result"] is False
    assert "but it is still reported as present" in ret["comment"]


def test_static_role_present(testmode, write_static_role_mock):
    ret = vault_db.static_role_present("role", "conn", "user", 42)
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert "created" in ret["changes"]
    assert (write_static_role_mock.call_args is None) is testmode
    assert "created" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode


def test_static_role_already_present(write_static_role_mock):
    write_static_role_mock("role", "conn", "user", 42)
    ret = vault_db.static_role_present("role", "conn", "user", 42)
    assert ret["result"] is True
    assert not ret["changes"]
    assert "as specified" in ret["comment"]


@pytest.mark.parametrize(
    "kwargs,param",
    (
        ({"connection": "conn2"}, "db_name"),
        ({"username": "bar"}, None),
        ({"rotation_period": 43}, None),
    ),
)
def test_static_role_changes(testmode, write_static_role_mock, kwargs, param, _roles):
    write_static_role_mock("role", "conn", "user", 42)
    kwargs = kwargs.copy()
    param = param or next(iter(kwargs))
    expected_changes = {"old": _roles["role"][param], "new": kwargs[next(iter(kwargs))]}
    conn = kwargs.pop("connection", "conn")
    username = kwargs.pop("username", "user")
    rotation_period = kwargs.pop("rotation_period", 42)
    ret = vault_db.static_role_present("role", conn, username, rotation_period, **kwargs)
    assert ret["result"] is not False
    assert (ret["result"] is None) is testmode
    assert ret["changes"]
    assert param in ret["changes"]
    assert ret["changes"][param] == expected_changes
    assert (write_static_role_mock.call_count == 1) is testmode
    assert "updated" in ret["comment"]
    assert ("would have been" in ret["comment"]) is testmode


def test_static_role_changes_strip(write_static_role_mock):
    write_static_role_mock("role", "conn", "user", 42, rotation_statements=["foo"])
    ret = vault_db.static_role_present("role", "conn", "user", 42, rotation_statements=["foo\n"])
    assert ret["result"] is True
    assert not ret["changes"]


def test_static_role_statements_as_strings(write_static_role_mock):
    write_static_role_mock("role", "conn", "user", 42, rotation_statements=["foo"])
    ret = vault_db.static_role_present("role", "conn", "user", 42, rotation_statements="foo")
    assert ret["result"] is True
    assert not ret["changes"]


@pytest.mark.parametrize("testmode", (False,), indirect=True)
@pytest.mark.parametrize("present", (False, True))
def test_static_role_verification(present, write_static_role_mock):
    if present:
        write_static_role_mock("role", "conn", "user", 42)
    write_static_role_mock.side_effect = None
    ret = vault_db.static_role_present("role", "conn", "user", 43)
    assert ret["result"] is False
    if present:
        assert "reported parameters do not match" in ret["comment"]
    else:
        assert "but it is still reported as absent" in ret["comment"]
