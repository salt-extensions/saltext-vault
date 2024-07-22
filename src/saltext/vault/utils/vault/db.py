"""
Vault Database helpers

.. versionadded:: 1.1.0
"""

from salt.utils.immutabletypes import freeze

PLUGINS = freeze(
    {
        "cassandra": {
            "name": "cassandra",
            "required": [
                "hosts",
                "username",
                "password",
            ],
        },
        "couchbase": {
            "name": "couchbase",
            "required": [
                "hosts",
                "username",
                "password",
            ],
        },
        "elasticsearch": {
            "name": "elasticsearch",
            "required": [
                "url",
                "username",
                "password",
            ],
        },
        "influxdb": {
            "name": "influxdb",
            "required": [
                "host",
                "username",
                "password",
            ],
        },
        "hanadb": {
            "name": "hana",
            "required": [
                "connection_url",
            ],
        },
        "mongodb": {
            "name": "mongodb",
            "required": [
                "connection_url",
            ],
        },
        "mongodb_atlas": {
            "name": "mongodbatlas",
            "required": [
                "public_key",
                "private_key",
                "project_id",
            ],
        },
        "mssql": {
            "name": "mssql",
            "required": [
                "connection_url",
            ],
        },
        "mysql": {
            "name": "mysql",
            "required": [
                "connection_url",
            ],
        },
        "oracle": {
            "name": "oracle",
            "required": [
                "connection_url",
            ],
        },
        "postgresql": {
            "name": "postgresql",
            "required": [
                "connection_url",
            ],
        },
        "redis": {
            "name": "redis",
            "required": [
                "host",
                "port",
                "username",
                "password",
            ],
        },
        "redis_elasticache": {
            "name": "redis-elasticache",
            "required": [
                "url",
                "username",
                "password",
            ],
        },
        "redshift": {
            "name": "redshift",
            "required": [
                "connection_url",
            ],
        },
        "snowflake": {
            "name": "snowflake",
            "required": [
                "connection_url",
            ],
        },
        "default": {
            "name": "",
            "required": [],
        },
    }
)


def get_plugin_meta(name):
    """
    Get meta information for a plugin with this name,
    excluding the `-database-plugin` suffix.
    """
    return PLUGINS.get(name, PLUGINS["default"])


def get_plugin_name(name):
    """
    Get the name of a plugin as rendered by this module. This is a utility for the state
    module primarily.
    """
    plugin_name = PLUGINS.get(name, {"name": name})["name"]
    return f"{plugin_name}-database-plugin"


def create_cache_pattern(name=None, mount=None, cache=None, static=None):
    """
    Render a match pattern for operating on cached leases.
    Unset parameters will result in a ``*`` glob.

    name
        The name of the database role.

    static
        Whether the role is static.

    cache
        Filter by cache name (refer to get_creds for details).

    mount
        The mount path the associated database backend is mounted to.
    """
    ptrn = ["db"]
    ptrn.append("*" if mount is None else mount)
    ptrn.append("*" if static is None else "static" if static else "dynamic")
    ptrn.append("*" if name is None else name)
    if cache is True or static is True:
        # Conceptually, there can only be one static lease since it's
        # tied to a specific account.
        ptrn.append("default")
    elif cache:
        ptrn.append(cache)
    else:
        ptrn.append("*")
    return ".".join(ptrn)
