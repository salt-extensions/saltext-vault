import pytest


@pytest.fixture(scope="module")
def pillar_tree(salt_master, salt_minion):
    top_file = f"""
    base:
      '{salt_minion.id}':
        - sdb
    """
    sdb_pillar_file = """
    test_etcd_pillar_sdb: sdb://sdbetcd/secret/test/test_pillar_sdb/foo
    """
    top_tempfile = salt_master.pillar_tree.base.temp_file("top.sls", top_file)
    sdb_tempfile = salt_master.pillar_tree.base.temp_file("sdb.sls", sdb_pillar_file)

    with top_tempfile, sdb_tempfile:
        yield
