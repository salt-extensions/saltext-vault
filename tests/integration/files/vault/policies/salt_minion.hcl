# General KV v2 testing
path "secret/*" {
  capabilities = ["read", "list", "create", "update", "delete", "patch"]
}

# General KV v1 testing
path "secret-v1/*" {
  capabilities = ["read", "list", "create", "update", "delete"]
}

# ACL policy templating tests
path "salt/+/minions/{{identity.entity.metadata.minion-id}}" {
    capabilities = ["create", "read", "update", "delete", "list", "patch"]
}

# ACL policy templating tests with pillar values
path "salt/data/roles/{{identity.entity.metadata.role}}" {
    capabilities = ["read"]
}

# Test list policies
path "sys/policy" {
    capabilities = ["read"]
}

# Test managing policies
path "sys/policy/*" {
    capabilities = ["read", "create", "update", "delete"]
}

# Request database credentials in integration test
path "database/creds/*" {
    capabilities = ["read"]
}
