# Manage SSH backend in Salt-SSH integration test
path "ssh/*" {
    capabilities = ["read", "create", "update", "delete", "list", "patch"]
}

path "identity/entity/id/{{identity.entity.id}}" {
    capabilities = ["read"]
}

path "identity/entity/name/{{identity.entity.name}}" {
    capabilities = ["read"]
}

path "identity/group/name/group1" {
    capabilities = ["read"]
}

path "identity/group/id/{{identity.groups.names.group1.id}}" {
    capabilities = ["read"]
}

path "identity/group/name/group2" {
    capabilities = ["read"]
}

path "identity/group/id/{{identity.groups.names.group2.id}}" {
    capabilities = ["read"]
}
