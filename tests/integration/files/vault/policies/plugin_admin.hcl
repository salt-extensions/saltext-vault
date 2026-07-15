# Manage plugins in Salt-SSH integration test

path "sys/plugins/catalog" {
  capabilities = ["read"]
}

path "sys/plugins/catalog/*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch", "sudo"]
}

path "sys/plugins/reload/*" {
  capabilities = ["update"]
}

path "sys/plugins/pins" {
  capabilities = ["read"]
}

path "sys/plugins/pins/*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch"]
}
