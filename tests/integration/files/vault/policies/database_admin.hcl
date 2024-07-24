# Manage database backend in Salt-SSH integration test
path "database/*" {
    capabilities = ["read", "create", "update", "delete", "list", "patch"]
}
