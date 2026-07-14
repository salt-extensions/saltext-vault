# Manage AppRole auth backend in Salt-SSH integration test
path "auth/approle-test*" {
    capabilities = ["read", "create", "update", "delete", "list", "patch"]
}
