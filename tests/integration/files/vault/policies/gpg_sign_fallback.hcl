# Fail using the general sign endpoint to force fallback to algo-specific one
path "+/sign/+/sha2-256" {
    capabilities = ["read", "create", "update", "delete", "list", "patch"]
}

path "+/sign/+/sha2-384" {
    capabilities = ["read", "create", "update", "delete", "list", "patch"]
}
