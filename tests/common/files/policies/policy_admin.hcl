# List existing policies
path "sys/policies/acl"
{
  capabilities = ["list"]
}

path "sys/policy" {
  capabilities = ["read"]
}

# Create and manage ACL policies
path "sys/policies/acl/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "sys/policy/*" {
  capabilities = ["create", "read", "update", "delete"]
}
