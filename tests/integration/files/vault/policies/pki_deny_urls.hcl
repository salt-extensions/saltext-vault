# Deny read access to the PKI mount's URL and cluster configuration to ensure
# the PKI states degrade gracefully. Assigned together with pki_admin,
# which allows everything else. Deny always wins in Vault.
path "pki/config/urls"
{
  capabilities = ["deny"]
}

path "pki/config/cluster"
{
  capabilities = ["deny"]
}
