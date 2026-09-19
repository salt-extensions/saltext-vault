# Deny read access to specific PKI roles to ensure the certificate_managed
# state degrades gracefully when issuer_ref is specified explicitly.
# Assigned together with pki_admin, which allows everything else.
# Deny always wins in Vault. Scoped to a prefix to keep other tests
# in the module unaffected.
path "pki/roles/denied-*"
{
  capabilities = ["deny"]
}
