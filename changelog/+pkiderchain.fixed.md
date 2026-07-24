Fixed `vault_pki.certificate_managed` with `append_ca_chain` never converging for binary encodings. The chain is now included for `pkcs7_der`, while the impossible combination with `der` fails early
