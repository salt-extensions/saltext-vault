Fixed `vault_db.creds_cached` crashing or misdetecting the need for renewal when the cached lease's `min_ttl` and the requested `valid_for` were specified as a mix of time strings and integers
