Fixed `vault_db.connection_present` failing and rewriting the connection on every run for plugins with secret parameters other than `password`, e.g. `private_key` for `mongodb_atlas`
