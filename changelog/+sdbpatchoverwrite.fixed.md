Fixed `sdb.set` with the `patch` option enabled unexpectedly overwriting the complete secret when its data could not be read (e.g. write-only policies or exhausted token uses)
