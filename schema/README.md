# JSON contracts

`run.schema.json` describes successful `aotregano --json` output and the
`analysis.json` written into a recovery bundle. `error.schema.json` describes a
machine-readable failure.

The schema identifier is versioned independently of the executable. Additive
properties do not change the major version. Renaming, removing, or changing the
meaning or type of a property requires a new major version.
