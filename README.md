# RNovModularDB

RNovModularDB is an implementation-preview Rust database engine focused on modular internals, secure storage primitives, embedded in-memory execution, and explicit memory/disk synchronization state.

The project is organized as a Cargo workspace with focused crates for common primitives, SQL types, parsing and binding, catalog metadata, storage, transactions, indexes, planning, execution, full-text search, UDF metadata, security, instance isolation, embedded runtime support, and CLI tooling.

## Status

RNovModularDB is not ready for production workloads. The current tree is useful for local experimentation, API evaluation, and engine development, but it does not yet provide a stable release contract, a network server protocol, or automatic on-disk format migration.

Implemented areas include:

- Embedded in-memory SQL sessions through `rnmdb_cli::LocalSession`.
- A command-line binary, `rnmdb`, that executes semicolon-separated SQL from standard input.
- SQL parsing, binding, planning, and execution for a deliberate subset of DDL, DML, expressions, aggregates, windows, set operations, recursive CTEs, and explain output.
- Fixed-size page storage with a memory backend, encrypted single-file page backend, and hybrid memory/disk synchronization state.
- Single-file diagnostics, structure verification, backup, restore dry-run, and restore commands.
- Catalog metadata for schemas, tables, indexes, functions, procedures, operators, roles, grants, row policies, and column encryption metadata.
- Security primitives for local credentials, RBAC-style authorization metadata, row policy metadata, column key wrapping metadata, and tamper-evident audit chains.
- Instance isolation and resource limit scaffolding for temporary embedded memory runtimes.

Important current limits:

- CLI SQL sessions are in-memory only. The storage CLI commands inspect, verify, back up, and restore single-file page stores; they do not yet persist full SQL table state from the SQL stdin session.
- SQL support is intentionally incomplete. Unsupported syntax returns an error instead of attempting partial compatibility.
- The single-file storage format is versioned, but there is no migration tool or cross-version upgrade promise yet.
- Transaction, security, UDF, and instance crates expose core primitives, but a production multi-session durable SQL server is not a supported product surface yet.

## Build And Test

RNovModularDB uses Rust 1.95 or newer.

```bash
cargo check --workspace
cargo test --workspace
cargo test --workspace --all-features
```

Run the CLI binary from the workspace without arguments to read SQL from standard input:

```bash
cargo run -p rnmdb-cli --bin rnmdb
```

The current CLI reports unsupported command names as errors.

## CLI Usage

Run an in-memory SQL session:

```bash
printf "CREATE TABLE items (id INT64 NOT NULL, name TEXT); INSERT INTO items (id, name) VALUES (1, 'alpha'); SELECT id, name FROM items ORDER BY id;" | cargo run -q -p rnmdb-cli --bin rnmdb
```

Inspect a single-file store:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- inspect path/to/database.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- inspect --page-key-hex <64-hex-chars> path/to/database.rnmdb
```

Verify, back up, and restore a single-file store:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- verify path/to/database.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- verify --page-key-hex <64-hex-chars> path/to/database.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- backup path/to/database.rnmdb path/to/database.backup.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- restore --dry-run path/to/database.backup.rnmdb path/to/restored.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- restore path/to/database.backup.rnmdb path/to/restored.rnmdb
```

Upgrade an older single-file store to the current format:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- upgrade path/to/legacy-v1.rnmdb path/to/upgraded-v2.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- upgrade --page-key-hex <64-hex-chars> path/to/legacy-v1.rnmdb path/to/upgraded-v2.rnmdb
```

`inspect` reports file layout, page size, single-file format version, superblock generation, page record counts, free space, encryption state, and page record details. Supplying `--page-key-hex` also authenticates encrypted page records and verifies decoded page checksums.

`verify` without a key validates the file structure. `verify --page-key-hex` also authenticates present encrypted pages. `restore` refuses to overwrite an existing target.

## Embedded API

Use `LocalSession` for a temporary in-memory SQL engine:

```rust
use rnmdb_cli::{CommandOutput, LocalSession};

fn main() -> rnmdb_common::Result<()> {
    let mut session = LocalSession::memory()?;
    session.execute("CREATE TABLE items (id INT64 NOT NULL, name TEXT);")?;
    session.execute("INSERT INTO items (id, name) VALUES (1, 'alpha');")?;

    if let CommandOutput::Rows(rows) = session.execute("SELECT id, name FROM items ORDER BY id;")? {
        println!("{:?}", rows.rows());
    }

    Ok(())
}
```

Use `LocalSession::memory_parallel(worker_threads)` or `LocalSession::memory_with_execution(...)` to configure local parallel execution. The optional `tokio-runtime` feature adds Tokio-backed wrappers for local sessions and embedded runtimes without making the storage core depend on Tokio.

Temporary embedded runtimes are available through `rnmdb_server::EmbeddedRuntime`:

```rust
use rnmdb_common::ids::{DatabaseId, InstanceId};
use rnmdb_server::EmbeddedRuntime;

fn main() -> rnmdb_common::Result<()> {
    let runtime = EmbeddedRuntime::temporary_memory(InstanceId::new(1), DatabaseId::new(1));
    let mut session = runtime.open_session()?;
    session.execute("CREATE TABLE events (id INT64 NOT NULL);")?;
    Ok(())
}
```

Temporary memory runtimes do not allow disk writes.

## SQL Support

Supported SQL data types are `BOOL`, `INT64`/`BIGINT`/`INTEGER`, `UINT64`, `TEXT`/`VARCHAR`, `BYTES`/`BYTEA`, `HSTORE`, `TEXTVECTOR`/`TSVECTOR`, arrays with `[]`, and `RANGE<type>`.

Supported statement families include:

- `CREATE TABLE`, `ALTER TABLE ADD COLUMN`, `ALTER TABLE ALTER COLUMN ... SET ENCRYPTED`, and `ALTER TABLE ALTER COLUMN ... DROP ENCRYPTED`.
- `CREATE INDEX` and `CREATE UNIQUE INDEX` with `USING btree`, `hash`, `gin`/`inverted`, `gist`, or `brin`/`summary`; expression indexes are supported for B-tree and hash metadata.
- `DROP TABLE`, `DROP INDEX`, `DROP FUNCTION`, `DROP PROCEDURE`, `DROP OPERATOR`, `DROP ROLE`, and `DROP POLICY`.
- `CREATE FUNCTION`, `CREATE PROCEDURE ... AS '<sql>'`, `CALL`, `CREATE OPERATOR`, `CREATE ROLE`, `CREATE POLICY ... USING (...)`, and `GRANT SELECT|INSERT|UPDATE|DELETE ON table TO role`.
- `INSERT ... VALUES`, `UPDATE ... SET ... WHERE ...`, and `DELETE FROM ... WHERE ...`.
- `SELECT` from one table with projection aliases, `DISTINCT`, `WHERE`, `GROUP BY`, `GROUPING SETS`, `ROLLUP`, `CUBE`, `HAVING`, `ORDER BY`, `LIMIT`, `OFFSET`, and `FETCH FIRST`.
- A restricted single `JOIN LATERAL ... ON ...` form for sideways lookup planning.
- `UNION`, `INTERSECT`, and `EXCEPT`, including `ALL`.
- Restricted recursive CTEs, `EXPLAIN`, `EXPLAIN ANALYZE`, `EXPLAIN COSTS`, and `EXPLAIN PHYSICAL`.

Supported expressions include arithmetic, comparison, boolean logic, `IS NULL`, `IS DISTINCT FROM`, `BETWEEN`, `IN`, `LIKE`, `COALESCE`, `NULLIF`, `CASE`, `CAST`, array literals, hstore literals, range literals, `count`, `count(DISTINCT ...)`, `sum`, `min`, `max`, `row_number`, `rank`, `dense_rank`, and full-text helper functions/operators such as `@@`, `text_rank`, and `text_phrase_match`.

Notable unsupported areas include decimal, timestamp, UUID, and JSON document types; arbitrary joins; general subqueries; triggers; foreign keys; virtual generated columns; procedural languages beyond SQL procedure expansion; and wire-protocol server access.

## Storage Compatibility

The encrypted single-file storage format currently uses `SINGLE_FILE_FORMAT_VERSION = 2`. File headers include this version, and open, inspect, verify, backup, and restore paths reject unsupported format versions rather than attempting best-effort decoding.

Compatibility rules for the current preview:

- Version 2 files are intended to be read and written by this implementation only.
- Version 1 files can be detected with compatibility diagnostics and upgraded explicitly to version 2 with `upgrade`.
- Upgrade writes a new target file and leaves the source file untouched. The target path must not already exist.
- Upgrading encrypted page records requires the page key. Empty version 1 files can be upgraded without a page key.
- Future or otherwise unsupported versions are rejected explicitly. Downgrade is not supported.
- Backups are byte copies that are validated against source layout metadata after copying.
- Memory-to-disk checkpoint export requires an explicit page encryption key.

Storage mode switching reports whether an operation is metadata-only, pre-synchronized, or full data movement. Millisecond-level active-target switching is only a valid expectation for metadata-only or pre-synchronized states.

## Security Model

RNovModularDB uses reviewed Rust cryptography crates for security-sensitive primitives:

- Argon2 password hashing for local credentials.
- ChaCha20-Poly1305 authenticated encryption for storage pages and column key wrapping.
- HMAC-SHA256 for wrapped-key authentication metadata and SHA-256 based audit hash chains.
- OS randomness for generated credential salts.

Current boundaries:

- Page encryption keys are caller-supplied. The CLI accepts page keys as 64-character hex strings for inspection and verification, but it does not manage key storage.
- Encrypted page reads authenticate metadata and payload before returning decoded pages.
- Column encryption metadata records wrapped data-encryption keys, key versions, rotation metadata, and decrypt authorization checks, but application-level key custody remains the embedder's responsibility.
- RBAC, row policy, and grants are represented in catalog/security metadata and are enforced where the current binder/executor path uses them. This is not yet a complete hardened multi-user server boundary.
- Audit chains detect insertion, deletion, reordering, sequence gaps, instance mismatch, and digest tampering within the inspected chain.

## License

RNovModularDB is licensed under AGPL-3.0-only.
