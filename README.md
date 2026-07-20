# RNovModularDB

RNovModularDB is a modular Rust database engine for secure embedded and edge
workloads. It combines a SQL execution engine with encrypted single-file
storage, explicit memory/disk synchronization, transaction primitives,
authorization, row policies, column encryption, audit chains, full-text
search, and sandboxed WebAssembly scalar functions.

The workspace separates common types, SQL parsing and binding, catalogs,
storage, transactions, indexes, planning, execution, full-text search, UDFs,
security, instance isolation, embedded runtimes, server support, and CLI
tooling into focused crates.

## Status

RNovModularDB is pre-1.0 software. Durable embedded SQL sessions and the
versioned single-file format are implemented, but public APIs and compatibility
guarantees may still evolve before a stable release. It is not a drop-in
replacement for SQLite or PostgreSQL.

Implemented product surfaces include:

- In-memory and encrypted durable `LocalSession` SQL engines.
- Explicit `BEGIN`, `COMMIT`, and `ROLLBACK` handling with atomic state rollback.
- General `INNER JOIN` and `LEFT JOIN` execution using hash or nested-loop plans.
- `IN`, `NOT IN`, `EXISTS`, `NOT EXISTS`, and scalar subqueries, including
  supported correlated forms.
- Single-column foreign keys and `AFTER INSERT`, `AFTER UPDATE`, and
  `AFTER DELETE` SQL triggers.
- `FLOAT64`, `TIMESTAMP`, `UUID`, and validated `JSON` values in addition to
  integer, text, bytes, array, range, hstore, and text-vector types.
- B-tree, hash, inverted, range/GiST, summary/BRIN, and multidimensional bounds
  indexing, with full-text operators integrated into planning and execution.
- Wasmtime-backed scalar UDF execution with import denial, fuel, epoch, memory,
  result-size, and module-cache limits.
- Encrypted single-file inspection, verification, backup, restore, explicit
  version 1 to version 2 upgrade, authenticated version 2 page-key rotation,
  and cross-process file coordination.
- A bounded TCP line protocol for embedded deployments.

## Build And Test

RNovModularDB requires Rust 1.95 or newer.

```bash
cargo check --workspace
cargo test --workspace
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Run the `rnmdb` binary without arguments to execute semicolon-separated SQL
from standard input in a temporary in-memory session:

```bash
printf "CREATE TABLE items (id INT64, name TEXT); SELECT id FROM items;" \
  | cargo run -q -p rnmdb-cli --bin rnmdb
```

## Storage CLI

Inspect or structurally verify a single-file database:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- inspect path/to/database.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- verify path/to/database.rnmdb
```

Authenticated inspection and verification require a page key. Keys are never
accepted as command-line values. Read a 64-character hexadecimal key, with an
optional `0x` prefix and one optional LF or CRLF terminator, from a protected
file or standard input:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- \
  verify --page-key-file /secure/page-key.hex path/to/database.rnmdb

cargo run -q -p rnmdb-cli --bin rnmdb -- \
  inspect --page-key-stdin path/to/database.rnmdb < /secure/page-key.hex
```

`--page-key-env` reads the fixed `RNMDB_PAGE_KEY_HEX` environment variable.
Standard input or a permission-restricted file is preferable where environment
variables may be exposed to process inspection or inherited by child processes.
The legacy `--page-key-hex` option is rejected.

Back up and restore a database:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- \
  backup path/to/database.rnmdb path/to/database.backup.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- \
  restore --dry-run path/to/database.backup.rnmdb path/to/restored.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- \
  restore path/to/database.backup.rnmdb path/to/restored.rnmdb
```

Upgrade a version 1 single-file database into a new version 2 target:

```bash
cargo run -q -p rnmdb-cli --bin rnmdb -- \
  upgrade path/to/legacy-v1.rnmdb path/to/upgraded-v2.rnmdb
cargo run -q -p rnmdb-cli --bin rnmdb -- \
  upgrade --page-key-file /secure/page-key.hex \
  path/to/legacy-v1.rnmdb path/to/upgraded-v2.rnmdb
```

The upgrade never modifies the source and refuses an existing target. The
library-level `SingleFileUpgradeOptions` API can use separate source and target
keys for key rotation.

Rotate the page key of an existing version 2 database through the embedded
storage API while the database is offline:

```rust
use std::path::Path;

use rnmdb_storage::{PageCryptoKey, rekey_single_file};

fn rotate_page_key(
    path: &Path,
    old_key: PageCryptoKey,
    fresh_key: PageCryptoKey,
) -> rnmdb_common::Result<()> {
    let report = rekey_single_file(path, old_key, fresh_key)?;
    assert!(report.key_rotated());
    Ok(())
}
```

`rekey_single_file` authenticates every source page with the old key, writes
and verifies a same-directory temporary database with the fresh key, then
atomically replaces the original pathname. It rejects reused keys, symbolic or
hard-linked sources, and live local backends. Other processes must also be
quiesced, and callers must supply a key that has never been used for this
database's page-nonce domain.

## Embedded API

Use `LocalSession::memory` for temporary execution:

```rust
use rnmdb_cli::{CommandOutput, LocalSession};

fn run() -> rnmdb_common::Result<()> {
    let mut session = LocalSession::memory()?;
    session.execute("CREATE TABLE items (id INT64, name TEXT);")?;
    session.execute("INSERT INTO items (id, name) VALUES (1, 'alpha');")?;

    if let CommandOutput::Rows(rows) = session.execute("SELECT id, name FROM items;")? {
        println!("{:?}", rows.rows());
    }
    Ok(())
}
```

Use `LocalSession::single_file_with_key` for durable SQL state. Call
`checkpoint` after autocommit changes; a successful explicit transaction
`COMMIT` checkpoints a durable session automatically.

```rust
use std::path::Path;

use rnmdb_cli::LocalSession;
use rnmdb_storage::PageCryptoKey;

fn write_event(path: &Path, page_key: PageCryptoKey) -> rnmdb_common::Result<()> {
    let mut session = LocalSession::single_file_with_key(path, page_key)?;
    session.execute("CREATE TABLE events (id INT64, payload TEXT);")?;
    session.execute("INSERT INTO events VALUES (1, 'created');")?;
    session.checkpoint()?;
    Ok(())
}
```

Column encryption requires the embedder to provide column key material through
`LocalSession::configure_column_encryption`. Column keys are not persisted with
the database and must be reinjected after reopening a session.

`LocalSession::memory_parallel` and `LocalSession::memory_with_execution`
configure local parallel execution. The optional `tokio-runtime` feature adds
Tokio wrappers without coupling the storage core to a specific async executor.

## TCP Server

`rnmdb_server::SqlTcpServer` exposes an embedded, newline-delimited protocol.
It supports optional local credential authentication and applies the
authenticated catalog role to authorization and column decryption. The server
limits active clients, command size, and socket I/O time, and isolates client
errors from the accept loop.

This protocol is not PostgreSQL, MySQL, or SQLite wire compatible. It is a
small operational interface for controlled embedded deployments, not a general
database proxy protocol.

## SQL Support

Supported statement families include:

- `CREATE TABLE`, `ALTER TABLE ADD COLUMN`, column encryption changes,
  `DROP TABLE`, single-column `REFERENCES`, and table-level single-column
  `FOREIGN KEY` declarations.
- `CREATE INDEX`, `CREATE UNIQUE INDEX`, `DROP INDEX`, `CREATE TRIGGER`, and
  `DROP TRIGGER`.
- `CREATE FUNCTION`, `CREATE PROCEDURE`, `CALL`, `CREATE OPERATOR`, roles,
  grants, row policies, and their corresponding drop statements.
- `INSERT`, `UPDATE`, `DELETE`, and `SELECT` with filtering, grouping,
  grouping sets, `ROLLUP`, `CUBE`, ordering, limits, windows, and set operations.
- `INNER JOIN`, `LEFT JOIN`, restricted `JOIN LATERAL`, recursive CTEs,
  expression subqueries, and explain output.

Supported scalar types are `BOOL`, `INT64`/`BIGINT`/`INTEGER`, `UINT64`,
`FLOAT64`/`DOUBLE PRECISION`, `TEXT`/`VARCHAR`, `BYTES`/`BYTEA`, `TIMESTAMP`,
`UUID`, `JSON`/`JSONB`, `HSTORE`, `TEXTVECTOR`/`TSVECTOR`, arrays, and ranges.

Important SQL limits include no `DECIMAL`/`NUMERIC`, `RIGHT JOIN`, `FULL JOIN`,
generated columns, or PostgreSQL-compatible procedural language. JSON values
are validated and persistable, but a complete JSON operator and path-query
surface is not provided.

## Storage Compatibility

The encrypted single-file format uses `SINGLE_FILE_FORMAT_VERSION = 2`.
Opening, inspection, verification, backup, restore, and upgrade reject unknown
versions rather than attempting partial decoding.

- Version 1 files can be detected and explicitly upgraded to version 2.
- Version 2 files can be re-encrypted in place with a fresh page key through an
  offline, verified atomic replacement.
- Upgrade and restore create new targets and never overwrite existing files.
- Backup sources are held under a shared OS file lock for inspection and copy.
- Writes, sync, checkpoints, restore targets, and upgrade targets use exclusive
  file locks and process-local cursor serialization.
- Backend operations remain attached to the originally opened file handle if a
  pathname is renamed or replaced.
- Page records use authenticated encryption and checksums; keyed verification
  authenticates and decodes every present page.
- Memory-to-disk checkpoint export requires an explicit page encryption key.

Storage mode reports distinguish metadata-only switching, pre-synchronized
switching, and full data movement. Millisecond switching is only claimed for
metadata-only or already synchronized state changes.

## Security Model

Security-sensitive primitives use reviewed Rust crates:

- Argon2 for local credential password hashing.
- ChaCha20-Poly1305 for page encryption, column values, and wrapped keys.
- HMAC-SHA256 for wrapped-key authentication metadata.
- SHA-256 hash chains for tamper-evident audit records.
- Operating-system randomness for salts and generated secret material.

RBAC grants, active roles, row policies, foreign keys, triggers, and configured
column encryption are enforced in the local execution path. Audit verification
detects insertion, deletion, reordering, sequence gaps, instance mismatch, and
digest tampering within an inspected chain.

Page keys, column keys, credential lifecycle, backups, and deployment access
remain the embedder's responsibility. RNovModularDB does not include a KMS,
certificate authority, replication layer, or high-availability coordinator.

## License

RNovModularDB is offered under a commercial license and under the GNU Affero
General Public License. For AGPL licensing, see [LICENSE](LICENSE). For custom
commercial licensing, contact [licensing@aperip.com](mailto:licensing@aperip.com).
