# RNovModularDB

RNovModularDB is an early-stage Rust database engine focused on modularity, secure storage, lightweight deployment, and fast embedded runtime use cases.

The project is being built as a Cargo workspace with small crates for shared primitives, SQL types, storage, and command-line tooling. The current implementation includes the initial workspace, common engine primitives, and a pure in-memory page backend foundation.

## Goals

- Modular Rust architecture with focused crates and stable internal interfaces.
- Lightweight embedded operation with a pure memory mode that performs no disk writes.
- Encrypted single-file durable storage in later milestones.
- Hybrid memory/disk execution with explicit synchronization state.
- SQL-oriented type, storage, transaction, indexing, and security layers built incrementally.
- Strong security defaults, including reviewed cryptographic primitives instead of custom cryptography.

## Current Status

This repository is in the bootstrap stage. It is not ready for production workloads.

Implemented foundations:

- Cargo workspace with AGPL-3.0-only licensing metadata.
- Common error, configuration, and typed identifier primitives.
- In-memory page backend with fixed page-size validation and no disk sync behavior.

## Build

```bash
cargo check --workspace
```

## Test

```bash
cargo test --workspace
```

## License

RNovModularDB is licensed under AGPL-3.0-only.
