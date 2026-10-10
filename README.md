# logos-signer-interface

`logos.signer/1`, the contract every Logos signer module implements so the signer manager can list
its accounts and have it sign: `keystore_module` for keys kept in files, and one module per hardware
wallet.

- [`signer.lidl`](signer.lidl): the IPC contract. A consumer lists it under `interface_dependencies`
  and binds it to a signer module at runtime.
- [`docs/interface.md`](docs/interface.md): the JSON every method takes and returns, the rules and
  the error codes.
- The Rust crate `logos-signer-interface`:
  - `wire`: the payload types.
  - `verify`: checks a signature against an account's address or xpub.
  - `jobs`: job bookkeeping a signer module can reuse.
  - `json`: builds a module's replies from a `Signer` and reads them back.
  - `conformance` (feature): the suite every signer runs in its own CI.
  - `mock` (feature): a software signer for tests.

```toml
logos-signer-interface = { git = "https://github.com/logos-co/logos-signer-interface", rev = "…" }
```

```sh
cargo test --all-features
```

Licensed under MIT or Apache-2.0.
