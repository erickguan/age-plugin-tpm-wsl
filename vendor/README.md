# Reviewed local dependency changes

I retain a local `aws-lc-rs 1.18.2` source copy to supply the deterministic ML-KEM seed interface required by Windows TPM custody. The public safe API otherwise imports expanded private keys. The local copy also preserves the accepted KEM error-path wiping guards. This copy passes the shared-module staging review and validation recorded in `notes/pq-module-integration.md`. The workspace selects it with the consumer integration checks and review accepted in `notes/pq-workspace-integration.md`.

[aws-lc-rs-provenance.json](aws-lc-rs-provenance.json) identifies the original registry archive by SHA-256, every original/patched file hash and the exact reviewed patch (`notes/aws-lc-mlkem-evaluation/aws-lc-rs-seed.patch`). Only `Cargo.toml` and `src/kem.rs` differ from the archive. The original licenses and notices are retained. The seed-interface acceptance (`notes/aws-lc-mlkem-evaluation/acceptance.md`) records the prior review, tests and limits; The relocated module, local source copy and workspace consumer wiring pass their checks and independent reviews. The production Windows custody adapter still needs implementation, validation and review.

The optional `experimental-kem-seed` feature enables the already pinned native backend's full bindings. It is unavailable with the FIPS backend and makes no FIPS approval claim. The native `aws-lc-sys` source remains a locked registry dependency. I have not copied or modified its C implementation here.

Changes to this copy must update its provenance and receive review of the exact source and enabled integration. Do not edit the Cargo registry cache to apply patches.
