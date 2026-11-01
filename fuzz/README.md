# Parser fuzzing

The post-quantum follow-up extends `formats` and `stanza` through the production APIs in `src/post_quantum.rs`. Native tagged recipients, version-3 identities, dedicated names and canonical tagged-stanza fields now enter the same fuzz harnesses as the classical parsers. The classical `Scheme` enum remains limited to RSA/P-256. Current local checks (`notes/post-quantum-parser-fuzz.md`) pass: 82 fixed seeds and four million Rust ASan inputs across all four targets, without a crash. The machine-readable report (`notes/post-quantum-parser-fuzz.json`) records the exact inputs and tools.

The multi-scheme milestone extended the three classical targets and seeds to cover RSA and P-256 formats. A fourth target, `custody_record`, exercises the reviewed production custody codecs, including independently expected identity checks. The fuzz workspace selects `crates/post_quantum` and the exact local AWS-LC patch; no evaluation package is linked. The PQ request-boundary campaigns (`notes/pq-wire-fuzz.json`) completed 500,000 executions each for `helper_frame` and `custody_record` without a crash, with Rust AddressSanitizer enabled and a clean exact fuzz-graph advisory scan. Its bounded sanitizer campaign (`notes/pq-custody-binding/parser-fuzz-validation.json`) completed 500,000 executions in five seconds without a crash. Rust AddressSanitizer was enabled; native AWS-LC C instrumentation is not claimed. The RSA backend replacement campaigns (`notes/rsa-backend-fuzz.json`) exercised 20,011,230 inputs without a crash after adopting AWS-LC public-key validation. Rust ASan was enabled; native AWS-LC C instrumentation is not claimed. The earlier multi-scheme campaigns (`notes/multi-scheme-fuzz-results.json`) covered 19,908,263 inputs. Native-blob decoding is exercised by portable regression tests; these fuzz targets do not yet include that decoder.

These libFuzzer targets exercise Linux parsing only. They never launch a helper, access the TPM, create keys or load an identity from the machine.

| Target | Coverage |
| --- | --- |
| `formats` | Classical and native PQ recipient/identity decoding, canonical round trips, fingerprints, dedicated key names and rejection across parser namespaces |
| `helper_frame` | Frame lengths/status/operations 1–10, fragmented reads, classical/PQ request decoding, canonical round trips and trailing-byte rejection |
| `stanza` | Classical version/fingerprint/body checks and PQ canonical routing tag, encapsulation, argument count and exact body length |
| `custody_record` | Canonical PQ identity/name, bounded `ATWPQC01` record, retained expected identity, canonical round trips and substitution/trailing rejection |

Install the tooling and seed the corpus:

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal
python3 fuzz/seed-corpus.py
```

Run bounded sanitizer-enabled sessions from the repository root:

```sh
cargo +nightly fuzz run formats -- -max_total_time=60 -max_len=4096
cargo +nightly fuzz run helper_frame -- -max_total_time=60 -max_len=8300
cargo +nightly fuzz run stanza -- -max_total_time=60 -max_len=4096
cargo +nightly fuzz run custody_record --sanitizer address -- -max_total_time=60 -runs=500000 -max_len=8192
```

For the bounded four-target local check, run `python3 scripts/fuzz-post-quantum-parsers.py`. It uses a dedicated build/corpus directory, replays all deterministic public seeds, then runs each target for at most 30 seconds or one million inputs. It writes a fresh report and retains logs under `target/post-quantum-parser-fuzz/`. The report path and logs are exclusive, so a repeated run needs a fresh destination or deliberate removal of only that prior local run's generated files.

Increase `-max_total_time` for longer campaigns or omit it for continuous fuzzing. Build output, corpus mutations and crash artifacts are ignored. Seed data is synthetic public material, never an enrolled identity or real ciphertext. On a crash, retain the artifact locally, minimize it with `cargo +nightly fuzz tmin TARGET PATH`, fix the issue and add a focused regression test.

A clean bounded run only describes its exercised corpus and duration. These targets do not cover Windows CNG buffers, live helper lifecycle, side channels or post-quantum security. Hardware failure tests and independent security reviews remain separate checks.
