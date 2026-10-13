# SUIT manifest logger

Testing/debugging helper that parses a SUIT envelope and logs every step,
manifest command. It does not execute conditions,
directives, or operating-system hooks.

The manifest digest and signature are checked separately, mirroring how the
`dress-up` library treats them: the digest is mandatory and always verified,
while the signature is optional.

- Digest: the digest read from the manifest and the digest recomputed locally
  are both printed, so they can be visually compared.
- Signature: if the manifest carries no COSE authentication block, a message
  is logged and verification is skipped entirely. If one is present, its raw
  bytes are logged; when `--pubkey` is supplied, it is cryptographically
  verified and the outcome is logged, otherwise it is accepted unconditionally
  (testing mode) after being logged.

This example is intentionally split into modules:

- `main.rs`: entry point, argument parsing and orchestration only.
- `inspect.rs`: logs envelope/manifest metadata (no execution).
- `digest_check.rs`: reads and recomputes the manifest digest for comparison.
- `signature_check.rs`: reports and optionally verifies the signature.
- `hooks.rs`: retained example hook implementation for reference; it is not
  used by the inspection-only logger.
- `log.rs`: shared log line formatting.

## Usage

```console
cargo run -- <manifest.cbor> [--pubkey <file.pem>]
```

`--pubkey` supplies a PEM-encoded EC public key used to verify a signature, if
one is present in the manifest; omit it to only log the raw signature bytes
without cryptographic verification.
