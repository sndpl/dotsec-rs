# How Encryption Works

## Overview

dotsec uses **per-value envelope encryption**: each secret is encrypted individually with a data encryption key (DEK), so `.sec` files are git-mergeable — changing one secret only affects that line.

Two providers are supported:

- **Local** (default) — age (X25519 + ChaCha20-Poly1305) keypair, no cloud account needed
- **AWS KMS** — IAM-controlled access, CloudTrail audit logs, enterprise teams

## Local encryption (default)

dotsec uses [age](https://age-encryption.org/) for key management. Each `.sec` file has a corresponding keypair.

<!-- TODO: add a "Why age?" section here. Cover: small audited library (Cure53 2021),
multi-recipient support enables painless team key rotation later, standard interchange
format (`age`/`rage` CLI can decrypt the wrapped DEK if dotsec ever broke), no curve or
parameter choices to footgun, maintained Rust crate by the spec author. Contrast vs. raw
libsodium/NaCl sealed boxes (no multi-recipient, no interchange format) and GPG (too much
surface area, web-of-trust we don't need). -->


### How it works

1. On first use, generate an X25519 keypair → store private key in `.sec.key`
2. Generate a random AES-256 DEK
3. Wrap the DEK using age (X25519 + ChaCha20-Poly1305) with the public key
4. Encrypt each secret value locally with AES-256-GCM using the DEK
5. Store the age-wrapped DEK as `__DOTSEC_KEY__` in the `.sec` file

On decryption, load the private key (from `DOTSEC_PRIVATE_KEY` env var or `.sec.key` file), unwrap the DEK, decrypt each `ENC[...]` value locally.

### What the `.sec` file looks like

```bash
# dotsec v5 — encrypted environment file
# https://github.com/jpwesselink/dotsec-rs
# @provider=local @default-encrypt

# @encrypt
DATABASE_URL=ENC[base64...]

# @plaintext
NODE_ENV="production"

# do not edit the line below, it is managed by dotsec
__DOTSEC_KEY__="base64-encoded-age-wrapped-dek..."
```

### Key file

The private key is stored in `.sec.key` as a plain age identity string:

```
AGE-SECRET-KEY-1QPZZY...
```

Key discovery order (checked in this order):
1. `DOTSEC_PRIVATE_KEY` environment variable
2. `<sec-file>.key` file alongside the `.sec` file

For CI/CD, use the env var — no file writes needed:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."
```

## AWS KMS

For enterprise teams needing IAM-controlled access and CloudTrail audit logs.

### How it works

dotsec uses AWS KMS **envelope encryption**:

1. Request a data key from KMS (`GenerateDataKey` with AES-256)
2. KMS returns both a plaintext DEK and a KMS-wrapped copy
3. Encrypt each secret value locally with AES-256-GCM using the plaintext DEK
4. Store the KMS-wrapped DEK as `__DOTSEC_KEY__` in the `.sec` file
5. Discard the plaintext DEK

On decryption, KMS unwraps the DEK first (`Decrypt`), then each `ENC[...]` value is decrypted locally. The actual secret data never leaves your machine — only the wrapped key touches KMS.

### Setup

See [Setup → AWS KMS](/guide/setup#aws-kms-setup) for configuration steps.

### What the `.sec` file looks like

```bash
# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

DATABASE_URL=ENC[base64...]
NODE_ENV="production"

__DOTSEC_KEY__="base64-encoded-kms-wrapped-dek..."
```

## Ciphertext format

Every `ENC[...]` value contains:

```
base64(32-byte-commitment || 12-byte-nonce || ciphertext || 16-byte-auth-tag)
```

- **Commitment** — HMAC-SHA256 of the DEK, verified before decryption to detect wrong-key attempts early
- **Nonce** — random 12 bytes per value (no nonce reuse even if the value is unchanged)
- **Padding** — plaintext is padded to 64-byte blocks with 0–1 random extra blocks to hide length

## Git mergeability

Because each value is encrypted independently, two developers can change different secrets in the same `.sec` file and merge without conflicts:

```diff
  # @encrypt
- API_KEY=ENC[old-value...]
+ API_KEY=ENC[new-value...]

  # @encrypt
  DB_PASSWORD=ENC[unchanged...]
```

Only the lines that were actually modified show up in the diff. The `__DOTSEC_KEY__` stays the same as long as the key isn't rotated.

## Key rotation

Rotate the DEK without changing any plaintext values:

```bash
dotsec rotate-key
```

This decrypts all values with the old DEK, generates a new DEK (local: new random DEK wrapped with the same age key; KMS: new data key from KMS), and re-encrypts everything. The `__DOTSEC_KEY__` line is updated.

Use this periodically or after a suspected key compromise. For a full key compromise (private key leaked), generate a new keypair first:

```bash
# Local: generate a new keypair, then rotate
dotsec init          # generates new .sec.key
dotsec rotate-key    # re-wraps all values with new key
```
