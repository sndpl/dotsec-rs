# dotsec

`.env` files, encrypted and committed to git.

dotsec encrypts your secrets into a `.sec` file — committed alongside your code as the single source of truth. Decrypt at runtime with no secrets ever written to disk.

## Install

```bash
npm install -g dotsec
# or
cargo install dotsec
```

## Quick start

```bash
dotsec set API_KEY sk-live-xxx --encrypt   # creates .sec + keypair on first run
dotsec set PORT 3000                       # plaintext variable
dotsec run -- node server.js               # inject decrypted vars into your process
```

That's it. `.sec` goes into git. `.sec.key` stays out (auto-added to `.gitignore`).

No AWS account. No config file. No setup step.

## How it works

```
.env (plaintext, gitignored)        .sec (encrypted, committed)
┌────────────────────────┐          ┌──────────────────────────┐
│ DATABASE_URL=postgres://│ encrypt │ DATABASE_URL=ENC[base64] │
│ API_KEY=sk-live-xxx    │ ──────▶ │ API_KEY=ENC[base64]      │
│ PORT=3000              │         │ PORT=3000                 │
└────────────────────────┘         │ __DOTSEC_KEY__="..."     │
                             ◀──── └──────────────────────────┘
                            decrypt
```

Each secret is encrypted individually with AES-256-GCM using a data encryption key (DEK). The DEK is wrapped by your age keypair and stored in the `.sec` file. This makes `.sec` files git-mergeable — changing one secret only affects that line.

## Common commands

```bash
dotsec set KEY value --encrypt     # add/update an encrypted variable
dotsec set KEY value               # add/update a plaintext variable
dotsec import                      # .env → .sec (interactive)
dotsec import -y                   # .env → .sec (auto-detect types)
dotsec run -- <command>            # run with decrypted env vars
dotsec show                        # display decrypted .sec (values masked)
dotsec show --reveal               # display decrypted .sec (plaintext)
dotsec export -o .env              # .sec → .env
dotsec validate                    # check types and constraints
dotsec extract-schema              # extract directives → dotsec.schema
dotsec schema export --format ts   # generate TypeScript types from schema
dotsec rotate-key                  # generate new DEK, re-encrypt all values
```

## Team sharing

Share `.sec.key` over a secure channel (1Password, Bitwarden, etc.). For CI/CD:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."
```

## AWS KMS

For teams needing IAM-controlled access and CloudTrail audit logs:

```bash
dotsec init   # choose "aws", enter KMS key ID and region
```

## Project structure

```
dotsec-core/       Core library (encryption, decryption, interpolation, redaction)
dotsec/            CLI binary
  npm/             npm platform packages
dotsec-napi/       Node.js bindings (published as @dotsec/core)
  npm/             npm platform packages
dotenv/            .env/.sec parser (internal)
crypto/            Shared cryptography + local age encryption (internal)
aws/               AWS KMS encryption (internal)
```

## npm packages

| Package | Description |
|---------|-------------|
| `dotsec` | CLI binary |
| `@dotsec/core` | Native Node.js bindings for parsing, validating, and formatting |

## Release channels

| Channel | Trigger | Install |
|---------|---------|---------|
| `latest` | Release PR merge | `npm install dotsec` |
| `beta` | Every commit on `main` | `npm install dotsec@beta` |
| `pr-N` | Every PR commit | `npm install dotsec@pr-42` |
| crates.io | Release PR merge | `cargo install dotsec` |

---

**[Full documentation →](https://jpwesselink.github.io/dotsec-rs)**
