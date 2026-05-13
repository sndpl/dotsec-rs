# Getting Started

dotsec encrypts your `.env` files into `.sec` files. The `.sec` file is committed to git as the single source of truth for your secrets — no more sharing credentials over Slack or managing secret vaults.

Encryption uses age (X25519 + ChaCha20-Poly1305) by default. AWS KMS is also supported for enterprise teams.

## Install

:::tabs

@tab npm

```bash
npm install -g dotsec
```

@tab cargo

```bash
cargo install dotsec
```

@tab npx

```bash
npx dotsec set API_KEY sk-live-xxx
```

:::

## Quick start

```bash
dotsec set API_KEY sk-live-xxx --encrypt  # add a secret (auto-creates .sec + keypair)
dotsec set PORT 3000                      # add a plaintext var
dotsec run -- node server.js              # run with decrypted env vars (from .sec)
dotsec run --env-file .env -- node server.js  # or from a plain .env
```

That's it. Your `.sec` file goes into git, your `.sec.key` stays in `.gitignore`.

## Import an existing .env

```bash
dotsec import              # .env → .sec (interactive)
dotsec import -y           # auto-detect types and encryption
```

## Core workflow

```
.env (plaintext, gitignored)          .sec (encrypted, committed)
┌─────────────────────────┐           ┌──────────────────────────┐
│ DATABASE_URL=postgres://│  encrypt  │ DATABASE_URL=ENC[base64] │
│ API_KEY=sk-live-xxx     │ ───────▶  │ API_KEY=ENC[base64]      │
│ DEBUG=true              │           │ DEBUG=true                │
└─────────────────────────┘           │ __DOTSEC_KEY__="wrapped" │
                                 ◀─── └──────────────────────────┘
                                decrypt
```

Each secret is encrypted individually with AES-256-GCM using a data encryption key (DEK). The DEK is wrapped by your keypair (or AWS KMS) and stored in the `.sec` file. This makes `.sec` files git-mergeable — changing one secret only affects that line.

## Commands

```bash
dotsec set KEY value              # add or update a variable
dotsec show                       # display decrypted .sec contents
dotsec export -o .env             # .sec → .env (decrypts to file)
dotsec run -- npm start           # inject decrypted vars into a command
dotsec validate                   # check directives and values
dotsec diff .sec.staging          # compare .sec files
dotsec rotate-key                 # generate new DEK, re-encrypt all values
dotsec extract-schema             # extract directives into dotsec.schema
dotsec schema export              # export schema as JSON Schema
dotsec schema export --format ts  # generate TypeScript types
```

## Encryption providers

### Local (default)

No cloud account needed. Uses age (X25519 + ChaCha20-Poly1305) keypairs.

- Private key: `.sec.key` file or `DOTSEC_PRIVATE_KEY` env var
- Auto-generated on first use
- Team sharing: send `.sec.key` via secure channel

### AWS KMS

For enterprise teams needing IAM-controlled access and CloudTrail audit logs.

```bash
dotsec init  # choose "aws", enter KMS key ID and region
```

See the [encryption guide](/guide/encryption) for details.

## Multi-environment support

Use separate `.sec` files per environment, each with its own keypair:

```bash
SEC_FILE=.sec.staging dotsec set DB_URL postgres://staging-db
SEC_FILE=.sec.production dotsec set DB_URL postgres://prod-db
```

Extract shared directives into a `dotsec.schema` file:

```bash
dotsec extract-schema              # creates dotsec.schema from .sec
dotsec validate                    # validates against schema
dotsec schema export --format ts   # generate TypeScript types
```

The schema uses the same directive syntax with bare keys (no values):

```bash
# @default-encrypt

# @type=string @not-empty
DATABASE_URL

# @type=number @min=0 @max=65535
PORT

# @type=enum("development", "staging", "production")
NODE_ENV
```

See the [directives guide](/guide/directives#schema-files) for details.

## Library

### Node.js — `@dotsec/core`

Native bindings for parsing, validating, formatting, and code generation:

```bash
npm install @dotsec/core
```

```js
import {
  parse, validate, toJson, format,
  loadSchema, validateAgainstSchema, formatBySchema,
  parseSchema, schemaToJsonSchema, schemaToTypescript,
  discoverSchema, generateHeader, hasHeader
} from '@dotsec/core';
import { readFileSync } from 'node:fs';

const source = readFileSync('.env', 'utf8');

// Parse into structured entries
const entries = parse(source);
for (const entry of entries) {
  console.log(`${entry.key} = ${entry.value}`);
}

// Validate directives
const errors = validate(source);
for (const err of errors) {
  console.error(`[${err.severity}] ${err.key}: ${err.message}`);
}

// Convert to JSON or normalize formatting
const json = toJson(source);
const formatted = format(source);
```

#### Schema operations

```js
// Auto-discover and load schema
const schema = loadSchema()   // finds dotsec.schema, returns entries or null
const path = discoverSchema('.sec')  // just returns the path or null

// Validate .env against schema
const schemaSource = readFileSync('dotsec.schema', 'utf8')
const errors = validateAgainstSchema(source, schemaSource)

// Reorder .env to match schema key ordering
const reordered = formatBySchema(source, schemaSource)

// Generate JSON Schema or TypeScript from schema
const jsonSchema = schemaToJsonSchema(schemaSource)   // JSON string
const typescript = schemaToTypescript(schemaSource)    // TypeScript code string
```

### Rust — `dotsec-core`

> **Note:** `dotsec-core` is not published to crates.io. Use a git dependency instead:

```toml
[dependencies]
dotsec-core = { git = "https://github.com/jpwesselink/dotsec-rs" }
```

```rust
use dotsec_core::dotenv::{parse_dotenv, lines_to_entries, validate_entries};

let content = std::fs::read_to_string(".env").unwrap();
let lines = parse_dotenv(&content).unwrap();
let entries = lines_to_entries(&lines);

for entry in &entries {
    println!("{} = {}", entry.key, entry.value);
}

let errors = validate_entries(&entries);
for err in &errors {
    eprintln!("[{:?}] {}: {}", err.severity, err.key, err.message);
}
```

## Channels

| Channel | npm | Cargo |
|---------|-----|-------|
| Stable | `npm install dotsec` | `cargo install dotsec` |
| Beta | `npm install dotsec@beta` | — |

## Project structure

```
dotsec-core/       Core library (encryption, decryption, interpolation, redaction)
dotsec/            CLI binary (uses dotsec-core)
  npm/             npm platform packages
dotsec-napi/       Node.js bindings (published as @dotsec/core)
  npm/             npm platform packages
dotenv/            .env/.sec parser (internal)
crypto/            Shared cryptography + local age encryption (internal)
aws/               AWS KMS encryption + push (internal)
```
