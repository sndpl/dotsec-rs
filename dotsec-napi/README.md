# @dotsec/core

Native Node.js bindings for [dotsec](https://github.com/jpwesselink/dotsec-rs) — parse, validate, and format `.env` files with directive support.

## Install

```bash
npm install @dotsec/core
```

## Usage

```js
import { parse, validate, toJson, format } from '@dotsec/core';

// Parse .env content into structured entries
const entries = parse(`
# @encrypt
DB_URL="postgres://localhost"
DEBUG=true
`);
// [
//   { key: "DB_URL", value: "postgres://localhost", quoteType: "Double", directives: [{ name: "encrypt" }] },
//   { key: "DEBUG", value: "true", quoteType: "None", directives: [] }
// ]

// Validate directives and values
const errors = validate('# @bogus\nFOO="bar"\n');
// [{ key: "FOO", message: "unknown directive @bogus..." }]

// Convert to JSON
const json = toJson('FOO=bar\nPORT=3000\n');
// '{"FOO":"bar","PORT":"3000"}'

// Roundtrip format
const formatted = format('FOO=bar\n');
// 'FOO=bar\n'
```

### Schema operations

```js
import {
  validateAgainstSchema, formatBySchema, discoverSchema,
  loadSchema, parseSchema, schemaToJsonSchema, schemaToTypescript
} from '@dotsec/core';
import { readFileSync } from 'node:fs';

// Discover and load a schema file
const schemaPath = discoverSchema('.sec');           // finds dotsec.schema or null
const schemaEntries = loadSchema();                  // parses discovered schema or null

// Validate .env against a schema
const source = readFileSync('.env', 'utf8');
const schemaSource = readFileSync('dotsec.schema', 'utf8');
const errors = validateAgainstSchema(source, schemaSource);

// Reorder .env to match schema key ordering
const reordered = formatBySchema(source, schemaSource);

// Code generation from schema
const jsonSchema = schemaToJsonSchema(schemaSource);   // JSON Schema (draft-07) string
const typescript = schemaToTypescript(schemaSource);    // TypeScript declarations
```

## Supported directives

- `@encrypt` / `@plaintext` — mark variables for encryption
- `@default-encrypt` / `@default-plaintext` — file-level defaults
- `@type=string|number|boolean|enum("a","b")` — value type validation
- `@format=email|url|uuid|ipv4|ipv6|date|semver` — format validation
- `@pattern="regex"` — regex pattern validation
- `@min` / `@max` — numeric range constraints
- `@min-length` / `@max-length` — string length constraints
- `@not-empty` — value must not be empty
- `@optional` — key not required in schema validation
- `@description` — human-readable description
- `@deprecated` — mark key as deprecated (optional message)
- `@push=aws-ssm|aws-secrets-manager` — push targets with options
- `@provider=local|aws`, `@key-id`, `@region` — file-level encryption config

See the [full documentation](https://jpwesselink.github.io/dotsec-rs/guide/directives.html) for details.

## Platforms

Pre-built binaries are available for:

- macOS (ARM64, x64)
- Linux (ARM64, x64, glibc)
- Windows (ARM64, x64)

## License

MIT — [github.com/jpwesselink/dotsec-rs](https://github.com/jpwesselink/dotsec-rs)
