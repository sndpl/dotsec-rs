# Directives

Directives are comments that control encryption, typing, validation, and push targets. They sit on the line immediately above the key they apply to:

```bash
# @encrypt
# @type=string @format=url @not-empty
DATABASE_URL="postgres://user:pass@localhost:5432/mydb"

# @plaintext
# @type=enum("development", "preview", "production")
NODE_ENV="production"

# @plaintext
# @type=number @min=0 @max=65535
PORT=3000
```

Directives must start with `#` — writing `@directive` without `#` is a parse error.

## Available directives

### File-level directives

These go at the top of the `.sec` file (or in `dotsec.schema`) and apply to the whole file:

| Directive | Value | Description |
|-----------|-------|-------------|
| `@provider` | `local`, `aws` | Encryption provider (`local` is the default) |
| `@key-id` | KMS key ID or alias | KMS key to use (AWS only) |
| `@region` | AWS region | AWS region (AWS only) |
| `@default-encrypt` | none | Encrypt all variables by default |
| `@default-plaintext` | none | Don't encrypt by default |

### Encryption directives

| Directive | Description |
|-----------|-------------|
| `@encrypt` | Mark variable for encryption |
| `@plaintext` | Exclude from encryption (overrides file-level default) |

### Type directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `@type` | `string`, `number`, `boolean`, `enum("a", "b")` | Type validation |
| `@format` | `email`, `url`, `uuid`, `ipv4`, `ipv6`, `date`, `semver` | Format validation |
| `@pattern` | `"regex"` | Regex pattern validation (quoted) |

### Constraint directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `@min` | number | Minimum value (requires `@type=number`) |
| `@max` | number | Maximum value (requires `@type=number`) |
| `@min-length` | number | Minimum string length |
| `@max-length` | number | Maximum string length |
| `@not-empty` | none | Value must not be empty |
| `@optional` | none | Key is not required (used in schema validation) |

### Metadata directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `@description` | text | Human-readable description |
| `@deprecated` | `"message"` (optional) | Mark key as deprecated |
| `@push` | `aws-ssm(...)`, `aws-secrets-manager(...)` | Push targets |

### Examples

```bash
# String with format and pattern validation
# @type=string @format=url @pattern="^https://"
CALLBACK_URL="https://example.com/webhook"

# Number with range
# @type=number @min=1024 @max=65535
PORT=3000

# String with length constraints
# @type=string @min-length=1 @max-length=255 @not-empty
APP_NAME="my-app"

# Optional key (not required in schema validation)
# @optional
SENTRY_DSN="https://sentry.io"

# Deprecated key
# @deprecated="Use NEW_API_KEY instead"
OLD_API_KEY="sk-..."

# Format validators
# @format=email
ADMIN_EMAIL="admin@example.com"

# @format=uuid
SESSION_ID="550e8400-e29b-41d4-a716-446655440000"

# @format=semver
APP_VERSION="2.1.0"
```

## Push target syntax

```bash
# Simple
# @push=aws-ssm

# With parameters (values must be quoted)
# @push=aws-ssm(path="/myapp/prod", prefix="/app")

# Multiple targets
# @push=aws-ssm(path="/myapp/prod"), aws-secrets-manager(path="/myapp/prod/db")
```

## Schema files

When a project has multiple `.sec` files (dev, staging, production), per-key directives would be duplicated across all files. A **schema file** (`dotsec.schema`) solves this by extracting shared directives into one place.

### Schema format

The schema uses the same directive syntax, but keys have no values:

```bash
# @default-encrypt

# @type=string @push=aws-ssm @not-empty
DATABASE_URL

# @type=number @min=0 @max=65535
PORT

# @type=enum("development", "staging", "production")
NODE_ENV

# @optional @format=url
SENTRY_DSN
```

### How it works

With a schema in place:

- **Schema file** (`dotsec.schema`) holds all per-key directives: `@type`, `@push`, `@encrypt`, `@format`, `@pattern`, `@min`/`@max`, `@optional`, `@deprecated`, etc.
- **`.sec` files** hold only file-level directives (`@provider`, `@key-id`, `@region`) and key=value pairs
- `dotsec validate` checks `.sec` entries against the schema: missing keys, extra keys, type mismatches, constraint violations
- `dotsec set` automatically writes new key directives to the schema (not inline in `.sec`)
- Inline per-key directives in `.sec` files are an **error** when a schema exists — use `dotsec remove-directives` to clean them up

### Directive classification

| Belongs in schema | Belongs in `.sec` |
|---|---|
| `@type`, `@format`, `@pattern` | `@provider` |
| `@min`, `@max`, `@min-length`, `@max-length` | `@key-id` |
| `@encrypt`, `@plaintext` | `@region` |
| `@push`, `@optional` | |
| `@not-empty`, `@deprecated`, `@description` | |
| `@default-encrypt`, `@default-plaintext` | |

### Discovery

The schema file is found automatically:

1. `--schema` CLI flag
2. `DOTSEC_SCHEMA` environment variable
3. `dotsec.schema` in the same directory as the `.sec` file

### Creating a schema

Run `dotsec extract-schema` on an existing `.sec` file to extract per-key directives into `dotsec.schema`:

```bash
dotsec extract-schema
```

See [extract-schema command](/guide/commands#dotsec-extract-schema) for details.

## Choosing between inline and schema

**Use inline directives** when you have a single environment or a small project. Everything lives in one `.sec` file — nothing extra to manage.

**Use a schema file** when you have multiple environments, collaborate with a team, or want to generate typed code. A shared `dotsec.schema` keeps directive definitions in one place and prevents drift.

**Migration path**: start with inline directives, then run `dotsec extract-schema` when you're ready. This moves per-key directives to `dotsec.schema` and strips them from your `.sec` file.

## Variable interpolation

`${VAR}` references are resolved at runtime by `dotsec run`. Single-quoted values are not interpolated (bash convention).

```bash
# @type=string
BASE_URL="https://api.example.com"

# @type=string
WEBHOOK_URL="${BASE_URL}/webhooks"
```

## Configuration

All file-level configuration lives in the `.sec` file as directives — no external config file needed:

```bash
# @provider=local @default-encrypt

DATABASE_URL="postgres://..."
API_KEY="sk-..."
```

Use `--sec-file` to specify a different `.sec` file:

```bash
dotsec --sec-file .sec.production show
```
