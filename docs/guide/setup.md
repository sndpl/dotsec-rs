# Setup

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

Verify the install:

```bash
dotsec --version
```

## Zero-config start

No AWS account, no config file, no setup step required. The first `dotsec set` auto-creates everything:

```bash
dotsec set API_KEY sk-live-xxx --encrypt
```

This creates:
- `.sec` — your encrypted secrets file (commit this)
- `.sec.key` — your age private key (never commit this)

Make sure `.sec.key` is in your `.gitignore` — dotsec warns on `set`/`init` if no `.gitignore` rule excludes it.

## Team sharing

Share the `.sec.key` file with teammates over a secure channel (1Password, Bitwarden, Signal, etc.). Each person puts it alongside their `.sec` file.

For CI/CD, set the key as an environment variable:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."
```

dotsec checks `DOTSEC_PRIVATE_KEY` before looking for a key file, so this works in any CI system without needing to write files.

Key discovery order:
1. `DOTSEC_PRIVATE_KEY` environment variable
2. `<sec-file>.key` file in the same directory

## AWS KMS setup

For teams that need IAM-controlled access and CloudTrail audit logs:

1. Create a KMS key in AWS (symmetric, AES-256):

   ```bash
   aws kms create-alias \
     --alias-name alias/dotsec \
     --target-key-id <your-key-id>
   ```

2. Initialize dotsec with AWS as the provider:

   ```bash
   dotsec init
   # Choose "aws", enter your key ID and region
   ```

3. AWS credentials are picked up automatically from `~/.aws/credentials`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, or an instance role.

See the [encryption guide](/guide/encryption#aws-kms) for more on how KMS envelope encryption works.

## Multiple environments

Each environment gets its own `.sec` file with its own keypair:

```bash
SEC_FILE=.sec.staging dotsec set DB_URL postgres://staging-db
SEC_FILE=.sec.production dotsec set DB_URL postgres://prod-db
```

Share directives (types, constraints) across environments using a schema file:

```bash
dotsec extract-schema   # creates dotsec.schema from .sec
dotsec validate         # validates .sec against schema
```

See the [directives guide](/guide/directives#schema-files) for details.
