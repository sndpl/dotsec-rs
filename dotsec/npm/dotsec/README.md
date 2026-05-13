# dotsec

`.env` files, encrypted and committed to git.

dotsec encrypts your secrets into a `.sec` file — committed alongside your code as the single source of truth. Decrypt at runtime with no secrets ever written to disk.

## Install

```bash
npm install -g dotsec
```

## Quick start

```bash
dotsec set API_KEY sk-live-xxx --encrypt   # creates .sec + keypair on first run
dotsec set PORT 3000                       # plaintext variable
dotsec run -- node server.js               # inject decrypted vars into your process
```

No AWS account. No config file. No setup step. `.sec` goes into git, `.sec.key` stays out.

## Common commands

```bash
dotsec set KEY value --encrypt     # add/update an encrypted variable
dotsec import -y                   # .env → .sec (auto-detect types)
dotsec run -- <command>            # run with decrypted env vars injected
dotsec show --reveal               # display decrypted contents
dotsec export -o .env              # .sec → .env
dotsec validate                    # check types and constraints
dotsec extract-schema              # extract directives → dotsec.schema
dotsec schema export --format ts   # generate TypeScript types
dotsec rotate-key                  # re-encrypt all values with a new DEK
```

## CI/CD

Set the private key as an environment variable — no file writes needed:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."
```

## Documentation

**[Docs →](https://jpwesselink.github.io/dotsec-rs)**

## License

MIT — [github.com/jpwesselink/dotsec-rs](https://github.com/jpwesselink/dotsec-rs)
