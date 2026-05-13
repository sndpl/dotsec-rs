---
pageType: home
hero:
  name: dotsec
  text: .env without .env
  tagline: Stop sharing secrets over Slack. Encrypt your .env, commit it to git, decrypt at runtime. Done.
  actions:
    - theme: brand
      text: Get Started →
      link: /guide/
    - theme: alt
      text: npm install -g dotsec
      link: /guide/setup
features:
  - icon: 🔐
    title: Encrypted in git
    details: Your .env becomes a .sec file — encrypted and committed alongside your code. One source of truth, version-controlled.
    link: /guide/encryption
  - icon: 🧠
    title: Decrypted in memory only
    details: Secrets are never written to disk. Decrypted on the fly when you run your app, then gone.
    link: /guide/commands#dotsec-run
  - icon: 🚀
    title: Zero config
    details: One command to start. dotsec set auto-creates an encrypted .sec file — no AWS, no cloud accounts, no setup.
    link: /guide/
  - icon: 🛡️
    title: Redacted output
    details: Accidentally logging a secret? dotsec intercepts stdout and redacts sensitive values before they hit your terminal or CI logs.
    link: /guide/commands#dotsec-run
  - icon: 📦
    title: Works everywhere
    details: Available as a CLI via npm and cargo. Native Node.js bindings (@dotsec/core) for parsing and validating .env files programmatically.
    link: /guide/#library
  - icon: ✅
    title: Validation built in
    details: Directives like @type, @format, @pattern, @min/@max let you enforce rules on your env vars. Shared schema files keep constraints consistent across environments.
    link: /guide/directives
---
