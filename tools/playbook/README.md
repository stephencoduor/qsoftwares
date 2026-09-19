# Partner gate for the field-data playbook

`carbon-playbook.html` is for **registered partners only**. This site is static hosting from a
**public** repository, so there is no server to check a login and nothing in the page source can
be relied on to stay hidden. The playbook body is therefore published **encrypted**, and each
registered partner gets a **personal access code** that decrypts it in their own browser.

## Everyday use (run from the repo root)

```bash
# 1. Someone asks for access (the page's form emails info@qsoftwares.org). Approve them:
node tools/playbook/gate.mjs add --name "Jane Doe" --org "Acme Carbon" --email jane@acme.org --type funding

# 2. The command prints their access code ONCE. Email it to them.
# 3. Publish the rebuilt page:
git add carbon-playbook.html && git commit -m "playbook: register a partner" && git push
```

```bash
node tools/playbook/gate.mjs list                          # who has access
node tools/playbook/gate.mjs revoke --email jane@acme.org  # take access away, then commit + push
node tools/playbook/gate.mjs verify --code CF-XXXX-XXXX-XXXX-XXXX   # does this code open the built page?
node tools/playbook/gate.mjs build                         # rebuild after editing the playbook text
```

A revocation only takes effect once the rebuilt `carbon-playbook.html` is **pushed**.

## What is private, and where it lives

| File | In git? | What it is |
| --- | --- | --- |
| `private/playbook-source.html` | **No** (git-ignored) | The plaintext playbook body. Edit this, then `build`. A backup lives in the private `carbon-pwa` repo under `docs/marketing/`. |
| `private/partners.json` | **No** (git-ignored) | The registry: names, emails, and each partner's key. Back it up somewhere private; if it is lost, every partner needs a new code. |
| `tools/playbook/template.html` | Yes | The public page shell: hero, intro, contents list, the gate and the registration form. |
| `carbon-playbook.html` | Yes | The built page: template + encrypted playbook. Never edit by hand. |

`build` refuses to write the page if it finds playbook body markup in the output.

## How it works

- The body is encrypted with AES-256-GCM under a content key. **Every build uses a fresh key.**
- An access code is 16 characters of Crockford base32 (80 random bits), shown as
  `CF-XXXX-XXXX-XXXX-XXXX`. Typing is forgiving: case, spaces and dashes are ignored, and
  `O`/`I`/`L` are read as `0`/`1`/`1`.
- The code is stretched with PBKDF2-SHA256 (310,000 rounds, per-partner salt) into a key that
  unwraps the content key. The page carries one wrapped copy per active partner.
- The entry list is padded with decoys to a fixed 40 slots, so the page does not reveal how many
  partners there are. More than 40 partners: raise `ENTRY_SLOTS`.
- Revoking drops the partner's entry. Because the next build has a new content key that was never
  wrapped for them, their old code cannot open it.
- "Remember me on this device" keeps the code in that browser's local storage; otherwise it lasts
  for the browser session. Nothing is ever sent to a server.

## What this does and does not protect

- It **does** keep the playbook unreadable to anyone without a valid code, including anyone
  reading the page source or this public repository.
- It does **not** stop a partner from sharing their code or copying the text once unlocked. Codes
  are personal so that a leaked one can be revoked without disturbing anyone else.
- It does **not** log who opened the page or when. That needs a server.
- The intro paragraph, the contents list and the "About" box stay public on purpose: they are the
  pitch for registering.
- Commits made **before** the gate (the first public version of the page) still contain the
  plaintext in this repository's history.
