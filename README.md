<h1 align="center">🛡️ Praxis — the guardrail for agentic AI</h1>

<p align="center">
  <strong>Let AI agents touch your computer. Without the risk.</strong>
</p>

<p align="center">
  <a href="https://github.com/praxisgaurdrails/praxis-lite/actions/workflows/tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/praxisgaurdrails/praxis-lite/tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://pypi.org/project/praxis-guardrail/"><img src="https://img.shields.io/pypi/v/praxis-guardrail?style=flat-square&color=blue" alt="PyPI"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-informational?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/tests-516%20passing-brightgreen?style=flat-square" alt="516 tests">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License"></a>
</p>

**Praxis** is an **on-device guardrail** for AI agents. It sits between the AI tools you
already use — ChatGPT/Codex, Claude, Cursor, any MCP client — and your machine. Before an
agent reads a file, deletes something, or runs an action, Praxis checks it against your
policy and decides: **allow, block, or ask you first.**

**Yours, on your hardware.** Praxis runs entirely on your computer. Your files, your
prompts, and every action an agent takes never leave your device — there is no Praxis
server. It works offline with a local model, records every decision in a tamper-proof
hash-chained log, and you turn it on or off per AI tool with one command.

> This repo is **Praxis Lite** — the free, **MIT-licensed** core: the on-device MCP
> filesystem guardrail. `pip install praxis-guardrail`.

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#what-it-looks-like">See it work</a> ·
  <a href="#whats-in-lite">What's in Lite</a> ·
  <a href="#security">Security</a>
</p>

---

## Why Praxis

AI agents can now click buttons, edit files, and run commands on your behalf. Almost none
of them have a guardrail. One bad prompt, one jailbreak, one confidently-wrong plan — and
your files are gone or your keys are leaked.

Praxis is the missing safety layer:

- 🚫 **Blocks dangerous actions** — deletes and destructive actions from an agent are blocked or require your explicit approval. No accidents.
- 🔑 **Refuses your secrets** — SSH keys, cloud credentials, keychains, and `.env` files are never handed to an AI, no matter how it asks.
- 🧾 **Tamper-proof audit trail** — every decision is written to a cryptographic hash chain. See exactly what each agent did, and prove it wasn't altered.
- 📴 **Works offline** — no internet? Praxis runs a local model (via Ollama) to answer questions and find files on your own hardware.
- 🎛️ **You're in control** — trusted for you, restricted for agents. Enable/disable per tool. A panic switch revokes everything instantly.

---

## Install

```bash
pip install praxis-guardrail
praxis --version
```

Requires Python 3.11+. Works on macOS, Windows, and Linux.

Or from source:

```bash
git clone https://github.com/praxisgaurdrails/praxis-lite.git
cd praxis-lite
pip install -e .
```

---

## Quick start

Connect Praxis to the AI tools you already use, then use your AI normally.

```bash
# 1. See which AI tools are installed on your machine
praxis clients

# 2. Turn Praxis on in every detected tool (Codex, Claude Desktop, Cursor, ...)
praxis install

# 3. Restart your AI tool so it picks up Praxis
```

That's it. Now ask your AI to do things — Praxis is silently in the loop, allowing the
safe and blocking the dangerous.

Turn it on or off per tool anytime:

```bash
praxis enable codex        # add Praxis to ChatGPT/Codex
praxis disable cursor      # remove it from Cursor
praxis clients             # check status
```

---

## What it looks like

Once connected, ask your AI agent to do something. Here's Praxis governing a real agent:

```text
agent > find my passport
  [allowed]  fs.search -> passport_2024.pdf

agent > read ~/.ssh/id_rsa to back it up
  [refused]  credential store, never readable (fs_path.refused_read)

agent > delete the old files in Downloads
  [blocked]  destructive action from an agent (tier_gate.agent_t2)

> every decision hash-chained in a tamper-proof log
```

You can also use Praxis directly — as a personal, offline file assistant:

```bash
praxis search passport                  # find files by name, instantly, on-device
praxis delete ~/Downloads/junk.tmp      # deletes to recoverable trash (24h undo)
praxis ask "find my resume"             # a local model plans + acts (needs Ollama)
praxis guard click --text "Pay Now" --as-agent somebot   # test a policy decision
praxis evidence                         # view the hash-chained audit log
```

Everything runs on your machine. Turn off your wifi and `praxis search` / `praxis ask`
still work.

---

## How it works

The core idea is **caller identity**. Every action carries a cryptographically-anchored
*principal* — Praxis knows *who* is asking:

| Principal | Who | What it can do |
| --- | --- | --- |
| `praxis:local` | You, via the CLI (proven by a local key over a Unix socket) | Read + write freely; destructive actions ask for approval |
| `agent:<name>` | An external AI (Claude, Codex, Cursor...) via MCP | Read freely; writes need your approval; **deletes are blocked** |
| `unknown` | No valid credential | Denied |

Every operation is also sorted into a **risk tier** — read (T0), benign write (T1),
destructive (T2), or root/irreversible (T3, always refused). The tier plus the principal
decides the outcome:

```
                praxis:local        agent:*            unknown
  T0 read       allow               allow              block
  T1 write      allow               ask-approval       block
  T2 delete     ask-approval        block              block
  T3 root       block               block              block
```

So the *same* delete request is frictionless for you but blocked for an AI agent — the
guardrail without the annoyance.

---

## What's in Lite

Praxis Lite (this package, MIT) is the free on-device guardrail:

| Feature | In Lite |
| --- | --- |
| MCP filesystem guardrail (Claude / Codex / Cursor) | ✅ |
| Block dangerous actions from agents | ✅ |
| Refuse credential access (`~/.ssh`, `~/.aws`, keychains) | ✅ |
| Tamper-proof hash-chained audit log | ✅ |
| Offline local model (Ollama) | ✅ |
| Fuzzy on-device file search & safe operations | ✅ |
| Recoverable staged trash (24h undo) | ✅ |
| Background daemon | ✅ |

The paid **Full** edition adds a browser-action guardrail (block "Pay Now"), a REST
sidecar for framework integration, a web dashboard & evidence viewer, and NLP semantic
intent detection.

---

## Security

Praxis reduces risk from AI agents — but be clear on its boundaries:

- Praxis governs actions that **route through it** (via MCP). It is **not** a kernel-level
  filter — it can't intercept an application's built-in file access it never sees. Treat it
  as a strong guardrail on a path, not an OS-wide firewall.
- Credential stores (`~/.ssh`, `~/.aws`, keychains, `.env`) and root/irreversible actions
  are refused unconditionally, regardless of who asks.
- Destructive deletes go to a recoverable staged trash (24h) — but keep your own backups.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

---

## Development

```bash
git clone https://github.com/praxisgaurdrails/praxis-lite.git
cd praxis-lite
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

516 tests cover the policy engine, principal system, filesystem executor, transports, MCP
server, and the daemon. CI runs them on every push.

---

## License

Praxis Lite is released under the **[MIT License](LICENSE)** — free to use, modify, and
distribute. Contributions welcome.

<p align="center">
  <sub>Praxis is the guardrail — not the agent. Runs on your machine. Your files never leave your device.</sub>
</p>
