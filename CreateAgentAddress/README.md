# 🤖 AgentAddress

**A universal identity for AI agents on the internet.**

Think of it like a Drivers License Number for your AI agent — a unique, verifiable identity that works across any website accepting AgentAddress authentication. It's not a wallet for holding money; it's how your agent proves who it is.

---

## What is AgentAddress?

When your AI agent needs to interact with services online, it needs a way to identify itself. AgentAddress provides:

- **Agent Address** — A public identifier you can share freely (like an email address)
- **Agent Secret Key** — Proof of identity that should never be shared (like a password)
- **Recovery Phrase** — 12 words to recover your agent's identity if you lose the key

One address works on **all EVM-compatible blockchains** — no need to create separate identities for different networks.

---

## Works with AgentPMT

Use AgentAddress with [AgentPMT's AgentAddressAuth](https://www.agentpmt.com) tool for:

- Seamless authentication across websites
- Cryptographic signatures that prove your agent's identity
- Secure connections without exposing your secret key

---

## Quick Start

### Web UI (Recommended)

```bash
npm install
npm run start:ui
```

Open the URL shown in the console and click **Generate New Agent Address**.

### Command Line

```bash
npm install
npm start
```

Prints your address, key, and recovery phrase directly to the terminal.

---

## Supported Chains

Your AgentAddress works on **all EVM-compatible chains** with the same address:

| Mainnets | Testnets |
|----------|----------|
| Ethereum, Base, Arbitrum, Optimism | Sepolia, Holesky, Base Sepolia |
| Polygon, BNB Chain, Avalanche | Arbitrum Sepolia, OP Sepolia |
| zkSync, Linea, Scroll, Blast | Polygon Amoy, Berachain Artio |
| Fantom, Gnosis, Cronos, Celo | |
| Moonbeam, Harmony, Zora, Metis | |
| Aurora, Taiko, Sei, Mantle | |
| ...and any other EVM chain | |

---

## Security

| Do | Don't |
|----|-------|
| Save your secret key and recovery phrase securely | Share your secret key with anyone |
| Share your Agent Address publicly | Store credentials in plain text |
| Use the recovery phrase to restore access | Lose both your key and recovery phrase |

**We don't store anything.** Your credentials are generated locally and never leave your device.

---

## How It Works

AgentAddress uses standard cryptographic key derivation (BIP-39/BIP-32) to generate a unique identity from a recovery phrase. The same cryptography that secures billions of dollars in blockchain assets secures your agent's identity.

```
Recovery Phrase → Secret Key → Agent Address
     (12 words)      (private)     (public)
```

---

## License

MIT
