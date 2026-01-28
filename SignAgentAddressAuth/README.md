# 🔑 SignAgentAddressAuth

**Authenticate with your AgentAddress in one command.**

A simple CLI tool that handles the full authentication flow: fetches a challenge, signs it with your secret key, and verifies your identity.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Authenticate (make sure AcceptAgentAddress server is running)
python sign.py --server http://localhost:8000 --address 0xYourAddress --key 0xYourSecretKey
```

---

## Usage

### Command Line Arguments

```bash
python sign.py --server http://localhost:8000 --address 0x... --key 0x...
```

| Flag | Description |
|------|-------------|
| `--server`, `-s` | Server URL (default: `http://localhost:8000`) |
| `--address`, `-a` | Your AgentAddress |
| `--key`, `-k` | Your secret key |
| `--verbose`, `-v` | Show detailed output |
| `--quiet`, `-q` | Minimal output for scripting |
| `--interactive`, `-i` | Prompt for credentials |

### Environment Variables

```bash
export AGENT_ADDRESS=0xYourAddress
export AGENT_KEY=0xYourSecretKey

python sign.py --server http://localhost:8000
```

### Interactive Mode

```bash
python sign.py --server http://localhost:8000 --interactive
# Prompts for address and key (key input is hidden)
```

---

## Examples

**Basic authentication:**
```bash
python sign.py -s http://localhost:8000 -a 0x742d35Cc6634C0532925a3b844Bc9e7595f... -k 0x...
```

**Verbose output (see the full flow):**
```bash
python sign.py -v -s http://localhost:8000 -a 0x... -k 0x...
```

Output:
```
🤖 AgentAddress Authentication

Requesting challenge from http://localhost:8000/challenge...
Received challenge (expires in 300s)
Nonce: a1b2c3d4e5f6...

Payload to sign:
AgentAddress Authentication

Address: 0x742d35cc6634c0532925a3b844bc9e7595f...
Nonce: a1b2c3d4e5f67890...
Timestamp: 1706300000

Signing payload with secret key...
Signature: 0x1a2b3c4d5e6f7890...90abcdef

Submitting signature to http://localhost:8000/verify...
✓ Authentication successful!
  Address: 0x742d35Cc6634C0532925a3b844Bc9e7595f...
```

**Scripting mode:**
```bash
if python sign.py -q -s http://localhost:8000 -a 0x... -k 0x...; then
  echo "Agent authenticated!"
else
  echo "Authentication failed"
fi
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Authentication successful |
| `1` | Authentication failed or invalid input |
| `2` | Connection error |
| `130` | Cancelled (Ctrl+C) |

---

## Use as a Library

```python
from sign import authenticate

result = authenticate(
    server_url="http://localhost:8000",
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f...",
    private_key="0x...",
    verbose=True,
)

if result["verified"]:
    print(f"Authenticated as {result['address']}")
```

---

## Full Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                     SignAgentAddressAuth                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Load credentials (args, env vars, or interactive prompt)     │
│                              │                                   │
│                              ▼                                   │
│  2. POST /challenge ─────────────────────► AcceptAgentAddress    │
│                              │                                   │
│                              ▼                                   │
│  3. Receive payload + nonce                                      │
│                              │                                   │
│                              ▼                                   │
│  4. Sign payload with secret key (locally)                       │
│                              │                                   │
│                              ▼                                   │
│  5. POST /verify ────────────────────────► AcceptAgentAddress    │
│                              │                                   │
│                              ▼                                   │
│  6. Output result: ✓ verified  or  ✗ failed                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Security

- Your secret key is **never sent to the server**
- Only the signature (proof you have the key) is transmitted
- Each authentication uses a unique nonce (no replay attacks)
- Use `--interactive` to avoid putting your key in shell history

---

## License

MIT
