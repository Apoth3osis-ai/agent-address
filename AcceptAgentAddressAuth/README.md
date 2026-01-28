# 🔐 AcceptAgentAddress

**Verify AgentAddress signatures for authentication.**

A FastAPI server that lets you authenticate AI agents (or users) by verifying they control an AgentAddress. Uses cryptographic signatures with replay protection.

---

## How It Works

```
┌─────────────┐     1. Request challenge 
                            (sends address)   ┌─────────────────────┐
│             │ ─────────────────────────────► │                     │
│   Agent     │                                 │  AcceptAgentAddress │
│             │ ◄───────────────────────────── │       Server        │
│             │     2. Receive payload + nonce │                     │
│             │                                │                     │
│             │     3. Sign payload            │                     │
│             │        (with secret key)       │                     │
│             │                                │                     │
│             │     4. Submit signature        │                     │
│             │ ─────────────────────────────► │                     │
│             │                                │                     │
│             │ ◄───────────────────────────── │                     │
└─────────────┘     5. Verified or rejected    └─────────────────────┘
```

1. Agent requests a challenge by submitting their AgentAddress
2. Server returns a payload containing a unique nonce
3. Agent signs the payload with their secret key
4. Agent submits the signature back to the server
5. Server verifies the signature matches the address

**Replay Protection:** Each nonce can only be used once. Challenges expire after 5 minutes.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

Server runs at `http://localhost:8000`

API docs available at `http://localhost:8000/docs`

---

## API Endpoints

### `POST /challenge`

Request a challenge payload to sign.

**Request:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f..."
}
```

**Response:**
```json
{
  "nonce": "a1b2c3d4e5f6...",
  "payload": "AgentAddress Authentication\n\nAddress: 0x742d...\nNonce: a1b2c3d4e5f6...\nTimestamp: 1706300000",
  "expires_in": 300
}
```

### `POST /verify`

Verify a signed challenge.

**Request:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f...",
  "nonce": "a1b2c3d4e5f6...",
  "signature": "0x..."
}
```

**Response (success):**
```json
{
  "verified": true,
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f...",
  "message": "Signature verified. AgentAddress authenticated successfully."
}
```

**Response (failure):**
```json
{
  "verified": false,
  "address": "0xRecoveredAddress...",
  "message": "Signature invalid. Recovered address does not match claimed address."
}
```

### `GET /health`

Health check endpoint.

---

## Example: Signing with Python

```python
from eth_account import Account
from eth_account.messages import encode_defunct
import requests

# Your AgentAddress credentials
address = "0x742d35Cc6634C0532925a3b844Bc9e7595f..."
private_key = "0x..."

# 1. Request a challenge
resp = requests.post("http://localhost:8000/challenge", json={"address": address})
challenge = resp.json()

# 2. Sign the payload
message = encode_defunct(text=challenge["payload"])
signed = Account.sign_message(message, private_key)

# 3. Verify the signature
resp = requests.post("http://localhost:8000/verify", json={
    "address": address,
    "nonce": challenge["nonce"],
    "signature": signed.signature.hex(),
})
result = resp.json()
print(f"Verified: {result['verified']}")
```

---

## Security Notes

| Feature | Description |
|---------|-------------|
| Nonce | Each challenge has a unique nonce that can only be used once |
| Expiry | Challenges expire after 5 minutes |
| Replay Protection | Used nonces are tracked and rejected |
| No Storage | Private keys never touch the server |

**Production Considerations:**
- Use Redis or a database for nonce storage (in-memory won't survive restarts)
- Add rate limiting to prevent abuse
- Use HTTPS in production
- Consider adding additional claims to the payload (e.g., intended action, resource)

---

## Integration with AgentPMT

This server implements the verification side of AgentAddress authentication. Use it alongside [AgentPMT's AgentAddressAuth](https://agentpmt.ai) tool to authenticate agents across your services.

---

## License

MIT
