# AcceptAgentAddressAuth

Reference FastAPI verifier for AgentPMT external wallet signature flows.

This server implements the verification side for:
- session nonce creation
- signed balance checks
- signed tool invocations
- sponsored credit purchases
- x402 payment header verification

## Quick start

```bash
pip install -r requirements.txt
python main.py
```

Server: `http://localhost:8000`

OpenAPI docs: `http://localhost:8000/docs`

## Endpoints

### `POST /session`
Creates a session nonce for one wallet.

Request:
```json
{
  "wallet_address": "0xabc..."
}
```

Response:
```json
{
  "session_nonce": "2d6c7d3f-...",
  "expires_in": 900,
  "expires_at": "2026-02-16T00:00:00Z"
}
```

### `POST /verify/balance`
Verifies the AgentPMT balance-signature message format.

Request:
```json
{
  "wallet_address": "0xabc...",
  "session_nonce": "2d6c7d3f-...",
  "request_id": "balance-123",
  "signature": "0x..."
}
```

### `POST /verify/invoke`
Verifies the AgentPMT invoke-signature message format.

Request:
```json
{
  "wallet_address": "0xabc...",
  "session_nonce": "2d6c7d3f-...",
  "request_id": "invoke-123",
  "product_id": "tool_abc",
  "parameters": {"action": "get_instructions"},
  "signature": "0x..."
}
```

### `POST /verify/sponsor`
Verifies sponsor signature when payer wallet is different from recipient wallet.

Request:
```json
{
  "payer_wallet_address": "0xpayer...",
  "recipient_wallet_address": "0xrecipient...",
  "credits": 500,
  "reference_kind": "tx",
  "reference_value": "0x<tx_hash>",
  "signature": "0x..."
}
```

### `POST /verify/x402-payment`
Verifies `PAYMENT-SIGNATURE` header payload (EIP-712 `TransferWithAuthorization`).

Request:
```json
{
  "wallet_address": "0xabc...",
  "payment_signature_header": "<base64 header value>",
  "expected_asset_address": "0xUSDC...",
  "expected_pay_to": "0xCREDIT_WALLET...",
  "expected_credits": 500,
  "domain_name": "USDC",
  "domain_version": "2",
  "enforce_not_expired": true
}
```

Important check:
- If `expected_credits` is set, verifier enforces:
- `authorization.value == expected_credits * 10000`

This is the credits-to-USDC base-unit conversion used by AgentPMT (`100 credits = 1 USD`, `USDC has 6 decimals`).

### `GET /health`
Basic health check.

## Security model

- Session nonce ownership check (`session_nonce` must belong to wallet)
- Session expiry enforcement (default 15 minutes)
- Replay protection for signed balance/invoke (`session_nonce + request_id` uniqueness)
- Strict address/signature/nonce format validation
- Typed-data signature recovery for x402 payment payloads

## Production notes

- Replace in-memory stores with Redis or database
- Add rate limiting
- Run behind HTTPS
- Add observability and request logging
