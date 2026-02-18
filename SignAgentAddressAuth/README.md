# SignAgentAddressAuth

AgentPMT external signer CLI for buying credits and using them with wallet signatures.

This tool matches AgentPMT's current external flow:
- Buy credits with `x402` (`/api/external/credits/purchase`)
- Create session nonce (`/api/external/auth/session`)
- Sign balance requests (`/api/external/credits/balance`)
- Sign invoke requests (`/api/external/tools/{productId}/invoke`)
- One-command invoke flow (`session -> sign -> POST invoke`)

## Install

```bash
pip install -r requirements.txt
```

## Environment variables

```bash
export AGENT_ADDRESS=0xYourWallet
export AGENT_KEY=0xYourPrivateKey
```

You can also pass `--address` and `--key` on each command.

## Commands

### 1) Buy credits with x402 (generate `PAYMENT-SIGNATURE`)

```bash
python sign.py purchase-x402 \
  --server https://www.agentpmt.com \
  --address 0xYOUR_WALLET \
  --key 0xYOUR_PRIVATE_KEY \
  --credits 500
```

This command:
1. Calls `POST /api/external/credits/purchase` with `payment_method: "x402"`
2. Reads the `PAYMENT-REQUIRED` header from the `402` response
3. Signs EIP-3009 `TransferWithAuthorization`
4. Prints JSON containing:
- `payment_signature_header` for the request header
- `next_request` with ready-to-send headers and body

To generate and submit in one command:

```bash
python sign.py purchase-x402 \
  --server https://www.agentpmt.com \
  --address 0xYOUR_WALLET \
  --key 0xYOUR_PRIVATE_KEY \
  --credits 500 \
  --submit
```

### 2) Create a session nonce

```bash
python sign.py session \
  --server https://www.agentpmt.com \
  --address 0xYOUR_WALLET
```

### 3) Sign a balance request

```bash
python sign.py sign-balance \
  --address 0xYOUR_WALLET \
  --key 0xYOUR_PRIVATE_KEY \
  --session-nonce <session_nonce>
```

Output includes:
- `message`
- `signature`
- `request_body` (ready for `POST /api/external/credits/balance`)

### 4) Sign an invoke request

```bash
python sign.py sign-invoke \
  --address 0xYOUR_WALLET \
  --key 0xYOUR_PRIVATE_KEY \
  --session-nonce <session_nonce> \
  --product-id <product_id> \
  --parameters-json '{"action":"get_instructions"}'
```

Alternative:

```bash
python sign.py sign-invoke \
  --address 0xYOUR_WALLET \
  --key 0xYOUR_PRIVATE_KEY \
  --session-nonce <session_nonce> \
  --product-id <product_id> \
  --parameters-file ./params.json
```

Output includes:
- `payload_hash`
- `message`
- `signature`
- `request_body` (ready for `POST /api/external/tools/{productId}/invoke`)

### 5) One-command invoke (create session -> sign invoke -> POST invoke)

```bash
python sign.py invoke-e2e \
  --server https://www.agentpmt.com \
  --address 0xYOUR_WALLET \
  --key 0xYOUR_PRIVATE_KEY \
  --product-id <product_id> \
  --parameters-json '{"action":"get_instructions"}'
```

Output includes:
- `session`
- `signed_invoke`
- `invoke_result`

## Exact message formats used by AgentPMT

### Balance signature message

```text
agentpmt-external
wallet:<lowercase_wallet>
session:<session_nonce>
request:<request_id>
action:balance
product:-
payload:
```

### Invoke signature message

```text
agentpmt-external
wallet:<lowercase_wallet>
session:<session_nonce>
request:<request_id>
action:invoke
product:<product_id>
payload:<sha256(canonical_json(parameters))>
```

`canonical_json(parameters)` is exactly:

```python
json.dumps(parameters, sort_keys=True, separators=(",", ":"))
```

## Notes

- Wallet address is normalized to lowercase before signing.
- `request_id` should be unique per request.
- For `purchase-x402`, default authorization validity is 30 minutes (`--validity-seconds`).
- Private keys stay local; only signatures are sent to AgentPMT.
