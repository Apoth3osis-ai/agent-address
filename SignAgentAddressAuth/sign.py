#!/usr/bin/env python3
"""
AgentPMT External Signer

Utility CLI for AgentPMT external wallet flows:
- create session nonce
- sign balance requests
- sign invoke requests
- generate or submit x402 purchase payment signatures
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Tuple

import requests
from eth_account import Account
from eth_account.messages import encode_defunct


DEFAULT_SERVER_URL = "https://www.agentpmt.com"
REQUEST_TIMEOUT_SECONDS = 30

TRANSFER_WITH_AUTH_TYPES = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]


def _fatal(message: str, code: int = 1) -> None:
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(code)


def _normalize_server_url(value: str) -> str:
    if not value:
        _fatal("Server URL is required")
    return value.rstrip("/")


def _normalize_address(value: str, field_name: str = "address") -> str:
    if not isinstance(value, str):
        _fatal(f"{field_name} must be a string")
    candidate = value.strip()
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", candidate):
        _fatal(f"Invalid {field_name}: expected 0x + 40 hex chars")
    return candidate.lower()


def _normalize_private_key(value: str) -> str:
    if not isinstance(value, str):
        _fatal("private key must be a string")
    candidate = value.strip()
    if not candidate:
        _fatal("private key is required")
    if not candidate.startswith("0x"):
        candidate = f"0x{candidate}"
    if not re.fullmatch(r"0x[a-fA-F0-9]{64}", candidate):
        _fatal("Invalid private key: expected 0x + 64 hex chars")
    return candidate


def _resolve_wallet_args(args: argparse.Namespace, require_key: bool = True) -> Tuple[str, str | None]:
    address_raw = args.address or os.getenv("AGENT_ADDRESS")
    if not address_raw:
        _fatal("wallet address is required (use --address or AGENT_ADDRESS)")

    address = _normalize_address(address_raw, "wallet address")

    private_key: str | None = None
    if require_key:
        key_raw = args.key or os.getenv("AGENT_KEY")
        if not key_raw:
            _fatal("private key is required (use --key or AGENT_KEY)")
        private_key = _normalize_private_key(key_raw)
        _assert_key_matches_wallet(address, private_key)

    return address, private_key


def _assert_key_matches_wallet(address: str, private_key: str) -> None:
    try:
        derived = Account.from_key(private_key).address.lower()
    except Exception as exc:  # pragma: no cover - defensive
        _fatal(f"Failed to derive address from private key: {exc}")

    if derived != address:
        _fatal(
            "Private key does not match wallet address "
            f"(derived {derived}, provided {address})"
        )


def _request_json(
    method: str,
    url: str,
    body: Dict[str, Any] | None = None,
    extra_headers: Dict[str, str] | None = None,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> requests.Response:
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        return requests.request(method=method, url=url, json=body, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        _fatal(f"HTTP request failed: {exc}")
    raise AssertionError("unreachable")


def _response_payload(response: requests.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return response.text


def _print_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=False))


def _decode_base64_json(value: str) -> Dict[str, Any]:
    padded = value + ("=" * (-len(value) % 4))
    try:
        decoded = base64.b64decode(padded)
        data = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        _fatal(f"Failed to decode base64 JSON: {exc}")

    if not isinstance(data, dict):
        _fatal("Decoded PAYMENT-REQUIRED payload must be a JSON object")
    return data


def _parse_chain_id(network: str) -> int:
    candidate = network.strip().lower()
    if candidate.startswith("eip155:"):
        candidate = candidate.split(":", 1)[1]
    try:
        return int(candidate)
    except ValueError:
        _fatal(f"Unsupported network format in PAYMENT-REQUIRED: {network}")
    raise AssertionError("unreachable")


def _sign_personal_message(private_key: str, message: str) -> str:
    signed = Account.sign_message(encode_defunct(text=message), private_key=private_key)
    signature = signed.signature.hex()
    return signature if signature.startswith("0x") else f"0x{signature}"


def _sign_transfer_with_authorization(
    private_key: str,
    domain_data: Dict[str, Any],
    message_data: Dict[str, Any],
) -> str:
    if not hasattr(Account, "sign_typed_data"):
        _fatal("eth-account version does not support typed-data signing. Upgrade to >=0.11.0")

    signed = Account.sign_typed_data(
        private_key,
        domain_data,
        {"TransferWithAuthorization": TRANSFER_WITH_AUTH_TYPES},
        message_data,
    )
    signature = signed.signature.hex()
    return signature if signature.startswith("0x") else f"0x{signature}"


def _build_external_sign_message(
    wallet: str,
    session_nonce: str,
    request_id: str,
    action: str,
    product_id: str,
    payload_hash: str,
) -> str:
    return "\n".join(
        [
            "agentpmt-external",
            f"wallet:{wallet}",
            f"session:{session_nonce}",
            f"request:{request_id}",
            f"action:{action}",
            f"product:{product_id}",
            f"payload:{payload_hash}",
        ]
    )


def _canonical_json(value: Any) -> str:
    payload = value if value is not None else {}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _load_parameters(args: argparse.Namespace) -> Dict[str, Any]:
    if args.parameters_json and args.parameters_file:
        _fatal("Use either --parameters-json or --parameters-file, not both")

    if args.parameters_json:
        try:
            data = json.loads(args.parameters_json)
        except json.JSONDecodeError as exc:
            _fatal(f"--parameters-json is invalid JSON: {exc}")
    elif args.parameters_file:
        try:
            data = json.loads(Path(args.parameters_file).read_text(encoding="utf-8"))
        except FileNotFoundError:
            _fatal(f"Parameters file not found: {args.parameters_file}")
        except json.JSONDecodeError as exc:
            _fatal(f"Parameters file is invalid JSON: {exc}")
    else:
        data = {}

    if not isinstance(data, dict):
        _fatal("Invoke parameters must be a JSON object")
    return data


def _create_session_nonce(server_url: str, wallet: str) -> Dict[str, Any]:
    response = _request_json(
        "POST",
        f"{server_url}/api/external/auth/session",
        {"wallet_address": wallet},
    )
    payload = _response_payload(response)

    if not response.ok:
        _fatal(f"Session creation failed ({response.status_code}): {payload}")

    if not isinstance(payload, dict):
        _fatal("Unexpected session response format")

    session_nonce = payload.get("session_nonce")
    if not isinstance(session_nonce, str) or not session_nonce.strip():
        _fatal("Session response missing session_nonce")

    return payload


def _build_signed_invoke_payload(
    wallet: str,
    private_key: str,
    session_nonce: str,
    product_id: str,
    parameters: Dict[str, Any],
    request_id: str | None = None,
) -> Dict[str, Any]:
    normalized_session_nonce = (session_nonce or "").strip()
    if not normalized_session_nonce:
        _fatal("--session-nonce is required")

    normalized_product_id = (product_id or "").strip()
    if not normalized_product_id:
        _fatal("--product-id is required")

    request_id_value = request_id or f"invoke-{uuid.uuid4()}"
    payload_hash = hashlib.sha256(_canonical_json(parameters).encode("utf-8")).hexdigest()

    message = _build_external_sign_message(
        wallet=wallet,
        session_nonce=normalized_session_nonce,
        request_id=request_id_value,
        action="invoke",
        product_id=normalized_product_id,
        payload_hash=payload_hash,
    )
    signature = _sign_personal_message(private_key, message)

    return {
        "product_id": normalized_product_id,
        "message": message,
        "payload_hash": payload_hash,
        "signature": signature,
        "request_body": {
            "wallet_address": wallet,
            "session_nonce": normalized_session_nonce,
            "request_id": request_id_value,
            "signature": signature,
            "parameters": parameters,
        },
    }


def _cmd_session(args: argparse.Namespace) -> None:
    server_url = _normalize_server_url(args.server)
    wallet, _ = _resolve_wallet_args(args, require_key=False)
    payload = _create_session_nonce(server_url, wallet)
    _print_json(payload)


def _cmd_sign_balance(args: argparse.Namespace) -> None:
    wallet, private_key = _resolve_wallet_args(args, require_key=True)
    assert private_key is not None

    session_nonce = (args.session_nonce or "").strip()
    if not session_nonce:
        _fatal("--session-nonce is required")

    request_id = args.request_id or f"balance-{uuid.uuid4()}"
    message = _build_external_sign_message(
        wallet=wallet,
        session_nonce=session_nonce,
        request_id=request_id,
        action="balance",
        product_id="-",
        payload_hash="",
    )
    signature = _sign_personal_message(private_key, message)

    output = {
        "message": message,
        "signature": signature,
        "request_body": {
            "wallet_address": wallet,
            "session_nonce": session_nonce,
            "request_id": request_id,
            "signature": signature,
        },
    }
    _print_json(output)


def _cmd_sign_invoke(args: argparse.Namespace) -> None:
    wallet, private_key = _resolve_wallet_args(args, require_key=True)
    assert private_key is not None

    parameters = _load_parameters(args)
    output = _build_signed_invoke_payload(
        wallet=wallet,
        private_key=private_key,
        session_nonce=args.session_nonce,
        product_id=args.product_id,
        parameters=parameters,
        request_id=args.request_id,
    )
    _print_json(output)


def _cmd_invoke_e2e(args: argparse.Namespace) -> None:
    server_url = _normalize_server_url(args.server)
    wallet, private_key = _resolve_wallet_args(args, require_key=True)
    assert private_key is not None

    parameters = _load_parameters(args)
    session_payload = _create_session_nonce(server_url, wallet)
    session_nonce = str(session_payload.get("session_nonce", "")).strip()
    if not session_nonce:
        _fatal("Session response missing session_nonce")

    signed_invoke = _build_signed_invoke_payload(
        wallet=wallet,
        private_key=private_key,
        session_nonce=session_nonce,
        product_id=args.product_id,
        parameters=parameters,
        request_id=args.request_id,
    )

    invoke_response = _request_json(
        "POST",
        f"{server_url}/api/external/tools/{signed_invoke['product_id']}/invoke",
        signed_invoke["request_body"],
        timeout=int(args.invoke_timeout_seconds),
    )

    output = {
        "session": session_payload,
        "signed_invoke": signed_invoke,
        "invoke_result": {
            "status_code": invoke_response.status_code,
            "ok": invoke_response.ok,
            "response": _response_payload(invoke_response),
        },
    }
    _print_json(output)


def _cmd_purchase_x402(args: argparse.Namespace) -> None:
    server_url = _normalize_server_url(args.server)
    wallet, private_key = _resolve_wallet_args(args, require_key=True)
    assert private_key is not None

    credits = int(args.credits)
    if credits <= 0:
        _fatal("--credits must be a positive integer")

    init_body = {
        "wallet_address": wallet,
        "credits": credits,
        "payment_method": "x402",
    }

    init_response = _request_json(
        "POST",
        f"{server_url}/api/external/credits/purchase",
        init_body,
    )

    if init_response.status_code != 402:
        payload = _response_payload(init_response)
        _fatal(
            "Expected 402 Payment Required from /api/external/credits/purchase "
            f"but got {init_response.status_code}: {payload}"
        )

    payment_required_header = (
        init_response.headers.get("PAYMENT-REQUIRED")
        or init_response.headers.get("payment-required")
    )
    if not payment_required_header:
        _fatal("Missing PAYMENT-REQUIRED header in 402 response")

    payment_required = _decode_base64_json(payment_required_header)
    accepts = payment_required.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        _fatal("PAYMENT-REQUIRED.accepts is missing or empty")

    acceptance = accepts[0]
    if not isinstance(acceptance, dict):
        _fatal("PAYMENT-REQUIRED.accepts[0] must be an object")

    network = str(acceptance.get("network") or "").strip()
    amount = acceptance.get("amount")
    asset = str(acceptance.get("asset") or "").strip()
    pay_to = str(acceptance.get("payTo") or "").strip()
    if not network or amount is None or not asset or not pay_to:
        _fatal("PAYMENT-REQUIRED accept object missing network/amount/asset/payTo")

    chain_id = _parse_chain_id(network)
    asset_address = _normalize_address(asset, "asset address")
    pay_to_address = _normalize_address(pay_to, "payTo address")

    extra = acceptance.get("extra") if isinstance(acceptance.get("extra"), dict) else {}
    domain_name = str(extra.get("name") or "USDC")
    domain_version = str(extra.get("version") or "2")

    valid_after = 0
    valid_before = int(time.time()) + int(args.validity_seconds)
    if args.nonce:
        nonce = args.nonce.strip().lower()
    else:
        nonce = f"0x{os.urandom(32).hex()}"
    if not re.fullmatch(r"0x[a-f0-9]{64}", nonce):
        _fatal("Nonce must be 0x-prefixed 32-byte hex")

    value_int = int(str(amount))

    domain_data = {
        "name": domain_name,
        "version": domain_version,
        "chainId": chain_id,
        "verifyingContract": asset_address,
    }
    message_for_signing = {
        "from": wallet,
        "to": pay_to_address,
        "value": value_int,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": nonce,
    }
    typed_signature = _sign_transfer_with_authorization(
        private_key=private_key,
        domain_data=domain_data,
        message_data=message_for_signing,
    )

    authorization_payload = {
        "from": wallet,
        "to": pay_to_address,
        "value": str(value_int),
        "validAfter": str(valid_after),
        "validBefore": str(valid_before),
        "nonce": nonce,
    }

    payment_signature_payload = {
        "x402Version": 2,
        "scheme": "exact",
        "network": network,
        "payload": {
            "signature": typed_signature,
            "authorization": authorization_payload,
        },
    }

    payment_signature_header = base64.b64encode(
        json.dumps(payment_signature_payload, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8")

    request_id = args.request_id or f"purchase-{uuid.uuid4()}"
    purchase_body = {
        "wallet_address": wallet,
        "credits": credits,
        "payment_method": "x402",
        "request_id": request_id,
    }

    output: Dict[str, Any] = {
        "payment_required": payment_required,
        "authorization": {
            **authorization_payload,
            "signature": typed_signature,
        },
        "payment_signature_header": payment_signature_header,
        "next_request": {
            "url": f"{server_url}/api/external/credits/purchase",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "PAYMENT-SIGNATURE": payment_signature_header,
            },
            "body": purchase_body,
        },
    }

    if args.submit:
        submit_response = _request_json(
            "POST",
            f"{server_url}/api/external/credits/purchase",
            purchase_body,
            extra_headers={"PAYMENT-SIGNATURE": payment_signature_header},
            timeout=int(args.submit_timeout_seconds),
        )
        output["submit_result"] = {
            "status_code": submit_response.status_code,
            "ok": submit_response.ok,
            "response": _response_payload(submit_response),
        }

    _print_json(output)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AgentPMT external signing helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variables supported:\n"
            "  AGENT_ADDRESS=0x...\n"
            "  AGENT_KEY=0x...\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    session = subparsers.add_parser("session", help="Create external session nonce")
    session.add_argument("--server", default=DEFAULT_SERVER_URL, help="AgentPMT base URL")
    session.add_argument("--address", help="Wallet address (or AGENT_ADDRESS)")
    session.set_defaults(func=_cmd_session)

    sign_balance = subparsers.add_parser("sign-balance", help="Sign payload for /api/external/credits/balance")
    sign_balance.add_argument("--address", help="Wallet address (or AGENT_ADDRESS)")
    sign_balance.add_argument("--key", help="Private key (or AGENT_KEY)")
    sign_balance.add_argument("--session-nonce", required=True, help="Session nonce from /api/external/auth/session")
    sign_balance.add_argument("--request-id", help="Optional request_id (defaults to balance-<uuid>)")
    sign_balance.set_defaults(func=_cmd_sign_balance)

    sign_invoke = subparsers.add_parser("sign-invoke", help="Sign payload for /api/external/tools/{productId}/invoke")
    sign_invoke.add_argument("--address", help="Wallet address (or AGENT_ADDRESS)")
    sign_invoke.add_argument("--key", help="Private key (or AGENT_KEY)")
    sign_invoke.add_argument("--session-nonce", required=True, help="Session nonce from /api/external/auth/session")
    sign_invoke.add_argument("--product-id", required=True, help="Product ID to invoke")
    sign_invoke.add_argument("--request-id", help="Optional request_id (defaults to invoke-<uuid>)")
    sign_invoke.add_argument("--parameters-json", help="Inline JSON object for parameters")
    sign_invoke.add_argument("--parameters-file", help="Path to JSON file for parameters")
    sign_invoke.set_defaults(func=_cmd_sign_invoke)

    invoke_e2e = subparsers.add_parser(
        "invoke-e2e",
        help="One-command flow: create session -> sign invoke -> POST invoke",
    )
    invoke_e2e.add_argument("--server", default=DEFAULT_SERVER_URL, help="AgentPMT base URL")
    invoke_e2e.add_argument("--address", help="Wallet address (or AGENT_ADDRESS)")
    invoke_e2e.add_argument("--key", help="Private key (or AGENT_KEY)")
    invoke_e2e.add_argument("--product-id", required=True, help="Product ID to invoke")
    invoke_e2e.add_argument("--request-id", help="Optional request_id (defaults to invoke-<uuid>)")
    invoke_e2e.add_argument("--parameters-json", help="Inline JSON object for parameters")
    invoke_e2e.add_argument("--parameters-file", help="Path to JSON file for parameters")
    invoke_e2e.add_argument(
        "--invoke-timeout-seconds",
        type=int,
        default=120,
        help="Timeout for invoke request (default: 120)",
    )
    invoke_e2e.set_defaults(func=_cmd_invoke_e2e)

    purchase = subparsers.add_parser("purchase-x402", help="Generate x402 payment signature header for credit purchase")
    purchase.add_argument("--server", default=DEFAULT_SERVER_URL, help="AgentPMT base URL")
    purchase.add_argument("--address", help="Wallet address (or AGENT_ADDRESS)")
    purchase.add_argument("--key", help="Private key (or AGENT_KEY)")
    purchase.add_argument("--credits", type=int, required=True, help="Credits to purchase (500-credit increments)")
    purchase.add_argument("--request-id", help="Optional request_id (defaults to purchase-<uuid>)")
    purchase.add_argument("--validity-seconds", type=int, default=1800, help="Authorization validity window (default: 1800)")
    purchase.add_argument("--nonce", help="Optional 0x-prefixed 32-byte hex nonce")
    purchase.add_argument("--submit", action="store_true", help="Submit the signed purchase request after generating the header")
    purchase.add_argument("--submit-timeout-seconds", type=int, default=120, help="Timeout for --submit request (default: 120)")
    purchase.set_defaults(func=_cmd_purchase_x402)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
