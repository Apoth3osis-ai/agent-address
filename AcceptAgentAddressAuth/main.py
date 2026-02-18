import base64
import hashlib
import json
import re
import time
import uuid
from typing import Any, Literal

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="AcceptAgentAddressAuth",
    description="Reference verifier for AgentPMT external wallet signature flows",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores. Replace with Redis/database in production.
session_nonces: dict[str, dict[str, Any]] = {}
used_session_requests: set[tuple[str, str]] = set()

SESSION_EXPIRY_SECONDS = 900
CREDITS_TO_USDC_UNITS = 10000

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SIGNATURE_RE = re.compile(r"^0x[a-fA-F0-9]{130}$")
NONCE_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")

TRANSFER_WITH_AUTH_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def _now_ts() -> int:
    return int(time.time())


def _normalize_wallet(value: str, field_name: str = "wallet_address") -> str:
    candidate = (value or "").strip()
    if not ADDRESS_RE.fullmatch(candidate):
        raise ValueError(f"{field_name} must be 0x + 40 hex chars")
    return candidate.lower()


def _normalize_signature(value: str, field_name: str = "signature") -> str:
    candidate = (value or "").strip()
    if not SIGNATURE_RE.fullmatch(candidate):
        raise ValueError(f"{field_name} must be 0x + 65-byte hex")
    return candidate


def _canonical_json(value: Any) -> str:
    payload = value if value is not None else {}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _build_external_message(
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


def _build_sponsor_message(
    payer_wallet_address: str,
    recipient_wallet_address: str,
    credits: int,
    reference_kind: Literal["nonce", "tx"],
    reference_value: str,
) -> str:
    reference_line = (
        f"nonce:{reference_value}" if reference_kind == "nonce" else f"tx:{reference_value}"
    )
    return "\n".join(
        [
            "agentpmt-external-sponsor",
            f"payer:{payer_wallet_address}",
            f"recipient:{recipient_wallet_address}",
            f"credits:{credits}",
            reference_line,
        ]
    )


def _recover_personal_signer(message: str, signature: str) -> str:
    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail=f"Invalid personal signature: {exc}")
    return recovered.lower()


def _recover_transfer_with_authorization_signer(
    chain_id: int,
    verifying_contract: str,
    domain_name: str,
    domain_version: str,
    authorization: dict[str, Any],
    signature: str,
) -> str:
    domain_data = {
        "name": domain_name,
        "version": domain_version,
        "chainId": chain_id,
        "verifyingContract": verifying_contract,
    }
    message_data = {
        "from": authorization["from"],
        "to": authorization["to"],
        "value": int(authorization["value"]),
        "validAfter": int(authorization["valid_after"]),
        "validBefore": int(authorization["valid_before"]),
        "nonce": authorization["nonce"],
    }

    try:
        signable = encode_typed_data(
            domain_data=domain_data,
            message_types=TRANSFER_WITH_AUTH_TYPES,
            message_data=message_data,
        )
        recovered = Account.recover_message(signable, signature=signature)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail=f"Invalid TransferWithAuthorization signature: {exc}")

    return recovered.lower()


def _decode_payment_signature_header(header_value: str) -> dict[str, Any]:
    try:
        padded = header_value + ("=" * (-len(header_value) % 4))
        decoded = base64.b64decode(padded)
        parsed = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid payment_signature_header: {exc}")

    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="payment_signature_header must decode to a JSON object")

    root = parsed.get("paymentPayload")
    if isinstance(root, dict):
        return root
    return parsed


def _parse_chain_id(network: str) -> int:
    candidate = (network or "").strip().lower()
    if not candidate:
        raise HTTPException(status_code=400, detail="Missing network in payment signature payload")
    if candidate.startswith("eip155:"):
        candidate = candidate.split(":", 1)[1]
    try:
        return int(candidate)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid network value: {network}")


def _create_session(wallet: str) -> dict[str, Any]:
    now = _now_ts()
    session_nonce = str(uuid.uuid4())
    expires_at = now + SESSION_EXPIRY_SECONDS
    session_nonces[session_nonce] = {
        "wallet": wallet,
        "created_at": now,
        "expires_at": expires_at,
    }
    return {
        "session_nonce": session_nonce,
        "expires_in": SESSION_EXPIRY_SECONDS,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)),
    }


def _validate_session(wallet: str, session_nonce: str) -> None:
    record = session_nonces.get(session_nonce)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid session nonce")

    if record.get("wallet") != wallet:
        raise HTTPException(status_code=401, detail="Session nonce does not belong to this wallet")

    if _now_ts() > int(record.get("expires_at", 0)):
        session_nonces.pop(session_nonce, None)
        raise HTTPException(status_code=401, detail="Session nonce expired")


def _consume_request_id(session_nonce: str, request_id: str) -> None:
    key = (session_nonce, request_id)
    if key in used_session_requests:
        raise HTTPException(status_code=409, detail="Duplicate request_id for this session_nonce")
    used_session_requests.add(key)


class SessionCreateRequest(BaseModel):
    wallet_address: str

    @field_validator("wallet_address")
    @classmethod
    def validate_wallet_address(cls, value: str) -> str:
        return _normalize_wallet(value, "wallet_address")


class SessionCreateResponse(BaseModel):
    session_nonce: str
    expires_in: int
    expires_at: str


class SignedBalanceVerifyRequest(BaseModel):
    wallet_address: str
    session_nonce: str
    request_id: str
    signature: str

    @field_validator("wallet_address")
    @classmethod
    def validate_wallet_address(cls, value: str) -> str:
        return _normalize_wallet(value, "wallet_address")

    @field_validator("session_nonce", "request_id")
    @classmethod
    def validate_non_empty(cls, value: str, info) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError(f"{info.field_name} is required")
        return candidate

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        return _normalize_signature(value, "signature")


class SignedInvokeVerifyRequest(BaseModel):
    wallet_address: str
    session_nonce: str
    request_id: str
    product_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    signature: str

    @field_validator("wallet_address")
    @classmethod
    def validate_wallet_address(cls, value: str) -> str:
        return _normalize_wallet(value, "wallet_address")

    @field_validator("session_nonce", "request_id", "product_id")
    @classmethod
    def validate_non_empty(cls, value: str, info) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError(f"{info.field_name} is required")
        return candidate

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        return _normalize_signature(value, "signature")


class SignedVerifyResponse(BaseModel):
    verified: bool
    wallet_address: str
    recovered_address: str
    action: str
    product_id: str
    request_id: str
    payload_hash: str
    message: str


class SponsorVerifyRequest(BaseModel):
    payer_wallet_address: str
    recipient_wallet_address: str
    credits: int
    reference_kind: Literal["nonce", "tx"]
    reference_value: str
    signature: str

    @field_validator("payer_wallet_address")
    @classmethod
    def validate_payer_wallet(cls, value: str) -> str:
        return _normalize_wallet(value, "payer_wallet_address")

    @field_validator("recipient_wallet_address")
    @classmethod
    def validate_recipient_wallet(cls, value: str) -> str:
        return _normalize_wallet(value, "recipient_wallet_address")

    @field_validator("credits")
    @classmethod
    def validate_credits(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("credits must be a positive integer")
        return value

    @field_validator("reference_value")
    @classmethod
    def validate_reference_value(cls, value: str, info) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("reference_value is required")
        if info.data.get("reference_kind") == "tx" and not TX_HASH_RE.fullmatch(candidate):
            raise ValueError("reference_value must be a tx hash when reference_kind is tx")
        return candidate

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        return _normalize_signature(value, "signature")


class SponsorVerifyResponse(BaseModel):
    verified: bool
    payer_wallet_address: str
    recovered_address: str
    message: str


class X402PaymentVerifyRequest(BaseModel):
    wallet_address: str
    payment_signature_header: str
    expected_asset_address: str
    expected_pay_to: str | None = None
    expected_credits: int | None = None
    domain_name: str = "USDC"
    domain_version: str = "2"
    enforce_not_expired: bool = True

    @field_validator("wallet_address")
    @classmethod
    def validate_wallet_address(cls, value: str) -> str:
        return _normalize_wallet(value, "wallet_address")

    @field_validator("expected_asset_address")
    @classmethod
    def validate_expected_asset_address(cls, value: str) -> str:
        return _normalize_wallet(value, "expected_asset_address")

    @field_validator("expected_pay_to")
    @classmethod
    def validate_expected_pay_to(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalize_wallet(value, "expected_pay_to")

    @field_validator("expected_credits")
    @classmethod
    def validate_expected_credits(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if value <= 0:
            raise ValueError("expected_credits must be positive")
        return value

    @field_validator("payment_signature_header")
    @classmethod
    def validate_payment_signature_header(cls, value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("payment_signature_header is required")
        return candidate


class X402PaymentVerifyResponse(BaseModel):
    verified: bool
    wallet_address: str
    recovered_address: str
    network: str
    chain_id: int
    authorization: dict[str, str]
    amount_units: str
    amount_usdc: str
    checks: dict[str, bool]


@app.post("/session", response_model=SessionCreateResponse)
def create_session(request: SessionCreateRequest):
    return SessionCreateResponse(**_create_session(request.wallet_address))


@app.post("/verify/balance", response_model=SignedVerifyResponse)
def verify_balance_signature(request: SignedBalanceVerifyRequest):
    _validate_session(request.wallet_address, request.session_nonce)

    message = _build_external_message(
        wallet=request.wallet_address,
        session_nonce=request.session_nonce,
        request_id=request.request_id,
        action="balance",
        product_id="-",
        payload_hash="",
    )
    recovered_address = _recover_personal_signer(message, request.signature)
    if recovered_address != request.wallet_address:
        raise HTTPException(status_code=401, detail="Signature does not match wallet_address")

    _consume_request_id(request.session_nonce, request.request_id)

    return SignedVerifyResponse(
        verified=True,
        wallet_address=request.wallet_address,
        recovered_address=recovered_address,
        action="balance",
        product_id="-",
        request_id=request.request_id,
        payload_hash="",
        message=message,
    )


@app.post("/verify/invoke", response_model=SignedVerifyResponse)
def verify_invoke_signature(request: SignedInvokeVerifyRequest):
    _validate_session(request.wallet_address, request.session_nonce)

    payload_hash = hashlib.sha256(_canonical_json(request.parameters).encode("utf-8")).hexdigest()
    message = _build_external_message(
        wallet=request.wallet_address,
        session_nonce=request.session_nonce,
        request_id=request.request_id,
        action="invoke",
        product_id=request.product_id,
        payload_hash=payload_hash,
    )
    recovered_address = _recover_personal_signer(message, request.signature)
    if recovered_address != request.wallet_address:
        raise HTTPException(status_code=401, detail="Signature does not match wallet_address")

    _consume_request_id(request.session_nonce, request.request_id)

    return SignedVerifyResponse(
        verified=True,
        wallet_address=request.wallet_address,
        recovered_address=recovered_address,
        action="invoke",
        product_id=request.product_id,
        request_id=request.request_id,
        payload_hash=payload_hash,
        message=message,
    )


@app.post("/verify/sponsor", response_model=SponsorVerifyResponse)
def verify_sponsor_signature(request: SponsorVerifyRequest):
    message = _build_sponsor_message(
        payer_wallet_address=request.payer_wallet_address,
        recipient_wallet_address=request.recipient_wallet_address,
        credits=request.credits,
        reference_kind=request.reference_kind,
        reference_value=request.reference_value,
    )
    recovered_address = _recover_personal_signer(message, request.signature)

    if recovered_address != request.payer_wallet_address:
        raise HTTPException(status_code=401, detail="Sponsor signature does not match payer_wallet_address")

    return SponsorVerifyResponse(
        verified=True,
        payer_wallet_address=request.payer_wallet_address,
        recovered_address=recovered_address,
        message=message,
    )


@app.post("/verify/x402-payment", response_model=X402PaymentVerifyResponse)
def verify_x402_payment_signature(request: X402PaymentVerifyRequest):
    root = _decode_payment_signature_header(request.payment_signature_header)

    x402_version = root.get("x402Version")
    if x402_version is not None and x402_version not in (1, 2):
        raise HTTPException(status_code=400, detail=f"Unsupported x402Version: {x402_version}")

    scheme = root.get("scheme")
    if isinstance(scheme, str) and scheme and scheme != "exact":
        raise HTTPException(status_code=400, detail=f"Unsupported scheme: {scheme}")

    payload = root.get("payload")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Missing payload object in payment signature header")

    authorization_raw = payload.get("authorization")
    if not isinstance(authorization_raw, dict):
        raise HTTPException(status_code=400, detail="Missing authorization object in payment signature header")

    signature = _normalize_signature(str(payload.get("signature") or ""), "payload.signature")

    from_wallet = _normalize_wallet(str(authorization_raw.get("from") or ""), "authorization.from")
    to_wallet = _normalize_wallet(str(authorization_raw.get("to") or ""), "authorization.to")
    nonce = str(authorization_raw.get("nonce") or "").strip()
    if not NONCE_RE.fullmatch(nonce):
        raise HTTPException(status_code=400, detail="authorization.nonce must be 0x-prefixed 32-byte hex")

    value_raw = authorization_raw.get("value")
    valid_after_raw = authorization_raw.get("validAfter")
    if valid_after_raw is None:
        valid_after_raw = authorization_raw.get("valid_after")
    valid_before_raw = authorization_raw.get("validBefore")
    if valid_before_raw is None:
        valid_before_raw = authorization_raw.get("valid_before")

    if value_raw is None or valid_after_raw is None or valid_before_raw is None:
        raise HTTPException(
            status_code=400,
            detail="authorization must include value, validAfter/valid_after, validBefore/valid_before",
        )

    try:
        value_int = int(str(value_raw))
        valid_after_int = int(str(valid_after_raw))
        valid_before_int = int(str(valid_before_raw))
    except ValueError:
        raise HTTPException(status_code=400, detail="authorization numeric fields must be valid integers")

    if value_int <= 0:
        raise HTTPException(status_code=400, detail="authorization.value must be positive")

    if request.enforce_not_expired and valid_before_int <= _now_ts():
        raise HTTPException(status_code=400, detail="authorization.valid_before is expired")

    if from_wallet != request.wallet_address:
        raise HTTPException(status_code=400, detail="authorization.from must match wallet_address")

    if request.expected_pay_to and to_wallet != request.expected_pay_to:
        raise HTTPException(status_code=400, detail="authorization.to does not match expected_pay_to")

    if request.expected_credits is not None:
        expected_units = request.expected_credits * CREDITS_TO_USDC_UNITS
        if value_int != expected_units:
            raise HTTPException(
                status_code=400,
                detail=f"authorization.value must equal expected_credits * 10000 ({expected_units})",
            )

    network = str(root.get("network") or "").strip()
    accepted = root.get("accepted")
    if not network and isinstance(accepted, dict):
        network = str(accepted.get("network") or "").strip()
    chain_id = _parse_chain_id(network)

    authorization = {
        "from": from_wallet,
        "to": to_wallet,
        "value": str(value_int),
        "valid_after": str(valid_after_int),
        "valid_before": str(valid_before_int),
        "nonce": nonce,
    }

    recovered_address = _recover_transfer_with_authorization_signer(
        chain_id=chain_id,
        verifying_contract=request.expected_asset_address,
        domain_name=request.domain_name,
        domain_version=request.domain_version,
        authorization=authorization,
        signature=signature,
    )
    if recovered_address != from_wallet:
        raise HTTPException(status_code=401, detail="Typed-data signature does not match authorization.from")

    checks = {
        "from_matches_wallet": from_wallet == request.wallet_address,
        "typed_signature_matches_from": recovered_address == from_wallet,
        "pay_to_matches_expected": True if request.expected_pay_to is None else (to_wallet == request.expected_pay_to),
        "credits_match_expected": True
        if request.expected_credits is None
        else (value_int == request.expected_credits * CREDITS_TO_USDC_UNITS),
        "not_expired": valid_before_int > _now_ts(),
    }

    amount_usdc = f"{value_int / 1_000_000:.6f}"

    return X402PaymentVerifyResponse(
        verified=True,
        wallet_address=request.wallet_address,
        recovered_address=recovered_address,
        network=network,
        chain_id=chain_id,
        authorization=authorization,
        amount_units=str(value_int),
        amount_usdc=amount_usdc,
        checks=checks,
    )


@app.get("/health")
def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
