import secrets
import time
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from eth_account.messages import encode_defunct
from eth_account import Account

app = FastAPI(
    title="AcceptAgentAddress",
    description="Verify AgentAddress signatures for authentication",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (use Redis or a database in production)
pending_challenges: dict[str, dict] = {}  # nonce -> {address, payload, created_at}
used_nonces: set[str] = set()

# Challenge expiry time in seconds
CHALLENGE_EXPIRY = 300  # 5 minutes


class ChallengeRequest(BaseModel):
    address: str

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("Invalid Ethereum address format")
        return v.lower()


class ChallengeResponse(BaseModel):
    nonce: str
    payload: str
    expires_in: int


class VerifyRequest(BaseModel):
    address: str
    nonce: str
    signature: str

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("Invalid Ethereum address format")
        return v.lower()

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        if not v.startswith("0x"):
            raise ValueError("Signature must start with 0x")
        return v


class VerifyResponse(BaseModel):
    verified: bool
    address: str
    message: str


@app.post("/challenge", response_model=ChallengeResponse)
async def request_challenge(request: ChallengeRequest):
    """
    Request a challenge payload to sign with your AgentAddress.

    The payload contains a nonce that must be signed and returned
    to the /verify endpoint within 5 minutes.
    """
    # Generate a secure random nonce
    nonce = secrets.token_hex(16)

    # Create the payload to be signed
    payload = f"AgentAddress Authentication\n\nAddress: {request.address}\nNonce: {nonce}\nTimestamp: {int(time.time())}"

    # Store the challenge
    pending_challenges[nonce] = {
        "address": request.address,
        "payload": payload,
        "created_at": time.time(),
    }

    return ChallengeResponse(
        nonce=nonce,
        payload=payload,
        expires_in=CHALLENGE_EXPIRY,
    )


@app.post("/verify", response_model=VerifyResponse)
async def verify_signature(request: VerifyRequest):
    """
    Verify a signed challenge payload.

    Confirms that the signature was created by the private key
    corresponding to the provided address. Each nonce can only
    be used once to prevent replay attacks.
    """
    # Check if nonce was already used
    if request.nonce in used_nonces:
        raise HTTPException(
            status_code=400,
            detail="Nonce already used. Request a new challenge.",
        )

    # Check if challenge exists
    if request.nonce not in pending_challenges:
        raise HTTPException(
            status_code=404,
            detail="Challenge not found. It may have expired or never existed.",
        )

    challenge = pending_challenges[request.nonce]

    # Check if challenge expired
    if time.time() - challenge["created_at"] > CHALLENGE_EXPIRY:
        del pending_challenges[request.nonce]
        raise HTTPException(
            status_code=400,
            detail="Challenge expired. Request a new one.",
        )

    # Check if address matches
    if challenge["address"] != request.address:
        raise HTTPException(
            status_code=400,
            detail="Address does not match the challenge.",
        )

    # Verify the signature
    try:
        message = encode_defunct(text=challenge["payload"])
        recovered_address = Account.recover_message(message, signature=request.signature)

        # Compare addresses (case-insensitive)
        verified = recovered_address.lower() == request.address.lower()
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid signature format: {str(e)}",
        )

    # Mark nonce as used (whether verification succeeded or not)
    used_nonces.add(request.nonce)
    del pending_challenges[request.nonce]

    if verified:
        return VerifyResponse(
            verified=True,
            address=recovered_address,
            message="Signature verified. AgentAddress authenticated successfully.",
        )
    else:
        return VerifyResponse(
            verified=False,
            address=recovered_address,
            message=f"Signature invalid. Recovered address {recovered_address} does not match claimed address {request.address}.",
        )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
