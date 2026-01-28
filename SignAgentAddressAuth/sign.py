#!/usr/bin/env python3
"""
SignAgentAddressAuth - Authenticate with your AgentAddress

Fetches a challenge, signs it with your secret key, and verifies your identity.
"""

import argparse
import sys
import requests
from eth_account import Account
from eth_account.messages import encode_defunct


def authenticate(server_url: str, address: str, private_key: str, verbose: bool = False) -> dict:
    """
    Authenticate with an AcceptAgentAddress server.

    Args:
        server_url: Base URL of the AcceptAgentAddress server
        address: Your AgentAddress (0x...)
        private_key: Your secret key (0x...)
        verbose: Print detailed output

    Returns:
        Verification response from the server
    """
    server_url = server_url.rstrip("/")

    # Step 1: Request a challenge
    if verbose:
        print(f"Requesting challenge from {server_url}/challenge...")

    try:
        resp = requests.post(
            f"{server_url}/challenge",
            json={"address": address},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ConnectionError(f"Could not connect to server at {server_url}")
    except requests.exceptions.HTTPError as e:
        error_detail = resp.json().get("detail", str(e))
        raise ValueError(f"Challenge request failed: {error_detail}")

    challenge = resp.json()
    nonce = challenge["nonce"]
    payload = challenge["payload"]

    if verbose:
        print(f"Received challenge (expires in {challenge['expires_in']}s)")
        print(f"Nonce: {nonce[:16]}...")
        print(f"\nPayload to sign:\n{payload}\n")

    # Step 2: Sign the payload
    if verbose:
        print("Signing payload with secret key...")

    try:
        message = encode_defunct(text=payload)
        signed = Account.sign_message(message, private_key)
        signature = signed.signature.hex()
        if not signature.startswith("0x"):
            signature = "0x" + signature
    except Exception as e:
        raise ValueError(f"Failed to sign message: {e}")

    if verbose:
        print(f"Signature: {signature[:20]}...{signature[-8:]}\n")

    # Step 3: Verify the signature
    if verbose:
        print(f"Submitting signature to {server_url}/verify...")

    try:
        resp = requests.post(
            f"{server_url}/verify",
            json={
                "address": address,
                "nonce": nonce,
                "signature": signature,
            },
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        error_detail = resp.json().get("detail", str(e))
        raise ValueError(f"Verification failed: {error_detail}")

    return resp.json()


def main():
    parser = argparse.ArgumentParser(
        description="Authenticate with your AgentAddress",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using command line arguments
  python sign.py --server http://localhost:8000 --address 0x123... --key 0xabc...

  # Using environment variables
  export AGENT_ADDRESS=0x123...
  export AGENT_KEY=0xabc...
  python sign.py --server http://localhost:8000

  # Interactive mode (prompts for credentials)
  python sign.py --server http://localhost:8000 --interactive
        """,
    )

    parser.add_argument(
        "--server", "-s",
        default="http://localhost:8000",
        help="AcceptAgentAddress server URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--address", "-a",
        help="Your AgentAddress (or set AGENT_ADDRESS env var)",
    )
    parser.add_argument(
        "--key", "-k",
        help="Your secret key (or set AGENT_KEY env var)",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Prompt for credentials interactively",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only output the result (for scripting)",
    )

    args = parser.parse_args()

    # Get credentials
    import os

    address = args.address or os.environ.get("AGENT_ADDRESS")
    private_key = args.key or os.environ.get("AGENT_KEY")

    if args.interactive:
        import getpass
        if not address:
            address = input("AgentAddress: ").strip()
        if not private_key:
            private_key = getpass.getpass("Secret Key: ").strip()

    if not address:
        print("Error: AgentAddress required. Use --address, set AGENT_ADDRESS, or use --interactive", file=sys.stderr)
        sys.exit(1)

    if not private_key:
        print("Error: Secret key required. Use --key, set AGENT_KEY, or use --interactive", file=sys.stderr)
        sys.exit(1)

    # Validate format
    if not address.startswith("0x") or len(address) != 42:
        print("Error: Invalid AgentAddress format (should be 0x + 40 hex chars)", file=sys.stderr)
        sys.exit(1)

    if not private_key.startswith("0x"):
        private_key = "0x" + private_key

    # Authenticate
    try:
        if not args.quiet:
            print("🤖 AgentAddress Authentication\n")

        result = authenticate(
            server_url=args.server,
            address=address,
            private_key=private_key,
            verbose=args.verbose and not args.quiet,
        )

        if args.quiet:
            print("verified" if result["verified"] else "failed")
        else:
            if result["verified"]:
                print("✓ Authentication successful!")
                print(f"  Address: {result['address']}")
            else:
                print("✗ Authentication failed!")
                print(f"  {result['message']}")

        sys.exit(0 if result["verified"] else 1)

    except ConnectionError as e:
        if args.quiet:
            print("error")
        else:
            print(f"✗ Connection error: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        if args.quiet:
            print("error")
        else:
            print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
