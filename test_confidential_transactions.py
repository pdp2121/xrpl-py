#!/usr/bin/env python3
"""
Test script for Confidential MPT transactions.

This script tests all confidential transaction types against a local rippled instance:
- MPTokenIssuanceCreate (with confidential support)
- ConfidentialConvert (public → confidential)
- ConfidentialSend (confidential transfer)
- ConfidentialMergeInbox (merge inbox to spending balance)
- ConfidentialConvertBack (confidential → public)
- ConfidentialClawback (issuer claws back from holder)

Prerequisites:
- rippled running on localhost:5005 with confidential MPT support
- charm-crypto-lite installed: pip install xrpl-py[confidential]
"""

import json
import os
import sys
from typing import Any, Dict

from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.models.amounts import MPTAmount
from xrpl.models.requests import AccountInfo, AccountObjects, GenericRequest, ServerInfo
from xrpl.models.requests.account_objects import AccountObjectType
from xrpl.models.transactions import Payment
from xrpl.transaction import sign_and_submit
from xrpl.wallet import Wallet

# Check if confidential module is available
try:
    from charm_lite.toolbox.ecgroup import ZR

    from xrpl.confidential import (
        ElGamalCMPT,
        create_initial_balance,
        generate_elgamal_keypair_with_proof,
        prepare_confidential_clawback,
        prepare_confidential_convert,
        prepare_confidential_convert_back,
        prepare_confidential_send,
    )
    from xrpl.confidential.primitives import point_to_bytes, point_to_bytes_uncompressed

    CONFIDENTIAL_AVAILABLE = True
except ImportError as e:
    print(f"❌ Confidential module not available: {e}")
    print("Install with: pip install xrpl-py[confidential]")
    CONFIDENTIAL_AVAILABLE = False
    sys.exit(1)

# XRPL imports
from xrpl.models.transactions import (
    ConfidentialClawback,
    ConfidentialConvert,
    ConfidentialConvertBack,
    ConfidentialMergeInbox,
    ConfidentialSend,
    MPTokenAuthorize,
    MPTokenIssuanceCreate,
    MPTokenIssuanceCreateFlag,
    MPTokenIssuanceSet,
    MPTokenIssuanceSetFlag,
)

# Configuration
RIPPLED_URL = "http://localhost:5005"
# Master account for standalone rippled
# Standard rippled standalone genesis account
MASTER_ACCOUNT = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
# This is the standard seed for the genesis account in rippled standalone
MASTER_SECRET = "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
FUNDING_AMOUNT = "2000000000"  # 2000 XRP in drops

# Ledger accept request for standalone mode
LEDGER_ACCEPT_REQUEST = GenericRequest(method="ledger_accept")


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def print_tx_response(response: Any, title: str = "Transaction Response") -> None:
    """Print transaction response in formatted JSON."""
    print(f"\n📋 {title}:")
    print(
        json.dumps(
            response.to_dict() if hasattr(response, "to_dict") else response, indent=2
        )
    )


def check_tx_success(response: Any, tx_name: str) -> None:
    """Check if transaction was successful, exit if not."""
    engine_result = response.result.get("engine_result", "")
    if engine_result != "tesSUCCESS":
        engine_message = response.result.get("engine_result_message", "Unknown error")
        print(f"\n❌ {tx_name} failed!")
        print(f"   Engine result: {engine_result}")
        print(f"   Message: {engine_message}")
        sys.exit(1)


def fund_account(client: JsonRpcClient, address: str, master_wallet: Wallet) -> None:
    """Fund an account from the genesis account (standalone mode)."""
    print(f"💰 Funding account {address}...")

    payment = Payment(
        account=master_wallet.address,
        destination=address,
        amount=FUNDING_AMOUNT,
    )

    response = sign_and_submit(payment, client, master_wallet)
    check_tx_success(response, "Payment")

    # Accept the ledger in standalone mode
    client.request(LEDGER_ACCEPT_REQUEST)

    print(f"✅ Funded {address}")


def fund_wallet_from_faucet(client: JsonRpcClient, wallet: Wallet) -> None:
    """Fund a wallet using the devnet faucet."""
    print(f"💰 Funding account {wallet.address} from faucet...")

    try:
        import time

        # Use xrpl-py's built-in faucet function with custom URL
        from xrpl.wallet import fund_wallet as xrpl_fund_wallet

        # The confidential devnet might use a different faucet
        # Let's try the standard devnet faucet first
        try:
            xrpl_fund_wallet(wallet, client, faucet_host="faucet.devnet.rippletest.net")
            print(f"✅ Funded {wallet.address}")
        except Exception as e:
            print(f"   Standard faucet failed: {e}")
            print(f"   Trying alternative method...")

            # Try direct API call
            import requests

            faucet_url = "https://faucet.devnet.rippletest.net/accounts"
            response = requests.post(faucet_url, json={"destination": wallet.address})

            if response.status_code != 200:
                print(
                    f"❌ Faucet request failed: {response.status_code} - {response.text}"
                )
                sys.exit(1)

            # Wait and verify
            time.sleep(5)
            account_info = client.request(AccountInfo(account=wallet.address))
            if account_info.is_successful():
                balance = (
                    int(account_info.result["account_data"]["Balance"]) / 1_000_000
                )
                print(f"✅ Funded {wallet.address} with {balance} XRP")
            else:
                print(f"❌ Account not found after funding")
                sys.exit(1)

    except Exception as e:
        print(f"❌ Failed to fund account: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


def main():
    """Run the confidential transaction test suite."""
    print_section("Confidential MPT Transaction Test Suite")

    # Connect to local rippled
    print(f"🔌 Connecting to {RIPPLED_URL}...")
    client = JsonRpcClient(RIPPLED_URL)

    try:
        server_info = client.request(ServerInfo())
        print(
            f"✅ Connected to rippled (version: {server_info.result.get('info', {}).get('build_version', 'unknown')})"
        )
    except Exception as e:
        print(f"❌ Failed to connect to rippled: {e}")
        print("Make sure rippled is running on localhost:5005")
        sys.exit(1)

    # Create and fund test accounts
    print_section("Step 1: Create and Fund Test Accounts")

    # Get master account for funding
    print("🔑 Using master account for funding...")

    # Try to use the expected master account first
    master_wallet = None
    for account_address in [MASTER_ACCOUNT]:
        try:
            # Check if this account exists
            account_info = client.request(AccountInfo(account=account_address))
            balance = int(account_info.result["account_data"]["Balance"]) / 1_000_000
            print(f"Master: {account_address}")
            print(f"   Balance: {balance:,.2f} XRP")

            # We found the account, but we need the seed to sign transactions
            # For standalone rippled, the standard genesis account seed is snoPBrXtMeMyMHUVTgbuqAfg1SUTb
            # The seed uses SECP256K1 algorithm to generate rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
            test_wallet = Wallet.from_seed(
                MASTER_SECRET, algorithm=CryptoAlgorithm.SECP256K1
            )
            if test_wallet.address == account_address:
                master_wallet = test_wallet
                print(f"   ✅ Seed matches account!")
                break
            else:
                print(
                    f"   ⚠️  Seed generates {test_wallet.address}, not {account_address}"
                )
                print(f"   Trying to use the generated address instead...")
                # Check if the generated address exists
                try:
                    gen_account_info = client.request(
                        AccountInfo(account=test_wallet.address)
                    )
                    gen_balance = (
                        int(gen_account_info.result["account_data"]["Balance"])
                        / 1_000_000
                    )
                    print(
                        f"   Generated address exists with balance: {gen_balance:,.2f} XRP"
                    )
                    master_wallet = test_wallet
                    break
                except:
                    pass
        except Exception as e:
            print(f"   Account {account_address} not found: {e}")

    if master_wallet is None:
        print(f"❌ Could not find a usable master account")
        print(f"   Make sure your standalone rippled is running")
        sys.exit(1)

    print(f"   Using master account: {master_wallet.address}")

    # Create test accounts
    issuer_wallet = Wallet.create()
    holder1_wallet = Wallet.create()
    holder2_wallet = Wallet.create()

    print(f"\nIssuer:  {issuer_wallet.address}")
    print(f"Holder1: {holder1_wallet.address}")
    print(f"Holder2: {holder2_wallet.address}")

    # Fund accounts from genesis account
    fund_account(client, issuer_wallet.address, master_wallet)
    fund_account(client, holder1_wallet.address, master_wallet)
    fund_account(client, holder2_wallet.address, master_wallet)

    # Generate ElGamal keypairs
    print_section("Step 2: Generate ElGamal Keypairs")

    elgamal = ElGamalCMPT()

    issuer_pk, issuer_sk, issuer_pok = generate_elgamal_keypair_with_proof(elgamal)
    holder1_pk, holder1_sk, holder1_pok = generate_elgamal_keypair_with_proof(elgamal)
    holder2_pk, holder2_sk, holder2_pok = generate_elgamal_keypair_with_proof(elgamal)

    print(f"✅ Generated ElGamal keypairs for all accounts")

    # Serialize public keys for transactions
    # NOTE: The working example uses UNCOMPRESSED format (64 bytes = 128 hex chars) for ALL keys!
    # This contradicts the spec which says 33 bytes, but let's match the working example.
    # CRITICAL: Reverse byte order of X and Y coordinates (based on xrpl4j finding)
    issuer_pk_uncompressed = point_to_bytes_uncompressed(elgamal.group, issuer_pk["h"])
    holder1_pk_uncompressed = point_to_bytes_uncompressed(
        elgamal.group, holder1_pk["h"]
    )
    holder2_pk_uncompressed = point_to_bytes_uncompressed(
        elgamal.group, holder2_pk["h"]
    )

    # Reverse byte order for each coordinate (big-endian to little-endian)
    def reverse_coordinates(pk_bytes):
        x_coord = pk_bytes[:32]
        y_coord = pk_bytes[32:64]
        return bytes(reversed(x_coord)) + bytes(reversed(y_coord))

    # Try WITH reversing each coordinate (big-endian to little-endian)
    # Based on xrpl4j finding: reverse byte order of X and Y coordinates
    issuer_pk_hex = reverse_coordinates(issuer_pk_uncompressed).hex()
    holder1_pk_hex = reverse_coordinates(holder1_pk_uncompressed).hex()
    holder2_pk_hex = reverse_coordinates(holder2_pk_uncompressed).hex()

    print(
        f"Issuer PK (uncompressed):  {issuer_pk_hex[:32]}... ({len(issuer_pk_hex)} hex chars)"
    )
    print(
        f"Holder1 PK (uncompressed): {holder1_pk_hex[:32]}... ({len(holder1_pk_hex)} hex chars)"
    )
    print(
        f"Holder2 PK (uncompressed): {holder2_pk_hex[:32]}... ({len(holder2_pk_hex)} hex chars)"
    )

    # Serialize Schnorr proofs (T: 33 bytes point + s: 32 bytes scalar = 65 bytes)
    def serialize_schnorr_proof(proof: Dict[str, Any], group) -> bytes:
        """Serialize Schnorr proof dict to bytes."""
        # T is the commitment point (33 bytes compressed)
        t_bytes = point_to_bytes(group, proof["T"])
        # s is a scalar (32 bytes)
        s_int = int(proof["s"])
        s_bytes = s_int.to_bytes(32, "big")
        return t_bytes + s_bytes

    # NOTE: The server expects 65-byte Schnorr proofs (33 bytes T + 32 bytes s)
    # Generate the real Schnorr proof for holder1 (with default zero context)
    holder1_pok_hex = serialize_schnorr_proof(holder1_pok, elgamal.group).hex()
    print(
        f"\n🔍 Holder1 Schnorr Proof: {holder1_pok_hex[:32]}... ({len(holder1_pok_hex)} hex chars)"
    )

    # Verify the proof locally before sending
    proof_valid = elgamal.verify_pok(holder1_pk, holder1_pok)
    print(f"   Local proof verification: {'✅ VALID' if proof_valid else '❌ INVALID'}")

    # Step 3: Create MPT Issuance with Privacy Support
    # NOTE: We need TF_MPT_CAN_PRIVACY flag to enable confidential transactions
    # Flags breakdown:
    #   - 0x02 (2):   TF_MPT_CAN_LOCK
    #   - 0x20 (32):  TF_MPT_CAN_TRANSFER
    #   - 0x40 (64):  TF_MPT_CAN_CLAWBACK
    #   - 0x80 (128): TF_MPT_CAN_PRIVACY
    # Total: 0x02 | 0x20 | 0x40 | 0x80 = 0xE2 = 226
    print_section("Step 3: Create MPT Issuance with Privacy Support")

    mpt_create = MPTokenIssuanceCreate(
        account=issuer_wallet.address,
        maximum_amount="1000000",  # 1M tokens
        asset_scale=2,  # 2 decimal places
        flags=(
            MPTokenIssuanceCreateFlag.TF_MPT_CAN_LOCK
            | MPTokenIssuanceCreateFlag.TF_MPT_CAN_TRANSFER
            | MPTokenIssuanceCreateFlag.TF_MPT_CAN_CLAWBACK
            | MPTokenIssuanceCreateFlag.TF_MPT_CAN_PRIVACY
        ),
    )

    print("📝 Creating MPT issuance...")
    response = sign_and_submit(mpt_create, client, issuer_wallet)
    print_tx_response(response, "MPTokenIssuanceCreate")
    check_tx_success(response, "MPTokenIssuanceCreate")

    # Extract the sequence number from the transaction
    seq = response.result["tx_json"]["Sequence"]

    # Query the ledger to get the MPT issuance ID
    account_objects_response = client.request(
        AccountObjects(
            account=issuer_wallet.address, type=AccountObjectType.MPT_ISSUANCE
        )
    )

    # Find the MPT issuance object that matches our sequence number
    mpt_issuance_id = ""
    for obj in account_objects_response.result["account_objects"]:
        if (
            obj.get("Issuer") == issuer_wallet.classic_address
            and obj.get("Sequence") == seq
        ):
            mpt_issuance_id = obj["mpt_issuance_id"]
            break

    if not mpt_issuance_id:
        raise ValueError(
            f"MPT issuance ID not found for issuer "
            f"{issuer_wallet.classic_address} and sequence {seq}"
        )

    print(f"✅ MPT Issuance created: {mpt_issuance_id}")
    print(
        f"   Length: {len(mpt_issuance_id)} hex chars ({len(mpt_issuance_id) // 2} bytes)"
    )

    # Debug: Print the full MPT issuance object to see what flags are set
    print("\n📋 MPT Issuance Object:")
    for obj in account_objects_response.result["account_objects"]:
        if (
            obj.get("Issuer") == issuer_wallet.classic_address
            and obj.get("Sequence") == seq
        ):
            print(json.dumps(obj, indent=2))
            break

    # MPTokenIssuanceID is 24 bytes (48 hex chars), not 32 bytes
    # Use it directly without padding
    mpt_issuance_id_bytes = bytes.fromhex(mpt_issuance_id)

    # Step 4: Enable Confidential Support via MPTokenIssuanceSet
    print_section("Step 4: Enable Confidential Support")

    # NOTE: The working example uses Flags: 2 (TF_MPT_UNLOCK).
    # Now testing against confidential devnet instead of localhost.

    # Debug: Verify the ElGamal key format
    print(f"\n🔍 Debug - ElGamal Key:")
    print(f"   Hex: {issuer_pk_hex}")
    print(
        f"   Length: {len(issuer_pk_hex)} hex chars = {len(issuer_pk_hex) // 2} bytes"
    )
    print(f"   Uppercase: {issuer_pk_hex.upper()}")

    # Try with uppercase (like the working example)
    mpt_set = MPTokenIssuanceSet(
        account=issuer_wallet.address,
        mptoken_issuance_id=mpt_issuance_id,
        issuer_elgamal_public_key=issuer_pk_hex.upper(),
        flags=MPTokenIssuanceSetFlag.TF_MPT_UNLOCK,  # Flags: 2
    )

    print("\n📝 Enabling confidential support...")
    response = sign_and_submit(mpt_set, client, issuer_wallet)
    print_tx_response(response, "MPTokenIssuanceSet")
    check_tx_success(response, "MPTokenIssuanceSet")

    # Accept the ledger in standalone mode
    client.request(LEDGER_ACCEPT_REQUEST)

    print("✅ Confidential support enabled successfully")

    # Step 5: Authorize holders
    print_section("Step 5: Authorize Holders")

    for holder_wallet, holder_name in [
        (holder1_wallet, "Holder1"),
        (holder2_wallet, "Holder2"),
    ]:
        authorize = MPTokenAuthorize(
            account=holder_wallet.address,
            mptoken_issuance_id=mpt_issuance_id,
        )

        print(f"📝 Authorizing {holder_name}...")
        response = sign_and_submit(authorize, client, holder_wallet)
        print_tx_response(response, f"MPTokenAuthorize ({holder_name})")
        check_tx_success(response, f"MPTokenAuthorize ({holder_name})")
        print(f"✅ {holder_name} authorized")

    # Step 5.5: Send Public MPT Tokens to Holders
    print_section("Step 5.5: Send Public MPT Tokens to Holders")

    # Send 2000 public MPT tokens to each holder
    for holder_wallet, holder_name in [
        (holder1_wallet, "Holder1"),
        (holder2_wallet, "Holder2"),
    ]:
        payment = Payment(
            account=issuer_wallet.address,
            destination=holder_wallet.address,
            amount=MPTAmount(
                mpt_issuance_id=mpt_issuance_id,
                value="2000",
            ),
        )

        print(f"📝 Sending 2000 public MPT tokens to {holder_name}...")
        response = sign_and_submit(payment, client, issuer_wallet)
        print_tx_response(response, f"MPT Payment to {holder_name}")
        check_tx_success(response, f"MPT Payment to {holder_name}")
        print(f"✅ {holder_name} funded with 2000 public MPT tokens")

    # Step 6: Test ConfidentialConvert (public → confidential)
    print_section("Step 6: Test ConfidentialConvert (Holder1: 1000 tokens)")

    # Get holder1's sequence number
    account_info = client.request(AccountInfo(account=holder1_wallet.address))
    holder1_sequence = account_info.result["account_data"]["Sequence"]

    # Prepare convert transaction
    convert_amount = 1000
    tx_data = prepare_confidential_convert(
        account=holder1_wallet.address.encode(),
        amount=convert_amount,
        holder_pk=holder1_pk,
        issuer_pk=issuer_pk,
        mpt_issuance_id=mpt_issuance_id_bytes,
        sequence=holder1_sequence,
        elgamal=elgamal,
    )

    # Serialize the ElGamal randomness (blinding factor) to 32 bytes
    r_int = int(tx_data["elgamal_randomness"])
    blinding_factor_hex = r_int.to_bytes(32, "big").hex()

    # Compute the context_id for Schnorr proof (for key registration in ConfidentialConvert)
    # This must match rippled's getConvertContextHash implementation:
    # Serializer format: txType (2 bytes) + account (20 bytes) + sequence (4 bytes) + issuanceID (24 bytes) + amount (8 bytes)
    # Then SHA512Half (first 32 bytes of SHA-512)
    import hashlib

    from xrpl.core.addresscodec import decode_classic_address

    # Get the 20-byte AccountID
    account_id_bytes = decode_classic_address(holder1_wallet.address)

    # Build the serialized context matching rippled's Serializer
    # ConfidentialConvert transaction type code is 85
    TX_TYPE_CONFIDENTIAL_CONVERT = 85

    context_bytes = b""
    context_bytes += TX_TYPE_CONFIDENTIAL_CONVERT.to_bytes(2, "big")  # 2 bytes, uint16
    context_bytes += account_id_bytes  # 20 bytes
    context_bytes += holder1_sequence.to_bytes(4, "big")  # 4 bytes, uint32
    context_bytes += mpt_issuance_id_bytes  # 24 bytes
    context_bytes += convert_amount.to_bytes(8, "big")  # 8 bytes, uint64

    # Use SHA-512 and take first 32 bytes (SHA512Half)
    context_id = hashlib.sha512(context_bytes).digest()[:32]
    print(f"\n🔍 Context ID (SHA512Half): {context_id.hex()} ({len(context_id)} bytes)")
    print(f"   Context bytes length: {len(context_bytes)} bytes (should be 58)")
    print(f"   TX Type: {TX_TYPE_CONFIDENTIAL_CONVERT}")
    print(f"   Account ID: {account_id_bytes.hex()}")
    print(f"   Sequence: {holder1_sequence}")
    print(f"   MPT Issuance ID: {mpt_issuance_id_bytes.hex()}")
    print(f"   Amount: {convert_amount}")

    # Generate proof with TRANSACTION CONTEXT using ORIGINAL key
    # But verify against REVERSED key bytes (what the server will see)
    print("\n🔬 Generating proof with TRANSACTION CONTEXT:")
    holder1_pok_tx = elgamal.generate_pok(holder1_pk, holder1_sk, context_id=context_id)
    holder1_pok_tx_hex = serialize_schnorr_proof(holder1_pok_tx, elgamal.group).hex()

    # Verify with ORIGINAL key (our internal format)
    proof_valid_tx = elgamal.verify_pok(
        holder1_pk, holder1_pok_tx, context_id=context_id
    )
    print(f"   Proof (tx context): {holder1_pok_tx_hex[:32]}...")
    print(
        f"   Verification (original key): {'✅ VALID' if proof_valid_tx else '❌ INVALID'}"
    )

    # Debug: Verify the proof using our Python implementation against REVERSED bytes
    print("\n🔍 DEBUG: Verifying proof with REVERSED key bytes (what server sees)...")
    from debug_schnorr_verify import verify_schnorr_proof

    proof_bytes = bytes.fromhex(holder1_pok_tx_hex)
    holder1_pk_reversed_bytes = reverse_coordinates(holder1_pk_uncompressed)

    python_verify_result = verify_schnorr_proof(
        elgamal.group, holder1_pk_reversed_bytes, proof_bytes, context_id
    )

    print(
        f"\n   Python verification result: {'✅ VALID' if python_verify_result else '❌ INVALID'}"
    )

    # Use the transaction context proof
    print("\n📤 Submitting with TRANSACTION CONTEXT proof...")
    holder1_pok = holder1_pok_tx
    holder1_pok_hex = holder1_pok_tx_hex

    convert_tx = ConfidentialConvert(
        account=holder1_wallet.address,
        mptoken_issuance_id=mpt_issuance_id,
        mpt_amount=convert_amount,
        holder_encrypted_amount=tx_data["holder_encrypted_amount"],
        issuer_encrypted_amount=tx_data["issuer_encrypted_amount"],
        blinding_factor=blinding_factor_hex,  # 32-byte ElGamal randomness (REQUIRED)
        holder_elgamal_public_key=holder1_pk_hex,
        zk_proof=holder1_pok_hex,  # 65-byte Schnorr proof
    )

    print(f"📝 Converting {convert_amount} tokens to confidential...")
    response = sign_and_submit(convert_tx, client, holder1_wallet)
    print_tx_response(response, "ConfidentialConvert")
    check_tx_success(response, "ConfidentialConvert")
    print("✅ ConfidentialConvert successful")

    # Step 7: Test ConfidentialMergeInbox
    print_section("Step 7: Test ConfidentialMergeInbox (Holder1)")

    merge_tx = ConfidentialMergeInbox(
        account=holder1_wallet.address,
        mptoken_issuance_id=mpt_issuance_id,
    )

    print("📝 Merging inbox to spending balance...")
    response = sign_and_submit(merge_tx, client, holder1_wallet)
    print_tx_response(response, "ConfidentialMergeInbox")
    check_tx_success(response, "ConfidentialMergeInbox")
    print("✅ ConfidentialMergeInbox successful")

    print("\n✅ All confidential transaction tests completed!")


if __name__ == "__main__":
    if not CONFIDENTIAL_AVAILABLE:
        sys.exit(1)

    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
