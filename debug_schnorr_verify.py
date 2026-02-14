#!/usr/bin/env python3
"""
Debug script to replicate secp256k1_mpt_pok_sk_verify in Python.

This recreates the C verification logic to help debug proof verification failures.
"""

import hashlib

from charm_lite.toolbox.ecgroup import ECGroup


def build_pok_challenge(
    pk_compressed: bytes, T_compressed: bytes, context_id: bytes
) -> bytes:
    """
    Build the Schnorr proof challenge exactly as the C code does.

    Args:
        pk_compressed: Public key in compressed format (33 bytes)
        T_compressed: Commitment T in compressed format (33 bytes)
        context_id: Context ID (32 bytes)

    Returns:
        Challenge e (32 bytes)
    """
    sha = hashlib.sha256()

    # Domain separator
    sha.update(b"MPT_POK_SK_REGISTER")  # 19 bytes

    # Public key (compressed, 33 bytes)
    sha.update(pk_compressed)

    # Commitment T (compressed, 33 bytes)
    sha.update(T_compressed)

    # Context ID (32 bytes)
    sha.update(context_id)

    return sha.digest()  # 32 bytes


def verify_schnorr_proof(
    group: ECGroup, pk_uncompressed: bytes, proof: bytes, context_id: bytes
) -> bool:
    """
    Verify Schnorr proof matching the C implementation.

    Args:
        group: ECGroup for secp256k1
        pk_uncompressed: Public key in uncompressed format (64 bytes, no prefix)
        proof: Schnorr proof (65 bytes: 33 bytes T + 32 bytes s)
        context_id: Context ID (32 bytes)

    Returns:
        True if proof is valid
    """
    print("\n" + "=" * 80)
    print("SCHNORR PROOF VERIFICATION DEBUG")
    print("=" * 80)

    # Parse proof
    T_compressed = proof[:33]
    s_bytes = proof[33:65]

    print(f"\n1. Parse Proof:")
    print(f"   T (compressed): {T_compressed.hex()}")
    print(f"   s (scalar):     {s_bytes.hex()}")

    # Convert uncompressed public key to compressed
    # Uncompressed: x (32 bytes) + y (32 bytes)
    x_bytes = pk_uncompressed[:32]
    y_bytes = pk_uncompressed[32:64]

    y_int = int.from_bytes(y_bytes, "big")
    prefix = 0x02 if y_int % 2 == 0 else 0x03
    pk_compressed = bytes([prefix]) + x_bytes

    print(f"\n2. Public Key:")
    print(f"   Uncompressed: {pk_uncompressed.hex()}")
    print(f"   X: {x_bytes.hex()}")
    print(f"   Y: {y_bytes.hex()}")
    print(f"   Y is {'even' if y_int % 2 == 0 else 'odd'}")
    print(f"   Compressed: {pk_compressed.hex()}")

    # Build challenge
    e_bytes = build_pok_challenge(pk_compressed, T_compressed, context_id)
    e_int = int.from_bytes(e_bytes, "big")

    print(f"\n3. Challenge:")
    print(f"   Context ID: {context_id.hex()}")
    print(f"   e (hash):   {e_bytes.hex()}")
    print(f"   e (int):    {e_int}")

    # Parse points using charm
    from xrpl.confidential.primitives import bytes_to_point

    try:
        T_point = bytes_to_point(group, T_compressed)
        pk_point = bytes_to_point(group, pk_compressed)
        print(f"\n4. Parse Points:")
        print(f"   T parsed: ✅")
        print(f"   PK parsed: ✅")
    except Exception as e:
        print(f"\n4. Parse Points:")
        print(f"   ❌ Failed to parse: {e}")
        return False

    # Verify: s*G == T + e*Pk
    # LHS = s*G
    s_int = int.from_bytes(s_bytes, "big")
    G = group.generator()
    lhs = G**s_int

    print(f"\n5. Compute LHS (s*G):")
    print(f"   s (int): {s_int}")
    print(f"   LHS computed: ✅")

    # RHS = T + e*Pk
    e_pk = pk_point**e_int
    rhs = T_point * e_pk

    print(f"\n6. Compute RHS (T + e*Pk):")
    print(f"   e*Pk computed: ✅")
    print(f"   RHS computed: ✅")

    # Compare
    result = lhs == rhs

    print(f"\n7. Verification Result:")
    print(f"   LHS == RHS: {'✅ VALID' if result else '❌ INVALID'}")

    # Serialize both sides for comparison
    from xrpl.confidential.primitives import point_to_bytes

    lhs_bytes = point_to_bytes(group, lhs)
    rhs_bytes = point_to_bytes(group, rhs)

    print(f"\n8. Serialized Comparison:")
    print(f"   LHS: {lhs_bytes.hex()}")
    print(f"   RHS: {rhs_bytes.hex()}")
    print(f"   Match: {'✅' if lhs_bytes == rhs_bytes else '❌'}")

    print("\n" + "=" * 80)

    return result


if __name__ == "__main__":
    print("Schnorr Proof Verification Debug Tool")
    print("This script can be imported and used to debug proof verification")
