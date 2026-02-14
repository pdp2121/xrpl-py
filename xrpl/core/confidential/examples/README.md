# Confidential MPT Examples

This directory contains example scripts demonstrating how to use the confidential MPT functionality in xrpl-py.

## Prerequisites

1. **Install xrpl-py with confidential support**:
   ```bash
   poetry install --extras confidential
   ```

2. **Build the C extension**:
   ```bash
   poetry run poe build_mpt_crypto
   ```

3. **Run rippled with confidential MPT support**:
   - You need a rippled instance running on `localhost:5005`
   - The rippled build must include confidential MPT support
   - Make sure the master account is funded

## Examples

### `submit_confidential_tx.py`

A complete workflow demonstrating all confidential MPT transaction types using the high-level transaction builder functions.

**What it demonstrates**:
1. Setting up accounts and funding them
2. Creating an MPT issuance with privacy support
3. Converting public tokens to confidential (`prepare_confidential_convert`)
4. Merging inbox to spending balance (`prepare_confidential_merge_inbox`)
5. Sending confidential tokens between holders (`prepare_confidential_send`)
6. Converting confidential tokens back to public (`prepare_confidential_convert_back`)

**Run it**:
```bash
python3 xrpl/core/confidential/examples/submit_confidential_tx.py
```

**Expected output**:
```
═══════════════════════════════════════════════════════════════════
Confidential MPT Transaction Example
═══════════════════════════════════════════════════════════════════
Using high-level transaction builder functions

═══════════════════════════════════════════════════════════════════
Step 1: Setup
═══════════════════════════════════════════════════════════════════
✅ Connected to rippled

🔑 Setting up master account...
Master: rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
Balance: 100,000.00 XRP

🔑 Creating test accounts...
Issuer:  rN7n7otQDd6FczFgLdlqtyMVrn3z1oqh3V
Holder1: rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY
Holder2: rBTwLga3i2gz3doX6Gva3MgEV8ZCD8jjah

💰 Funding accounts...
✅ All accounts funded

...

═══════════════════════════════════════════════════════════════════
Summary
═══════════════════════════════════════════════════════════════════
✅ All confidential MPT transactions completed successfully!

Transaction flow:
  1. Holder1 converted 1000 public → confidential
  2. Holder1 merged inbox to spending balance
  3. Holder1 sent 300 confidential → Holder2
  4. Holder2 merged inbox to spending balance
  5. Holder1 converted 200 confidential → public

Final balances:
  Holder1 confidential: 500 tokens
  Holder1 public: 200 tokens
  Holder2 confidential: 300 tokens
```

## Key Concepts

### High-Level Transaction Builders

The examples use high-level transaction builder functions that handle all the complexity:

- **`prepare_confidential_convert()`** - Converts public tokens to confidential
  - Queries ledger for sequence and issuer public key
  - Generates holder keypair if not provided
  - Computes context hash
  - Generates Schnorr proof of knowledge
  - Encrypts amount for holder and issuer
  - Returns ready-to-submit transaction

- **`prepare_confidential_merge_inbox()`** - Merges inbox to spending balance
  - Simplest transaction, no proofs needed
  - Returns ready-to-submit transaction

- **`prepare_confidential_send()`** - Transfers confidential tokens
  - Queries sender's current balance and version
  - Queries receiver and issuer public keys
  - Computes context hash
  - Encrypts amount for sender, receiver, and issuer
  - Creates Pedersen commitments
  - Generates all required zero-knowledge proofs
  - Returns ready-to-submit transaction

- **`prepare_confidential_convert_back()`** - Converts confidential to public
  - Queries holder's current balance and version
  - Queries issuer public key
  - Computes context hash
  - Encrypts amount for holder and issuer
  - Creates Pedersen commitment
  - Generates balance link proof
  - Returns ready-to-submit transaction

### Coordinate Byte Order

The C library outputs public keys in big-endian format (standard secp256k1), but rippled expects little-endian coordinates. The examples include a `reverse_coordinates()` helper function to handle this conversion.

## Troubleshooting

### "xrpl.core.confidential not available"

The C extension hasn't been built. Run:
```bash
poetry run poe build_mpt_crypto
```

### "Failed to connect to rippled"

Make sure rippled is running on `localhost:5005`:
```bash
# Check if rippled is running
curl http://localhost:5005 -X POST -H "Content-Type: application/json" -d '{"method":"server_info"}'
```

### "Master account not found"

The master account needs to be funded. Check your rippled configuration and make sure the genesis account is set up correctly.

## See Also

- [Transaction Builders Documentation](../transaction_builders.py)
- [C Bindings README](../README.md)
- [Integration Guide](../INTEGRATION.md)
- [Full Test Suite](../../../../test_confidential_with_c_bindings.py)

