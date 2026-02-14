# Header Files for MPT Crypto

This directory contains the C header files required to build the Python bindings for mpt-crypto.

## Required Files

- `secp256k1.h` - Main secp256k1 library header
- `secp256k1_mpt.h` - MPT-specific extensions to secp256k1

## Obtaining the Headers

These header files should be copied from the mpt-crypto repository:

```bash
# From the mpt-crypto repository
cp include/secp256k1_mpt.h /path/to/xrpl-py/xrpl/core/confidential/include/
cp build/secp256k1_build/include/secp256k1.h /path/to/xrpl-py/xrpl/core/confidential/include/
```

## Notes

- These headers are needed at build time only (when running `build_mpt_crypto.py`)
- They are not needed at runtime
- The headers must match the version of the pre-compiled libraries in `../libs/`

