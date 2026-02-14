# Setup Guide for Confidential MPT Support

This guide explains how to set up the confidential MPT functionality in xrpl-py.

## Overview

The confidential MPT feature uses pre-compiled C libraries that are **already included** in the repository:

- Pre-compiled static libraries (`libmpt-crypto.a`, `libsecp256k1.a`) in `libs/darwin/` (macOS)
- C header files (`secp256k1.h`, `secp256k1_mpt.h`) in `include/`
- Python bindings built using CFFI

## Quick Start (For Users)

The pre-compiled libraries are already included, so you just need to build the Python extension:

```bash
# Clone the repository
git clone https://github.com/XRPLF/xrpl-py.git
cd xrpl-py

# Build the C extension (one-time setup)
python xrpl/core/confidential/build_mpt_crypto.py

# Or use Poetry
poetry install
poetry run python xrpl/core/confidential/build_mpt_crypto.py

# Now you can use confidential MPT features
python xrpl/core/confidential/examples/submit_confidential_tx.py
```

## Setup for Development

### 1. Prepare Pre-compiled Libraries

The pre-compiled libraries should be placed in the `libs/` directory:

```
xrpl/core/confidential/
├── libs/
│   ├── darwin/
│   │   ├── libmpt-crypto.a
│   │   └── libsecp256k1.a
│   ├── linux/
│   │   ├── libmpt-crypto.a
│   │   └── libsecp256k1.a
│   └── win32/
│       ├── mpt-crypto.lib
│       └── secp256k1.lib
```

See `libs/README.md` for instructions on building these libraries.

### 2. Prepare Header Files

The header files should be placed in the `include/` directory:

```
xrpl/core/confidential/
├── include/
│   ├── secp256k1.h
│   └── secp256k1_mpt.h
```

See `include/README.md` for instructions on obtaining these headers.

### 3. Build the Python Extension

```bash
# From the repository root
cd xrpl/core/confidential
python build_mpt_crypto.py

# Or use Poetry
poetry run python xrpl/core/confidential/build_mpt_crypto.py
```

This will generate:

- `_mpt_crypto.c` - Generated C source
- `_mpt_crypto.o` - Compiled object file
- `_mpt_crypto.cpython-*.so` - Python extension module (macOS/Linux)
- `_mpt_crypto.cpython-*.pyd` - Python extension module (Windows)

## Platform-Specific Notes

### macOS

- Requires Xcode Command Line Tools: `xcode-select --install`
- OpenSSL is required: `brew install openssl`
- The build script automatically detects macOS and uses `libs/darwin/`

### Linux

- Requires build essentials: `sudo apt-get install build-essential`
- OpenSSL development libraries: `sudo apt-get install libssl-dev`
- The build script automatically detects Linux and uses `libs/linux/`

### Windows

- Requires Visual Studio Build Tools
- OpenSSL for Windows: Download from https://slproweb.com/products/Win32OpenSSL.html
- The build script automatically detects Windows and uses `libs/win32/`

## Troubleshooting

### "Pre-compiled libraries not found" Error

Make sure the libraries are in the correct platform-specific directory:

- macOS: `libs/darwin/`
- Linux: `libs/linux/`
- Windows: `libs/win32/`

### "Cannot find secp256k1.h" Error

Make sure the header files are in the `include/` directory.

### Runtime Import Error

If you get an import error when using the module:

```python
from xrpl.core.confidential import MPTCrypto
# ImportError: cannot import name '_mpt_crypto'
```

Rebuild the extension:

```bash
cd xrpl/core/confidential
python build_mpt_crypto.py
```

## Distribution

For distributing xrpl-py with confidential MPT support:

1. **Include pre-compiled libraries** for all supported platforms in the repository
2. **Use cibuildwheel** to build platform-specific wheels
3. **Configure pyproject.toml** to build the extension during installation

Example `pyproject.toml` configuration:

```toml
[build-system]
requires = ["poetry-core>=1.0.0", "cffi>=1.15.0"]
build-backend = "poetry.core.masonry.api"

[tool.poetry.build]
script = "xrpl/core/confidential/build_mpt_crypto.py"
```

## Security Considerations

- The pre-compiled libraries should be built from trusted sources
- Verify the integrity of the libraries before including them in the repository
- Consider signing the libraries for additional security
- Keep the mpt-crypto dependency up to date with security patches
