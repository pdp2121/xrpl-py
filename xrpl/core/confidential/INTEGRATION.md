# Confidential MPT Integration with Poetry

This document describes how the Confidential MPT C bindings are integrated with xrpl-py's Poetry build system.

## Poetry Configuration

### Optional Dependencies

The C bindings are available as an optional dependency group called `confidential`:

```toml
[tool.poetry.dependencies]
cffi = { version = "^1.15.0", optional = true }

[project.optional-dependencies]
confidential = ["cffi>=1.15.0"]

[tool.poetry.extras]
confidential = ["cffi"]
```

### Installation

Users can install xrpl-py with confidential MPT support:

```bash
# With Poetry
poetry install --extras confidential

# With pip
pip install xrpl-py[confidential]
```

## Build Task

A Poetry task is provided to build the C extension:

```toml
[tool.poe.tasks]
build_mpt_crypto = "python3 xrpl/core/confidential/build_mpt_crypto.py"
```

### Usage

```bash
# Build the C extension
poetry run poe build_mpt_crypto
```

This task:
1. Compiles the `mpt-crypto` C library
2. Generates Python bindings using `cffi`
3. Creates a platform-specific `.so` file (e.g., `_mpt_crypto.cpython-311-darwin.so`)

## Git Ignore

The following files are excluded from version control:

```gitignore
# C extensions
*.so
*.o
_mpt_crypto.c
```

This ensures that:
- Compiled binaries are not committed (they're platform/Python-version specific)
- Generated C code is not committed
- Each developer/user builds for their own environment

## Build Process

### What Gets Built

When `build_mpt_crypto.py` runs:

1. **Defines C API** - Uses `cffi` to define the interface to `mpt-crypto`
2. **Compiles C Code** - Links against `libsecp256k1` and `mpt-crypto`
3. **Generates Extension** - Creates `_mpt_crypto.cpython-{version}-{platform}.so`

### Build Requirements

- **C Compiler**: gcc, clang, or MSVC
- **Python Headers**: Usually included with Python
- **cffi**: Installed via `poetry install --extras confidential`
- **mpt-crypto Source**: Included in the repository

### Platform-Specific Notes

**macOS**:
- Uses clang (Xcode Command Line Tools)
- Links against system `libsecp256k1` or Homebrew version

**Linux**:
- Uses gcc
- May need to install `libsecp256k1-dev`

**Windows**:
- Uses MSVC
- May need to build `libsecp256k1` separately

## Developer Workflow

### First-Time Setup

```bash
# 1. Clone repository
git clone https://github.com/XRPLF/xrpl-py.git
cd xrpl-py

# 2. Install dependencies with confidential support
poetry install --extras confidential

# 3. Build C extension
poetry run poe build_mpt_crypto

# 4. Run tests
python3 test_confidential_with_c_bindings.py
```

### After Updating mpt-crypto

If the `mpt-crypto` C library is updated:

```bash
# Rebuild the extension
poetry run poe build_mpt_crypto
```

### Switching Python Versions

The C extension must be rebuilt for each Python version:

```bash
# Switch Python version (e.g., with pyenv)
pyenv local 3.11

# Rebuild
poetry run poe build_mpt_crypto
```

## CI/CD Considerations

For continuous integration:

```yaml
# Example GitHub Actions workflow
- name: Install dependencies
  run: poetry install --extras confidential

- name: Build C extension
  run: poetry run poe build_mpt_crypto

- name: Run tests
  run: python3 test_confidential_with_c_bindings.py
```

## Future Enhancements

### Option 1: Automatic Build on Install

Integrate with Poetry's build system to automatically compile the C extension during `poetry install`:

- Use a custom build backend
- Add a `build.py` script
- Requires Poetry plugin support

### Option 2: Pre-built Wheels

Distribute pre-compiled wheels for common platforms:

- Build wheels for Python 3.8, 3.9, 3.10, 3.11, 3.12
- Build for macOS (x86_64, arm64), Linux (x86_64, aarch64), Windows (x86_64)
- Upload to PyPI
- Users get the right binary automatically

### Option 3: Fallback to Pure Python

Provide a pure Python implementation as a fallback:

- Try to import C bindings first
- Fall back to Python implementation if C bindings unavailable
- Trade-off: Performance vs. ease of installation

## Troubleshooting

### "cffi not found"

```bash
poetry install --extras confidential
```

### "C compiler not found"

**macOS**: Install Xcode Command Line Tools
```bash
xcode-select --install
```

**Linux**: Install build essentials
```bash
sudo apt-get install build-essential
```

**Windows**: Install Visual Studio Build Tools

### "libsecp256k1 not found"

The `mpt-crypto` library includes its own secp256k1 implementation, but if you see this error:

**macOS**:
```bash
brew install libsecp256k1
```

**Linux**:
```bash
sudo apt-get install libsecp256k1-dev
```

## Summary

The Confidential MPT C bindings are:
- ✅ Integrated with Poetry as an optional dependency
- ✅ Built via a Poetry task (`poe build_mpt_crypto`)
- ✅ Excluded from version control (`.gitignore`)
- ✅ Documented for users and developers
- ✅ Ready for CI/CD integration

