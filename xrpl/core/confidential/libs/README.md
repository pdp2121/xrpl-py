# Pre-compiled Libraries for MPT Crypto

This directory contains pre-compiled static libraries for the mpt-crypto C library and its dependencies.

## Directory Structure

```
libs/
├── darwin/          # macOS (x86_64 and arm64)
│   ├── libmpt-crypto.a
│   └── libsecp256k1.a
├── linux/           # Linux (x86_64)
│   ├── libmpt-crypto.a
│   └── libsecp256k1.a
└── win32/           # Windows (x86_64)
    ├── mpt-crypto.lib
    └── secp256k1.lib
```

## Building the Libraries

If you need to rebuild the libraries for your platform, follow these steps:

### Prerequisites

- CMake 3.15+
- C compiler (gcc, clang, or MSVC)
- OpenSSL development libraries

### macOS

```bash
# Clone the mpt-crypto repository
git clone https://github.com/your-org/mpt-crypto.git
cd mpt-crypto

# Build the library
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make

# Copy the libraries
cp libmpt-crypto.a /path/to/xrpl-py/xrpl/core/confidential/libs/darwin/
cp secp256k1_build/lib/libsecp256k1.a /path/to/xrpl-py/xrpl/core/confidential/libs/darwin/
```

### Linux

```bash
# Clone the mpt-crypto repository
git clone https://github.com/your-org/mpt-crypto.git
cd mpt-crypto

# Build the library
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make

# Copy the libraries
cp libmpt-crypto.a /path/to/xrpl-py/xrpl/core/confidential/libs/linux/
cp secp256k1_build/lib/libsecp256k1.a /path/to/xrpl-py/xrpl/core/confidential/libs/linux/
```

### Windows

```bash
# Clone the mpt-crypto repository
git clone https://github.com/your-org/mpt-crypto.git
cd mpt-crypto

# Build the library
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

# Copy the libraries
copy Release\mpt-crypto.lib \path\to\xrpl-py\xrpl\core\confidential\libs\win32\
copy secp256k1_build\lib\secp256k1.lib \path\to\xrpl-py\xrpl\core\confidential\libs\win32\
```

## Notes

- The libraries are statically linked to avoid runtime dependency issues
- OpenSSL's libcrypto is dynamically linked (system library)
- The libraries are platform-specific and cannot be used across different platforms
- For distribution, you may want to create platform-specific wheels using `cibuildwheel`

