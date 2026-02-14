#!/usr/bin/env python3
"""
Build script for xrpl-py package.

This script is called by Poetry during the build process to compile
the optional C extension for confidential MPT support.
"""

import os
import subprocess
import sys
from pathlib import Path


def build_confidential_extension():
    """Build the confidential MPT C extension if possible."""
    print("=" * 80)
    print("Building xrpl-py package")
    print("=" * 80)
    
    # Check if we should build the C extension
    skip_build = os.environ.get("XRPL_SKIP_CONFIDENTIAL_BUILD", "").lower() in ("1", "true", "yes")
    
    if skip_build:
        print("Skipping confidential MPT C extension build (XRPL_SKIP_CONFIDENTIAL_BUILD set)")
        return
    
    # Path to the build script
    build_script = Path(__file__).parent / "xrpl" / "core" / "confidential" / "build_mpt_crypto.py"
    
    if not build_script.exists():
        print(f"Warning: Build script not found: {build_script}")
        print("Skipping confidential MPT C extension build")
        return
    
    print("\nBuilding confidential MPT C extension...")
    print(f"Build script: {build_script}")
    
    try:
        # Run the build script
        result = subprocess.run(
            [sys.executable, str(build_script)],
            cwd=build_script.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        
        if result.returncode == 0:
            print("✓ Confidential MPT C extension built successfully")
        else:
            print("Warning: Failed to build confidential MPT C extension")
            print("This is optional - the package will still work without it")
            print("\nBuild output:")
            print(result.stdout)
            if result.stderr:
                print("\nBuild errors:")
                print(result.stderr)
            print("\nTo use confidential MPT features, run after installation:")
            print("  python -m xrpl.core.confidential.setup")
    
    except Exception as e:
        print(f"Warning: Exception while building C extension: {e}")
        print("This is optional - the package will still work without it")
    
    print("=" * 80)


if __name__ == "__main__":
    build_confidential_extension()

