#!/bin/bash
source ish-env/bin/activate

echo "=== Debugging stdout issue ==="

echo "1. Testing if the program runs and writes to stdout:"
echo "Running: echo hello | build-64bit/ish -f e2e_out/testfs_proper /bin/cat"
echo "hello" | build-64bit/ish -f e2e_out/testfs_proper /bin/cat

echo ""
echo "2. Testing exit code:"
build-64bit/ish -f e2e_out/testfs_proper /bin/echo "test"
echo "Exit code: $?"

echo ""
echo "3. Testing with explicit stdout redirection:"
build-64bit/ish -f e2e_out/testfs_proper /bin/echo "test" 1>&1

echo ""
echo "4. Testing comparison with 32-bit:"
echo "32-bit output:"
build/ish -f e2e_out/testfs_proper /bin/echo "32bit test" | cat -A
echo ""
echo "64-bit output:"
build-64bit/ish -f e2e_out/testfs_proper /bin/echo "64bit test" | cat -A

echo ""
echo "5. Testing with a simple command that should generate output:"
echo "Running /bin/ls /:"
build-64bit/ish -f e2e_out/testfs_proper /bin/ls /