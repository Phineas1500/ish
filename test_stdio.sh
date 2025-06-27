#!/bin/bash
source ish-env/bin/activate

echo "=== Testing stdio and execution ==="

echo "1. Testing 64-bit /bin/true:"
echo -n "Exit code: "
build-64bit/ish -f e2e_out/testfs /bin/true 2>/dev/null
echo $?

echo -n "With stderr: "
build-64bit/ish -f e2e_out/testfs /bin/true
echo " (exit: $?)"

echo "2. Testing if /bin/true exists in filesystem:"
ls -la e2e_out/testfs/data/bin/true 2>/dev/null || echo "File not found"

echo "3. Testing filesystem contents:"
find e2e_out/testfs/data -name "*true*" 2>/dev/null | head -5

echo "4. Checking what binaries are available:"
find e2e_out/testfs/data -type f -executable 2>/dev/null | head -10 || echo "No executables found"

echo "5. Testing with strace logging:"
build-64bit/ish -f e2e_out/testfs /bin/echo test 2>&1 | head -5