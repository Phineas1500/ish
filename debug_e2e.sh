#!/bin/bash
cd /Users/sriram/Documents/ish
source ish-env/bin/activate

ISH="./build-64bit/ish -f ./e2e_out/testfs_proper"

echo "=== Testing individual commands ==="
echo "1. Testing rm command..."
eval "$ISH /bin/rm -rf /tmp/e2e/hello"
echo "Exit code: $?"

echo "2. Testing mkdir command..."
eval "$ISH /bin/mkdir -p /tmp/e2e/hello"  
echo "Exit code: $?"

echo "3. Testing tar pipe command..."
tar -cf - -C tests/e2e hello | eval "$ISH /bin/tar xf - -C /tmp/e2e"
echo "Exit code: $?"

echo "=== All commands completed ==="