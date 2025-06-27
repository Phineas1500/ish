#!/bin/bash
source ish-env/bin/activate

echo "Testing SQLite database directly..."
sqlite3 e2e_out/testfs/meta.db "pragma user_version;"
echo "Database file permissions:"
ls -la e2e_out/testfs/meta.db*

echo "Testing with strace equivalent..."
# Run with more verbose error output 
ASAN_OPTIONS=abort_on_error=1 build-64bit/ish -f e2e_out/testfs /bin/true 2>&1