#!/bin/sh
echo "=== Testing directory access ==="
echo "1. Working - shell glob:"
echo /*
echo "2. Working - explicit file access:"
cat /etc/alpine-release
echo "3. Not working - ls command:"
ls /
echo "4. Testing ls with specific file:"
ls /etc/alpine-release
echo "5. Testing ls with error (should work):"
ls /nonexistent
echo "=== End test ==="