#!/bin/bash
source ish-env/bin/activate

echo "Running 64-bit iSH under LLDB to catch crash..."
lldb build-64bit/ish -o "run -f e2e_out/testfs /bin/true" -o "bt" -o "thread list" -o "register read" -o "quit" 2>&1