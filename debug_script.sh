#\!/bin/bash
lldb build-64bit/ish -o "run -f e2e_out/testfs /bin/true" -o "bt" -o "quit"
