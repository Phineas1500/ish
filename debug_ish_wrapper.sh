#!/bin/bash
echo "ISH WRAPPER: Called with args: $@" >&2
echo "ISH WRAPPER: PWD: $(pwd)" >&2
echo "ISH WRAPPER: Starting actual iSH..." >&2
exec ./build-64bit/ish "$@"