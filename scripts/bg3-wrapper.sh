#!/bin/bash
# BG3SE Wrapper - Steam calls this, we inject and launch
export DYLD_INSERT_LIBRARIES="/Users/tomdimino/Desktop/Programming/bg3se-macos/build/lib/libbg3se.dylib"
exec "$@"
