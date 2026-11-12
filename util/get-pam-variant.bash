#!/usr/bin/env bash

# FIXME read headers to find the actually used variant
case $(uname) in
Linux)
    echo linuxpam
    ;;
FreeBSD)
    echo openpam
    ;;
*)
    echo "Unsupported platform" >&2
    exit 1
    ;;
esac
