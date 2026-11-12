#!/usr/bin/env bash

# FIXME read headers to find the actually used variant
case $(uname) in
Linux)
    echo linuxpam
    ;;
FreeBSD|NetBSD)
    echo openpam
    ;;
Darwin)
    echo "Apple uses the checked shared OpenPAM subset; run make pam-abi-check" >&2
    echo "Do not regenerate the shared file from Apple headers" >&2
    exit 1
    ;;
*)
    echo "Unsupported platform"
    exit 1
    ;;
esac
