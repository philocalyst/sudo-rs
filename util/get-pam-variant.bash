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
    # macOS uses sys_openpam.rs too; its own headers lack PAM_BAD_ITEM and add
    # Apple extensions, so they must not be used to regenerate that shared file
    echo "Do not regenerate the OpenPAM bindings from macOS headers" >&2
    exit 1
    ;;
*)
    echo "Unsupported platform" >&2
    exit 1
    ;;
esac
