#!/bin/sh

cd /workspace/source/libtorrent/build/examples
cmake \
    -G "Unix Makefiles" \
    $@ \
    /workspace/source/libtorrent/examples
