#!/bin/sh

cd /extra/source/libtorrent/examples
cmake \
    -D libtorrent_includes_asio_source= \
    -G "Unix Makefiles" \
    $@ \
    /extra/source/libtorrent/examples
