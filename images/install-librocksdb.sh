#!/bin/bash
set -eou pipefail

# Build librocksdb from source and install it plus pkg-config metadata.
#
# convex CI links against the version of rocksdb that its pinned
# librocksdb-sys expects (0.16.0+8.10.0 -> rocksdb 8.10.0). Shipping a matching
# prebuilt lib lets CI reuse it instead of recompiling rocksdb from source on
# every job. Keep this in the [8,9) range and in sync with librocksdb-sys.
ROCKSDB_VERSION=v8.10.0

cd /tmp
git clone --depth 1 --branch "$ROCKSDB_VERSION" https://github.com/facebook/rocksdb.git
cd rocksdb
make -j"$(nproc)" shared_lib
# /lib is a symlink to /usr/lib on Ubuntu; the bare .so is what -lrocksdb links.
cp -d librocksdb.so* /lib/

# Ship pkg-config metadata so `pkg-config rocksdb` resolves the built version.
# Without it convex's mise config sets ROCKSDB_COMPILE=1 and rebuilds rocksdb
# from source on every job. Derive the version from the checked-out source so
# the .pc can't drift from the lib that was actually built.
rocksdb_version="$(
  awk '/define ROCKSDB_MAJOR/ {major=$3}
       /define ROCKSDB_MINOR/ {minor=$3}
       /define ROCKSDB_PATCH/ {patch=$3}
       END {print major "." minor "." patch}' include/rocksdb/version.h
)"
# /usr/lib/pkgconfig is on pkg-config's default search path on both amd64 and
# arm64 Ubuntu, so one location serves both images without an arch-specific
# multiarch dir.
install -d /usr/lib/pkgconfig
cat > /usr/lib/pkgconfig/rocksdb.pc <<PC
libdir=/usr/lib
includedir=/usr/include

Name: rocksdb
Description: RocksDB embedded key-value store
Version: ${rocksdb_version}
Libs: -L\${libdir} -lrocksdb
Cflags: -I\${includedir}
PC
