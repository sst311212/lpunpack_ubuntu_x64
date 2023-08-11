#!/bin/bash

LIBS="lib/liblp.a lib/libsparse.a lib/libbase.a lib/liblog.a lib/libext4_utils.a lib/libcrypto_utils.a lib/libcrypto.a lib/libz.a"

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -o lpadd \
partition_tools/lpadd.cc $LIBS

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -o lpflash \
partition_tools/lpflash.cc $LIBS

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -o lpmake \
partition_tools/lpmake.cc $LIBS

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -o lpunpack \
partition_tools/lpunpack.cc $LIBS

clang++ -std=c++17 -static \
-Ilib/include -Ilib/protobuf/src -D_FILE_OFFSET_BITS=64 -o lpdump \
partition_tools/lpdump.cc partition_tools/dynamic_partitions_device_info.pb.cc partition_tools/lpdump_host.cc \
$LIBS lib/libjsonpbparse.a lib/libprotobuf-cpp-full.a

strip -s lp*
chmod +x lp*