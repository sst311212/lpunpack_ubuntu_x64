#!/bin/bash

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -lpthread \
partition_tools/lpadd.cc \
lib/liblp.a lib/libsparse.a lib/libbase.a lib/liblog.a lib/fmtlib.a lib/libext4_utils.a lib/libcrypto_utils.a lib/libcrypto.a lib/libz.a \
-o lpadd

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -lpthread \
partition_tools/lpflash.cc \
lib/liblp.a lib/libsparse.a lib/libbase.a lib/liblog.a lib/fmtlib.a lib/libext4_utils.a lib/libcrypto_utils.a lib/libcrypto.a lib/libz.a \
-o lpflash

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -lpthread \
partition_tools/lpmake.cc \
lib/liblp.a lib/libsparse.a lib/libbase.a lib/liblog.a lib/fmtlib.a lib/libext4_utils.a lib/libcrypto_utils.a lib/libcrypto.a lib/libz.a \
-o lpmake

clang++ -std=c++17 -static \
-Ilib/include -D_FILE_OFFSET_BITS=64 -lpthread \
partition_tools/lpunpack.cc \
lib/liblp.a lib/libsparse.a lib/libbase.a lib/liblog.a lib/fmtlib.a lib/libext4_utils.a lib/libcrypto_utils.a lib/libcrypto.a lib/libz.a \
-o lpunpack

clang++ -std=c++17 -static \
-Ilib/include -Ilib/protobuf/src -D_FILE_OFFSET_BITS=64 -lpthread \
partition_tools/lpdump.cc partition_tools/dynamic_partitions_device_info.pb.cc partition_tools/lpdump_host.cc \
lib/liblp.a lib/libsparse.a lib/libbase.a lib/liblog.a lib/fmtlib.a lib/libext4_utils.a lib/libcrypto_utils.a lib/libcrypto.a lib/libz.a lib/libjsonpbparse.a lib/libprotobuf-cpp-full.a \
-o lpdump

strip -s lpadd
strip -s lpflash
strip -s lpmake
strip -s lpunpack
strip -s lpdump