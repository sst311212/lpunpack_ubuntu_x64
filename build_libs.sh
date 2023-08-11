#!/bin/bash

pushd lib/liblog
clang -std=c++17 -static \
-I../include \
-DLIBLOG_LOG_TAG=1006 -DSNET_EVENT_LOG_TAG=1397638484 -DANDROID_DEBUGGABLE=0 \
-c log_event_list.cpp log_event_write.cpp logger_name.cpp logger_read.cpp logger_write.cpp logprint.cpp properties.cpp event_tag_map.cpp
ar rcs ../liblog.a *.o
rm -r *.o
popd

pushd lib/zlib
clang -static \
-I. \
-DHAVE_HIDDEN -DZLIB_CONST -O3 \
-c adler32.c adler32_simd.c compress.c cpu_features.c crc32.c crc32_simd.c crc_folding.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c
ar rcs ../libz.a *.o
rm -r *.o
popd

pushd lib/libbase
clang -std=gnu++17 -static \
-I../include \
-c abi_compatibility.cpp chrono_utils.cpp cmsg.cpp file.cpp hex.cpp logging.cpp mapped_file.cpp parsebool.cpp parsenetaddress.cpp posix_strerror_r.cpp process.cpp properties.cpp stringprintf.cpp strings.cpp threads.cpp test_utils.cpp errors_unix.cpp
ar rcs ../libbase.a *.o
rm -r *.o
popd

pushd lib/libsparse
clang -std=c++17 -static \
-I../include \
-c backed_block.cpp output_file.cpp sparse.cpp sparse_crc32.cpp sparse_err.cpp sparse_read.cpp
ar rcs ../libsparse.a *.o
rm -r *.o
popd

pushd lib/fmtlib
clang -std=c++17 -static \
-I../include \
-c src/format.cc
ar rcs ../fmtlib.a *.o
rm -r *.o
popd

pushd lib/liblp
clang -std=c++17 -static \
-I../include \
-D_FILE_OFFSET_BITS=64 \
-c builder.cpp super_layout_builder.cpp images.cpp partition_opener.cpp property_fetcher.cpp reader.cpp utility.cpp writer.cpp
ar rcs ../liblp.a *.o
rm -r *.o
popd

pushd lib/ext4_utils
clang -std=c++17 -static \
-I../include \
-fno-strict-aliasing -D_FILE_OFFSET_BITS=64 \
-c ext4_utils.cpp wipe.cpp ext4_sb.cpp
ar rcs ../libext4_utils.a *.o
rm -r *.o
popd

pushd lib/libcrypto_utils
clang -std=c++17 -static \
-I../include \
-c android_pubkey.cpp
ar rcs ../libcrypto_utils.a *.o
rm -r *.o
popd

pushd lib/boringssl
clang -static \
-I../include \
-DBORINGSSL_IMPLEMENTATION -fvisibility=hidden -DBORINGSSL_SHARED_LIBRARY -DBORINGSSL_ANDROID_SYSTEM -DOPENSSL_SMALL -D_XOPEN_SOURCE=700 \
-c \
err_data.c \
src/crypto/asn1/a_bitstr.c \
src/crypto/asn1/a_bool.c \
src/crypto/asn1/a_d2i_fp.c \
src/crypto/asn1/a_dup.c \
src/crypto/asn1/a_gentm.c \
src/crypto/asn1/a_i2d_fp.c \
src/crypto/asn1/a_int.c \
src/crypto/asn1/a_mbstr.c \
src/crypto/asn1/a_object.c \
src/crypto/asn1/a_octet.c \
src/crypto/asn1/a_strex.c \
src/crypto/asn1/a_strnid.c \
src/crypto/asn1/a_time.c \
src/crypto/asn1/a_type.c \
src/crypto/asn1/a_utctm.c \
src/crypto/asn1/asn1_lib.c \
src/crypto/asn1/asn1_par.c \
src/crypto/asn1/asn_pack.c \
src/crypto/asn1/f_int.c \
src/crypto/asn1/f_string.c \
src/crypto/asn1/posix_time.c \
src/crypto/asn1/tasn_dec.c \
src/crypto/asn1/tasn_enc.c \
src/crypto/asn1/tasn_fre.c \
src/crypto/asn1/tasn_new.c \
src/crypto/asn1/tasn_typ.c \
src/crypto/asn1/tasn_utl.c \
src/crypto/base64/base64.c \
src/crypto/bio/bio.c \
src/crypto/bio/bio_mem.c \
src/crypto/bio/connect.c \
src/crypto/bio/errno.c \
src/crypto/bio/fd.c \
src/crypto/bio/file.c \
src/crypto/bio/hexdump.c \
src/crypto/bio/pair.c \
src/crypto/bio/printf.c \
src/crypto/bio/socket.c \
src/crypto/bio/socket_helper.c \
src/crypto/blake2/blake2.c \
src/crypto/bn_extra/bn_asn1.c \
src/crypto/bn_extra/convert.c \
src/crypto/buf/buf.c \
src/crypto/bytestring/asn1_compat.c \
src/crypto/bytestring/ber.c \
src/crypto/bytestring/cbb.c \
src/crypto/bytestring/cbs.c \
src/crypto/bytestring/unicode.c \
src/crypto/chacha/chacha.c \
src/crypto/cipher_extra/cipher_extra.c \
src/crypto/cipher_extra/derive_key.c \
src/crypto/cipher_extra/e_aesctrhmac.c \
src/crypto/cipher_extra/e_aesgcmsiv.c \
src/crypto/cipher_extra/e_chacha20poly1305.c \
src/crypto/cipher_extra/e_des.c \
src/crypto/cipher_extra/e_null.c \
src/crypto/cipher_extra/e_rc2.c \
src/crypto/cipher_extra/e_rc4.c \
src/crypto/cipher_extra/e_tls.c \
src/crypto/cipher_extra/tls_cbc.c \
src/crypto/conf/conf.c \
src/crypto/cpu_aarch64_apple.c \
src/crypto/cpu_aarch64_fuchsia.c \
src/crypto/cpu_aarch64_linux.c \
src/crypto/cpu_aarch64_openbsd.c \
src/crypto/cpu_aarch64_sysreg.c \
src/crypto/cpu_aarch64_win.c \
src/crypto/cpu_arm.c \
src/crypto/cpu_arm_freebsd.c \
src/crypto/cpu_arm_linux.c \
src/crypto/cpu_intel.c \
src/crypto/crypto.c \
src/crypto/curve25519/curve25519.c \
src/crypto/curve25519/curve25519_64_adx.c \
src/crypto/curve25519/spake25519.c \
src/crypto/des/des.c \
src/crypto/dh_extra/dh_asn1.c \
src/crypto/dh_extra/params.c \
src/crypto/digest_extra/digest_extra.c \
src/crypto/dsa/dsa.c \
src/crypto/dsa/dsa_asn1.c \
src/crypto/ec_extra/ec_asn1.c \
src/crypto/ec_extra/ec_derive.c \
src/crypto/ec_extra/hash_to_curve.c \
src/crypto/ecdh_extra/ecdh_extra.c \
src/crypto/ecdsa_extra/ecdsa_asn1.c \
src/crypto/engine/engine.c \
src/crypto/err/err.c \
src/crypto/evp/evp.c \
src/crypto/evp/evp_asn1.c \
src/crypto/evp/evp_ctx.c \
src/crypto/evp/p_dsa_asn1.c \
src/crypto/evp/p_ec.c \
src/crypto/evp/p_ec_asn1.c \
src/crypto/evp/p_ed25519.c \
src/crypto/evp/p_ed25519_asn1.c \
src/crypto/evp/p_hkdf.c \
src/crypto/evp/p_rsa.c \
src/crypto/evp/p_rsa_asn1.c \
src/crypto/evp/p_x25519.c \
src/crypto/evp/p_x25519_asn1.c \
src/crypto/evp/pbkdf.c \
src/crypto/evp/print.c \
src/crypto/evp/scrypt.c \
src/crypto/evp/sign.c \
src/crypto/ex_data.c \
src/crypto/fipsmodule/bcm.c \
src/crypto/fipsmodule/fips_shared_support.c \
src/crypto/hpke/hpke.c \
src/crypto/hrss/hrss.c \
src/crypto/kyber/keccak.c \
src/crypto/kyber/kyber.c \
src/crypto/lhash/lhash.c \
src/crypto/mem.c \
src/crypto/obj/obj.c \
src/crypto/obj/obj_xref.c \
src/crypto/pem/pem_all.c \
src/crypto/pem/pem_info.c \
src/crypto/pem/pem_lib.c \
src/crypto/pem/pem_oth.c \
src/crypto/pem/pem_pk8.c \
src/crypto/pem/pem_pkey.c \
src/crypto/pem/pem_x509.c \
src/crypto/pem/pem_xaux.c \
src/crypto/pkcs7/pkcs7.c \
src/crypto/pkcs7/pkcs7_x509.c \
src/crypto/pkcs8/p5_pbev2.c \
src/crypto/pkcs8/pkcs8.c \
src/crypto/pkcs8/pkcs8_x509.c \
src/crypto/poly1305/poly1305.c \
src/crypto/poly1305/poly1305_arm.c \
src/crypto/poly1305/poly1305_vec.c \
src/crypto/pool/pool.c \
src/crypto/rand_extra/deterministic.c \
src/crypto/rand_extra/forkunsafe.c \
src/crypto/rand_extra/getentropy.c \
src/crypto/rand_extra/ios.c \
src/crypto/rand_extra/passive.c \
src/crypto/rand_extra/rand_extra.c \
src/crypto/rand_extra/trusty.c \
src/crypto/rand_extra/windows.c \
src/crypto/rc4/rc4.c \
src/crypto/refcount.c \
src/crypto/rsa_extra/rsa_asn1.c \
src/crypto/rsa_extra/rsa_crypt.c \
src/crypto/rsa_extra/rsa_print.c \
src/crypto/siphash/siphash.c \
src/crypto/stack/stack.c \
src/crypto/thread.c \
src/crypto/thread_none.c \
src/crypto/thread_pthread.c \
src/crypto/thread_win.c \
src/crypto/trust_token/pmbtoken.c \
src/crypto/trust_token/trust_token.c \
src/crypto/trust_token/voprf.c \
src/crypto/x509/a_digest.c \
src/crypto/x509/a_sign.c \
src/crypto/x509/a_verify.c \
src/crypto/x509/algorithm.c \
src/crypto/x509/asn1_gen.c \
src/crypto/x509/by_dir.c \
src/crypto/x509/by_file.c \
src/crypto/x509/i2d_pr.c \
src/crypto/x509/name_print.c \
src/crypto/x509/policy.c \
src/crypto/x509/rsa_pss.c \
src/crypto/x509/t_crl.c \
src/crypto/x509/t_req.c \
src/crypto/x509/t_x509.c \
src/crypto/x509/t_x509a.c \
src/crypto/x509/x509.c \
src/crypto/x509/x509_att.c \
src/crypto/x509/x509_cmp.c \
src/crypto/x509/x509_d2.c \
src/crypto/x509/x509_def.c \
src/crypto/x509/x509_ext.c \
src/crypto/x509/x509_lu.c \
src/crypto/x509/x509_obj.c \
src/crypto/x509/x509_req.c \
src/crypto/x509/x509_set.c \
src/crypto/x509/x509_trs.c \
src/crypto/x509/x509_txt.c \
src/crypto/x509/x509_v3.c \
src/crypto/x509/x509_vfy.c \
src/crypto/x509/x509_vpm.c \
src/crypto/x509/x509cset.c \
src/crypto/x509/x509name.c \
src/crypto/x509/x509rset.c \
src/crypto/x509/x509spki.c \
src/crypto/x509/x_algor.c \
src/crypto/x509/x_all.c \
src/crypto/x509/x_attrib.c \
src/crypto/x509/x_crl.c \
src/crypto/x509/x_exten.c \
src/crypto/x509/x_info.c \
src/crypto/x509/x_name.c \
src/crypto/x509/x_pkey.c \
src/crypto/x509/x_pubkey.c \
src/crypto/x509/x_req.c \
src/crypto/x509/x_sig.c \
src/crypto/x509/x_spki.c \
src/crypto/x509/x_val.c \
src/crypto/x509/x_x509.c \
src/crypto/x509/x_x509a.c \
src/crypto/x509v3/v3_akey.c \
src/crypto/x509v3/v3_akeya.c \
src/crypto/x509v3/v3_alt.c \
src/crypto/x509v3/v3_bcons.c \
src/crypto/x509v3/v3_bitst.c \
src/crypto/x509v3/v3_conf.c \
src/crypto/x509v3/v3_cpols.c \
src/crypto/x509v3/v3_crld.c \
src/crypto/x509v3/v3_enum.c \
src/crypto/x509v3/v3_extku.c \
src/crypto/x509v3/v3_genn.c \
src/crypto/x509v3/v3_ia5.c \
src/crypto/x509v3/v3_info.c \
src/crypto/x509v3/v3_int.c \
src/crypto/x509v3/v3_lib.c \
src/crypto/x509v3/v3_ncons.c \
src/crypto/x509v3/v3_ocsp.c \
src/crypto/x509v3/v3_pcons.c \
src/crypto/x509v3/v3_pmaps.c \
src/crypto/x509v3/v3_prn.c \
src/crypto/x509v3/v3_purp.c \
src/crypto/x509v3/v3_skey.c \
src/crypto/x509v3/v3_utl.c \
linux-x86_64/crypto/chacha/chacha-x86_64-linux.S \
linux-x86_64/crypto/cipher_extra/aes128gcmsiv-x86_64-linux.S \
linux-x86_64/crypto/cipher_extra/chacha20_poly1305_x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/aesni-gcm-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/aesni-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/ghash-ssse3-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/ghash-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/md5-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/p256-x86_64-asm-linux.S \
linux-x86_64/crypto/fipsmodule/p256_beeu-x86_64-asm-linux.S \
linux-x86_64/crypto/fipsmodule/rdrand-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/rsaz-avx2-linux.S \
linux-x86_64/crypto/fipsmodule/sha1-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/sha256-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/sha512-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/vpaes-x86_64-linux.S \
linux-x86_64/crypto/fipsmodule/x86_64-mont-linux.S \
linux-x86_64/crypto/fipsmodule/x86_64-mont5-linux.S \
linux-x86_64/crypto/test/trampoline-x86_64-linux.S \
src/crypto/curve25519/asm/x25519-asm-arm.S \
src/crypto/hrss/asm/poly_rq_mul.S \
src/crypto/poly1305/poly1305_arm_asm.S \
src/third_party/fiat/asm/fiat_curve25519_adx_mul.S \
src/third_party/fiat/asm/fiat_curve25519_adx_square.S
ar rcs ../libcrypto.a *.o
rm -r *.o
popd

pushd lib/protobuf
clang -std=c++17 -static \
-Isrc -Iandroid \
-DHAVE_ZLIB=1 \
-c \
src/google/protobuf/any_lite.cc \
src/google/protobuf/arena.cc \
src/google/protobuf/arenastring.cc \
src/google/protobuf/arenaz_sampler.cc \
src/google/protobuf/extension_set.cc \
src/google/protobuf/generated_enum_util.cc \
src/google/protobuf/generated_message_tctable_lite.cc \
src/google/protobuf/generated_message_util.cc \
src/google/protobuf/implicit_weak_message.cc \
src/google/protobuf/inlined_string_field.cc \
src/google/protobuf/io/coded_stream.cc \
src/google/protobuf/io/io_win32.cc \
src/google/protobuf/io/strtod.cc \
src/google/protobuf/io/zero_copy_stream.cc \
src/google/protobuf/io/zero_copy_stream_impl.cc \
src/google/protobuf/io/zero_copy_stream_impl_lite.cc \
src/google/protobuf/map.cc \
src/google/protobuf/message_lite.cc \
src/google/protobuf/parse_context.cc \
src/google/protobuf/repeated_field.cc \
src/google/protobuf/repeated_ptr_field.cc \
src/google/protobuf/stubs/bytestream.cc \
src/google/protobuf/stubs/common.cc \
src/google/protobuf/stubs/int128.cc \
src/google/protobuf/stubs/status.cc \
src/google/protobuf/stubs/statusor.cc \
src/google/protobuf/stubs/stringpiece.cc \
src/google/protobuf/stubs/stringprintf.cc \
src/google/protobuf/stubs/structurally_valid.cc \
src/google/protobuf/stubs/strutil.cc \
src/google/protobuf/stubs/time.cc \
src/google/protobuf/wire_format_lite.cc \
src/google/protobuf/any.cc \
src/google/protobuf/any.pb.cc \
src/google/protobuf/api.pb.cc \
src/google/protobuf/compiler/importer.cc \
src/google/protobuf/compiler/parser.cc \
src/google/protobuf/descriptor.cc \
src/google/protobuf/descriptor.pb.cc \
src/google/protobuf/descriptor_database.cc \
src/google/protobuf/duration.pb.cc \
src/google/protobuf/dynamic_message.cc \
src/google/protobuf/empty.pb.cc \
src/google/protobuf/extension_set_heavy.cc \
src/google/protobuf/field_mask.pb.cc \
src/google/protobuf/generated_message_bases.cc \
src/google/protobuf/generated_message_reflection.cc \
src/google/protobuf/generated_message_tctable_full.cc \
src/google/protobuf/io/gzip_stream.cc \
src/google/protobuf/io/printer.cc \
src/google/protobuf/io/tokenizer.cc \
src/google/protobuf/map_field.cc \
src/google/protobuf/message.cc \
src/google/protobuf/reflection_ops.cc \
src/google/protobuf/service.cc \
src/google/protobuf/source_context.pb.cc \
src/google/protobuf/struct.pb.cc \
src/google/protobuf/stubs/substitute.cc \
src/google/protobuf/text_format.cc \
src/google/protobuf/timestamp.pb.cc \
src/google/protobuf/type.pb.cc \
src/google/protobuf/unknown_field_set.cc \
src/google/protobuf/util/delimited_message_util.cc \
src/google/protobuf/util/field_comparator.cc \
src/google/protobuf/util/field_mask_util.cc \
src/google/protobuf/util/internal/datapiece.cc \
src/google/protobuf/util/internal/default_value_objectwriter.cc \
src/google/protobuf/util/internal/error_listener.cc \
src/google/protobuf/util/internal/field_mask_utility.cc \
src/google/protobuf/util/internal/json_escaping.cc \
src/google/protobuf/util/internal/json_objectwriter.cc \
src/google/protobuf/util/internal/json_stream_parser.cc \
src/google/protobuf/util/internal/object_writer.cc \
src/google/protobuf/util/internal/proto_writer.cc \
src/google/protobuf/util/internal/protostream_objectsource.cc \
src/google/protobuf/util/internal/protostream_objectwriter.cc \
src/google/protobuf/util/internal/type_info.cc \
src/google/protobuf/util/internal/utility.cc \
src/google/protobuf/util/json_util.cc \
src/google/protobuf/util/message_differencer.cc \
src/google/protobuf/util/time_util.cc \
src/google/protobuf/util/type_resolver_util.cc \
src/google/protobuf/wire_format.cc \
src/google/protobuf/wrappers.pb.cc
ar rcs ../libprotobuf-cpp-full.a *.o
rm -r *.o
popd

pushd lib/libjsonpb
clang -std=c++17 -static \
-I../include -I../protobuf/src \
-c parse/jsonpb.cpp
ar rcs ../libjsonpbparse.a *.o
rm -r *.o
popd