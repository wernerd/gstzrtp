set (sdes_src ${zrtpSrcs}/zrtp/ZrtpSdesStream.cpp)

set(zrtp_src_no_cache
    ${zrtpSrcs}/zrtp/ZrtpCallbackWrapper.cpp
    ${zrtpSrcs}/zrtp/ZRtp.cpp
    ${zrtpSrcs}/zrtp/ZrtpCrc32.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketCommit.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketConf2Ack.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketConfirm.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketDHPart.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketGoClear.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketClearAck.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketHelloAck.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketHello.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketError.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketErrorAck.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketPingAck.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketPing.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketSASrelay.cpp
    ${zrtpSrcs}/zrtp/ZrtpPacketRelayAck.cpp
    ${zrtpSrcs}/zrtp/ZrtpStateClass.cpp
    ${zrtpSrcs}/zrtp/ZrtpTextData.cpp
    ${zrtpSrcs}/zrtp/ZrtpConfigure.cpp
    ${zrtpSrcs}/zrtp/ZrtpCWrapper.cpp
    ${zrtpSrcs}/zrtp/Base32.cpp)
#    ${zrtpSrcs}/common/osSpecifics.c)


if (OPENSSL_FOUND)
    set(crypto_src
        ${zrtpSrcs}/zrtp/crypto/openssl/zrtpDH.cpp
        ${zrtpSrcs}/zrtp/crypto/openssl/hmac256.cpp
        ${zrtpSrcs}/zrtp/crypto/openssl/sha256.cpp
        ${zrtpSrcs}/zrtp/crypto/openssl/hmac384.cpp
        ${zrtpSrcs}/zrtp/crypto/openssl/sha384.cpp
        ${zrtpSrcs}/zrtp/crypto/openssl/aesCFB.cpp
        ${zrtpSrcs}/zrtp/crypto/openssl/InitializeOpenSSL.cpp
        ${zrtpSrcs}/zrtp/crypto/twoCFB.cpp)

     set(crypto_src_srtp
        ${zrtpSrcs}/srtp/crypto/openssl/hmac.cpp
        ${zrtpSrcs}/srtp/crypto/openssl/SrtpSymCrypto.cpp)

endif()

# in standalone mode we need bignumber lib and crypto primitives
if (CRYPTO_STANDALONE)
    set(crypto_src
        ${zrtpSrcs}/cryptcommon/ZrtpRandom.cpp
        ${zrtpSrcs}/common/Thread.cpp
        ${zrtpSrcs}/common/MutexClass.cpp
        ${zrtpSrcs}/common/EventClass.cpp
        ${zrtpSrcs}/srtp/crypto/sha1.c
        ${zrtpSrcs}/bnlib/bn00.c
        ${zrtpSrcs}/bnlib/lbn00.c
        ${zrtpSrcs}/bnlib/bn.c
        ${zrtpSrcs}/bnlib/lbnmem.c
        ${zrtpSrcs}/bnlib/sieve.c
        ${zrtpSrcs}/bnlib/prime.c
        ${zrtpSrcs}/bnlib/bnprint.c
        ${zrtpSrcs}/bnlib/jacobi.c
        ${zrtpSrcs}/bnlib/germain.c
        ${zrtpSrcs}/bnlib/ec/ec.c
        ${zrtpSrcs}/bnlib/ec/ecdh.c
        ${zrtpSrcs}/bnlib/bnprint.c
        ${zrtpSrcs}/zrtp/crypto/zrtpDH.cpp
        ${zrtpSrcs}/zrtp/crypto/hmac256.cpp
        ${zrtpSrcs}/zrtp/crypto/sha256.cpp
        ${zrtpSrcs}/zrtp/crypto/hmac384.cpp
        ${zrtpSrcs}/zrtp/crypto/sha384.cpp
        ${zrtpSrcs}/zrtp/crypto/aesCFB.cpp
        ${zrtpSrcs}/zrtp/crypto/twoCFB.cpp
        ${zrtpSrcs}/zrtp/crypto/sha2.c)

    set(crypto_src_srtp
        ${zrtpSrcs}/srtp/crypto/hmac.cpp
        ${zrtpSrcs}/srtp/crypto/SrtpSymCrypto.cpp
        ${zrtpSrcs}/srtp/crypto/sha1.c)

endif()

set(cryptcommon_srcs
    ${zrtpSrcs}/cryptcommon/twofish.c
    ${zrtpSrcs}/cryptcommon/twofish_cfb.c
    ${zrtpSrcs}/cryptcommon/aescrypt.c
    ${zrtpSrcs}/cryptcommon/aeskey.c
    ${zrtpSrcs}/cryptcommon/aestab.c
    ${zrtpSrcs}/cryptcommon/aes_modes.c
    ${zrtpSrcs}/cryptcommon/macSkein.cpp
    ${zrtpSrcs}/cryptcommon/skein.c
    ${zrtpSrcs}/cryptcommon/skein_block.c
    ${zrtpSrcs}/cryptcommon/skeinApi.c)

if (NOT enable_sqlite)
    set(zrtp_src ${zrtp_src_no_cache}
        ${zrtpSrcs}/zrtp/ZIDCacheFile.cpp
        ${zrtpSrcs}/zrtp/ZIDRecordFile.cpp)
else()
    set(zrtp_src ${zrtp_src_no_cache}
        ${zrtpSrcs}/zrtp/ZIDCacheDb.cpp
        ${zrtpSrcs}/zrtp/ZIDRecordDb.cpp
        ${zrtpSrcs}/zrtp/zrtpB64Encode.c
        ${zrtpSrcs}/zrtp/zrtpB64Decode.c
        ${zrtpSrcs}/zrtp/zrtpCacheSqliteBackend.c)

endif()


set(srtp_src
    ${zrtpSrcs}/srtp/CryptoContext.cpp
    ${zrtpSrcs}/srtp/CryptoContextCtrl.cpp
    ${crypto_src_srtp})

set(filter_src
    gstzrtpfilter.c gstSrtpCWrapper.cpp)

set(gstzrtp_src ${zrtp_src} ${crypto_src} ${cryptcommon_srcs} ${srtp_src} ${filter_src})

set(LIBRARY_BUILD_TYPE SHARED)

add_library(gstzrtp ${LIBRARY_BUILD_TYPE} ${gstzrtp_src})
set_target_properties(gstzrtp PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(gstzrtp ${LIBS})
# add_custom_command(TARGET gstzrtp POST_BUILD
#                   COMMAND "${PROJECT_SOURCE_DIR}/doc/generateDoc.sh"
#                   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/doc)

install(TARGETS gstzrtp DESTINATION ${LIBDIRNAME})

if (BUILD_TESTER)
    set(tester_src gstzrtptester.c)
    add_library(gstzrtptester ${LIBRARY_BUILD_TYPE} ${tester_src})
    set_target_properties(gstzrtptester PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
    target_link_libraries(gstzrtptester ${LIBS})
endif()

