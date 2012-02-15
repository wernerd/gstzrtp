
set(gcrypt_src
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/gcryptZrtpDH.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/gcrypthmac256.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/gcryptsha256.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/gcrypthmac384.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/gcryptsha384.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/gcryptAesCFB.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/gcrypt/InitializeGcrypt.cpp)

set(openssl_src
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/ZrtpDH.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/hmac256.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/sha256.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/hmac384.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/sha384.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/AesCFB.cpp
    ${zrtpSrcs}/libzrtpcpp/crypto/openssl/InitializeOpenSSL.cpp)

set(skein_srcs
    ${srtpSrcs}/crypto/macSkein.cpp
    ${srtpSrcs}/crypto/skein.c
    ${srtpSrcs}/crypto/skein_block.c
    ${srtpSrcs}/crypto/skeinApi.c)

set(openssl_src_srtp
    ${srtpSrcs}/crypto/openssl/hmac.cpp
    ${srtpSrcs}/crypto/openssl/AesSrtp.cpp)

set(gcrypt_src_srtp
    ${srtpSrcs}/crypto/gcrypt/gcrypthmac.cpp
    ${srtpSrcs}/crypto/gcrypt/gcryptAesSrtp.cpp
    ${srtpSrcs}/crypto/gcrypt/InitializeGcrypt.cpp)


if (GCRYPT_FOUND)
    set(crypto_src ${gcrypt_src} ${gcrypt_src_srtp})
endif()

if (OPENSSL_FOUND)
    set(crypto_src ${openssl_src} ${openssl_src_srtp})
endif()

set(twofish_srcs 
    ${zrtpSrcs}/libzrtpcpp/crypto/twofish.c
    ${zrtpSrcs}/libzrtpcpp/crypto/twofish_cfb.c
    ${zrtpSrcs}/libzrtpcpp/crypto/TwoCFB.cpp)

set(zrtp_src
    ${zrtpSrcs}/ZrtpCallbackWrapper.cpp
    ${zrtpSrcs}/ZIDFile.cpp
    ${zrtpSrcs}/ZIDRecord.cpp
    ${zrtpSrcs}/ZRtp.cpp
    ${zrtpSrcs}/ZrtpCrc32.cpp
    ${zrtpSrcs}/ZrtpPacketCommit.cpp
    ${zrtpSrcs}/ZrtpPacketConf2Ack.cpp
    ${zrtpSrcs}/ZrtpPacketConfirm.cpp
    ${zrtpSrcs}/ZrtpPacketDHPart.cpp
    ${zrtpSrcs}/ZrtpPacketGoClear.cpp
    ${zrtpSrcs}/ZrtpPacketClearAck.cpp
    ${zrtpSrcs}/ZrtpPacketHelloAck.cpp
    ${zrtpSrcs}/ZrtpPacketHello.cpp
    ${zrtpSrcs}/ZrtpPacketError.cpp
    ${zrtpSrcs}/ZrtpPacketErrorAck.cpp
    ${zrtpSrcs}/ZrtpPacketPingAck.cpp
    ${zrtpSrcs}/ZrtpPacketPing.cpp
    ${zrtpSrcs}/ZrtpPacketSASrelay.cpp
    ${zrtpSrcs}/ZrtpPacketRelayAck.cpp
    ${zrtpSrcs}/ZrtpStateClass.cpp
    ${zrtpSrcs}/ZrtpTextData.cpp
    ${zrtpSrcs}/ZrtpConfigure.cpp
    ${zrtpSrcs}/ZrtpCWrapper.cpp
    ${zrtpSrcs}/Base32.cpp)

set(srtp_src
    ${srtpSrcs}/CryptoContext.cpp
    ${srtpSrcs}/CryptoContextCtrl.cpp
)


set(filter_src
    gstzrtpfilter.c gstSrtpCWrapper.cpp)

set(gstzrtp_src ${zrtp_src} ${ccrtp_src} ${crypto_src} ${twofish_srcs} ${skein_srcs} ${srtp_src} ${filter_src})

set(LIBRARY_BUILD_TYPE SHARED)

add_library(gstzrtp ${LIBRARY_BUILD_TYPE} ${gstzrtp_src})
set_target_properties(gstzrtp PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(gstzrtp ${LIBS})

install(TARGETS gstzrtp DESTINATION ${LIBDIRNAME})

if (BUILD_TESTER)
    set(tester_src gstzrtptester.c)
    add_library(gstzrtptester ${LIBRARY_BUILD_TYPE} ${tester_src})
    set_target_properties(gstzrtptester PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
    target_link_libraries(gstzrtptester ${LIBS})
endif()

