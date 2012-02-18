# Copyright (C) 2012 Werner Dittman
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
cmake_minimum_required(VERSION 2.6)

PROJECT(libgstzrtp)

SET(CPACK_PACKAGE_VERSION_MAJOR 0)
SET(CPACK_PACKAGE_VERSION_MINOR 10)
SET(CPACK_PACKAGE_VERSION_PATCH 16)

set (VERSION 0.10.0)
set (SOVERSION 0)
set (PACKAGE zrtpfilter)

set (GST_REQUIRED 0.10.16)
set (GSTPB_REQUIRED 0.10.16)

# build the test driver plugin
set(BUILD_TESTER TRUE)

if(MSVC60)
    set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
    MARK_AS_ADVANCED(BUILD_STATIC)
else()
    option(BUILD_STATIC "Set to OFF to build shared libraries" OFF)
endif()

# set to true for debug and trace during CMakeLists development
set(CMAKE_VERBOSE_MAKEFILE FALSE)

MESSAGE( STATUS "Configuring GNU ${PROJECT_NAME} ${VERSION}...")

# include most of the fine stuff we need
include(FindPkgConfig)
include(CheckLibraryExists)
include(CheckIncludeFiles)

# this caused problems in debian where it has to always be lib....
set(LIBDIRNAME "lib")
if (NOT EXISTS /etc/debian_version)
    if ( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" )
        set(LIBDIRNAME "lib64")
    endif()
endif()

# pkg_check_modules(GST
#     gstreamer-0.10>=${GST_REQUIRED}
#     gstreamer-base-0.10>=${GST_REQUIRED}
#     gstreamer-controller-0.10>=${GST_REQUIRED}
# )
# link_directories(${GST_LIBRARY_DIRS})
# add_definitions(${GST_CFLAGS})
# set(LIBS ${LIBS} ${GST_LDFLAGS} ${GST_LIBRARIES})

# gstreamer-rtp config includes all required lib, above check not needed
pkg_check_modules(GST_RTP gstreamer-rtp-0.10>=${GST_REQUIRED})
link_directories(${GST_RTP_LIBRARY_DIRS})
add_definitions(${GST_RTP_CFLAGS})
set(LIBS ${LIBS} ${GST_RTP_LDFLAGS} ${GST_RTP_LIBRARIES})

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()

pkg_check_modules(OPENSSL libcrypto>=0.9.8)
if (OPENSSL_FOUND)
    check_include_files(openssl/bn.h HAVE_OPENSSL_BN_H)
    check_include_files(openssl/aes.h HAVE_OPENSSL_AES_H)
    check_include_files(openssl/sha.h HAVE_OPENSSL_SHA_H)
    check_library_exists(crypto EVP_CipherInit_ex "" HAVE_SSL_CRYPT)
    set(LIBS ${LIBS} -lcrypto)
    set(CRYPTOBACKEND "libcrypto >= 0.9.8")
    set(BUILD_REQ "libopenssl-devel >= 0.9.8")
    set(PACKAGE_REQ "libopenssl >= 0.9.8")
else()
    message(FATAL_ERROR "No crypto library found")
endif()

check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(string.h HAVE_STRING_H)

# necessary and required modules checked, ready to generate config.h
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(zrtpSrcs ${PROJECT_SOURCE_DIR}/zrtp/src)
set(srtpSrcs ${PROJECT_SOURCE_DIR}/zrtp/srtp)

if (NOT EXISTS ${zrtpSrcs}/ZRtp.cpp)
   MESSAGE(FATAL_ERROR "No ZRTP sources found in: ${zrtpSrcs}.")
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR} 
                    ${CMAKE_CURRENT_SOURCE_DIR}/src
                    ${zrtpSrcs} ${srtpSrcs} ${srtpSrcs}/crypto)

add_definitions(-g -O2 -fno-strict-aliasing)
if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-Wno-long-long -Wno-char-subscripts)
  add_definitions(-Wall)
  add_definitions(-DHAVE_CONFIG_H)
endif()

# set (GST_PLUGIN_LDFLAGS "-module -avoid-version -export-symbols-regex [_]*\\(gst_\\|Gst\\|GST_\\).*")

add_subdirectory(src)
add_subdirectory(demo)

