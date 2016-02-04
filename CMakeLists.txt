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

SET(CPACK_PACKAGE_VERSION_MAJOR 1)
SET(CPACK_PACKAGE_VERSION_MINOR 0)
SET(CPACK_PACKAGE_VERSION_PATCH 0)

set (VERSION 1.0.0)
set (SOVERSION 1)
set (PACKAGE zrtpfilter)

# The GStreamer package and version that this filter requires
set(GST_REQUIRED 1.0.10)
set(GST_PACKAGE gstreamer-rtp-1.0)

# Use standalone crypto module? If false try to use openSSL library
#
set (CRYPTO_STANDALONE true)


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
include(CheckFunctionExists)

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
pkg_check_modules(GST_RTP ${GST_PACKAGE}>=${GST_REQUIRED})
if (NOT GST_RTP_FOUND)
     MESSAGE(FATAL_ERROR "No GST_RTP packet found (check for gstreamer-rtp).")
endif()
link_directories(${GST_RTP_LIBRARY_DIRS})
add_definitions(${GST_RTP_CFLAGS})
set(LIBS ${LIBS} ${GST_RTP_LDFLAGS} ${GST_RTP_LIBRARIES})

MESSAGE(STATUS "GST include dirs ${GST_RTP_INCLUDE_DIRS}")

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()

# Check if ZRTP and SRTP source are available
#
set(zrtpSrcs ${PROJECT_SOURCE_DIR}/zrtp)

if (NOT EXISTS ${zrtpSrcs}/zrtp/ZRtp.cpp)
   MESSAGE(FATAL_ERROR "No ZRTP sources found in: ${zrtpSrcs}.")
endif()

if (NOT CRYPTO_STANDALONE)
    pkg_check_modules(OPENSSL libcrypto>=0.9.8)
    if (OPENSSL_FOUND)
        set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${OPENSSL_INCLUDE_DIRS}) #update include files search directory
        check_include_files(openssl/bn.h HAVE_OPENSSL_BN_H)
        check_include_files(openssl/aes.h HAVE_OPENSSL_AES_H)
        check_include_files(openssl/sha.h HAVE_OPENSSL_SHA_H)
        check_library_exists(crypto EVP_CipherInit_ex "${OPENSSL_LIBDIR}" HAVE_SSL_CRYPT) #use search lib directory from pkg-config
        set(LIBS ${LIBS} -lcrypto)
        set(CRYPTOBACKEND "libcrypto >= 0.9.8")
        set(BUILD_REQ "libopenssl-devel >= 0.9.8")
        set(PACKAGE_REQ "libopenssl >= 0.9.8")
        include_directories(${OPENSSL_INCLUDE_DIRS}) #update includes directory from pkg-configure_file
    else()
        message(FATAL_ERROR "No crypto library found")
    endif()
else()
    # For crypto standalone mode we need to configure the bnlib. In a first step
    # without the tests and demos.
    check_include_files(stdint.h HAVE_STDINT_H)
    check_include_files(stdint.h HAVE_ASSERT_H)
    check_include_files(limits.h HAVE_LIMITS_H)
    check_include_files(string.h HAVE_STRING_H)

    check_function_exists(memmove HAVE_MEMMOVE)
    check_function_exists(memcpy HAVE_MEMCPY)

    # TODO: check if we compile the tests for bnlib
    #
    # check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
    # check_function_exists(getrusage HAVE_GETRUSAGE)
    # check_function_exists(clock HAVE_CLOCK)
    # check_function_exists(time HAVE_TIME)

    # Check if Solaris-style gethrvtime() is available
    # check_function_exists(gethrvtime HAVE_GETHRVTIME)
    #
    # until here

    # necessary and required modules checked, ready to generate config.h
    configure_file(${zrtpSrcs}/bnlib/bnconfig.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/bnconfig.h)
endif()

check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(string.h HAVE_STRING_H)

# necessary and required modules checked, ready to generate config.h
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# Configure shell script to generate the documentation
set(ZRTP_LIB_FILE ${CMAKE_CURRENT_BINARY_DIR}/src)
set(ZRTP_SRC_DIR ${PROJECT_SOURCE_DIR}/src)
configure_file(${PROJECT_SOURCE_DIR}/doc/generateDoc.sh.cmake ${PROJECT_SOURCE_DIR}/doc/generateDoc.sh @ONLY)
execute_process(COMMAND chmod +x  ${PROJECT_SOURCE_DIR}/doc/generateDoc.sh WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/doc)

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src
                    ${zrtpSrcs} ${zrtpSrcs}/zrtp ${zrtpSrcs}/srtp ${zrtpSrcs}/bnlib)

include_directories(${GST_RTP_INCLUDE_DIRS})

add_definitions(-g -O2 -fno-strict-aliasing)
if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-Wno-long-long -Wno-char-subscripts -std=c++11)
  add_definitions(-Wall)
  add_definitions(-DHAVE_CONFIG_H)
endif()

# set (GST_PLUGIN_LDFLAGS "-module -avoid-version -export-symbols-regex [_]*\\(gst_\\|Gst\\|GST_\\).*")

add_subdirectory(src)
add_subdirectory(demo)
