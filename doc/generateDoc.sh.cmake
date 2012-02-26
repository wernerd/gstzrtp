#!/bin/sh
#
# Runs the gtkdoc stuff to create the documentation that follows the gtk/gstreamer rules.
#
# This script must only run after the plugin library was created, the cmake file in
# the src directory takes care of this, refer to the gstzrtp target. The gtk-scangobj
# gets the necessary parameter to link the plugin library and to find it when running
# the scanner executable.
#
# The script uses the same pkg-config data as the CMakeLists.txt and adds the path and
# name of the plugin library. To run the scanner executable the script also adds the
# correct LD_LIBRARY_PATH.
#
# The documentation does not include the helper and tester sources.
#
DOC_MODULE=zrtpfilter
#
# Get standard flags for compile and link
CFLAGS=`pkg-config @GST_PACKAGE@ --cflags`
LDFLAGS=`pkg-config @GST_PACKAGE@ --libs`

# Standard cmake setup using a normal build directory.
RUN="LD_LIBRARY_PATH=@ZRTP_LIB_FILE@"
MODLIBS="-L@ZRTP_LIB_FILE@ -lgstzrtp"
LDFLAGS="$LDFLAGS $MODLIBS"

# src directory name.
gtkdoc-scan --module=${DOC_MODULE} \
    --ignore-headers="gstzrtptester.h gstSrtpCWrapper.h" --source-dir=@ZRTP_SRC_DIR@

export CFLAGS LDFLAGS RUN
gtkdoc-scangobj --verbose --module=${DOC_MODULE}
gtkdoc-mkdb --module=${DOC_MODULE} --output-format=xml --xml-mode --source-dir=@ZRTP_SRC_DIR@ \
    --ignore-files="gstzrtptester.c gstzrtptester.h gstSrtpCWrapper.cpp gstSrtpCWrapper.h"

# xml files have changed
mkdir html
cd html && gtkdoc-mkhtml ${DOC_MODULE} ../zrtpfilter-docs.xml
cd ..
gtkdoc-fixxref --module=${DOC_MODULE} --module-dir=html
