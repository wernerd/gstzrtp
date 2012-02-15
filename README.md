## General

This GStreamer plugin _zrtpfilter_ supports the ZRTP protocol as defined in
RFC 6189. The plugin also contains a SRTP/SRTCP implementation that support
different key lengths.

The current layout of zrtpfilter:

             +-------------------------------------+
             |              zrtpfilter             |
             +---------------+      +--------------+
             |recv_rtp_sink  |      |recv_rtp_src  |
    from     |               |      |              |  to RTP
    network  +---------------+      +--------------+  plugin,
    plugin,  |                                     |  e.g.
    e.g.     +---------------+      +--------------+  rtpbin
    udpsrc   |recv_rtcp_sink |      |recv_rtcp_src |
             |               |      |              |
             +---------------+      +--------------+
             |                                     |
             +---------------+      +--------------+
             |send_rtp_sink  |      |send_rtp_src  |
             |               |      |              |  to
    from RTP +---------------+      +--------------+  network
    plugin,  |                                     |  plugin,
    e.g.     +---------------+      +--------------+  e.g.
    rtpbin   |send_rtcp_sink |      |send_rtcp_src |  udpsink
             |               |      |              |
             +---------------+      +--------------+
             |                                     |
             +-------------------------------------+

The plugin is a full-duplex plugin that handles up- and downstream traffic for
RTP and RTCP. If connected with another ZRTP enabled client it automatically
negotiates the SRTP keys and enables SRTP and SRTCP. This is fully transparent
to the connected up- or downstream plugins.

## Building

__NOTE: this is a pre-alpha version for testing only!__

The only prerequisits the build GStreamer ZRTP are:

- openSSL development environment
- a C and C++ compiler (tested with gcc and g++)
- installed GStreamer base including development environment. Make sure you
  have also gstreamer-rtp installed.
- This plugin uses `cmake` to generate the build files.

The use `git clone` to get the sources from github and change into the gstZrtp
directory. Before starting to build you need to get the ZRTP and SRTP sources:

    sh getzrtp.sh
    
This script clones the current ZRTP/SRTP source repository (also on github)
into the _zrtp_ subdirectory. If this subdirectory already exists it checks if
it contains a Git repository and updates the sources with `git pull`. The
build process uses thes sources and puts the compiles objects into the
_zrtpfilter_ shared library. This avoids a dependcy to the standard ZRTP
library and is more inline with GStreamer's binary-only plugin concept.

Now create a build directoy and create the build scripts:

    mkdir build
    cd build
    cmake ..

Just call `make` as usual to build the shared library for the plugin. `cmake`
places this library in the `src` subdirectory und us can use it, for example
with gst-launch:

    gst-launch --gst-plugin-path=/your/path/gstZrtp/build/src ...


## Some documentation

The ZRTP sources contain a lot of documentation, the _zrtpfilter_ plugin will
have it also once it is in a more stable state and the interface to
applications is defined. Stay tuned.
