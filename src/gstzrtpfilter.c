/*
 * GStreamer - ZRTP filter
 * Copyright (C) 2012 Werner Dittmann <Werner.Dittmann@t-online.de>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the
 * GNU Lesser General Public License Version 2.1 (the "LGPL"), in
 * which case the following provisions apply instead of the ones
 * mentioned above:
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * SECTION:element-zrtpfilter
 *
 * The ZRTP filter sits between the raw media transport (usually UDP) and the 
 * upstream plugin, usually a RTP plugin. 
 * 
 * The ZRTP filter monitors the data packets it receives via its receiver sinks
 * and checks if they belong to the ZRTP protocol. If this is the case the filter 
 * forwards these packets to the ZRTP protocol engine and discards them after 
 * being processed by the ZRTP protocol engine.
 * 
 * If the data packets do not belong to ZRTP the filter checks if these are RTP 
 * or RTCP packets (depending on the input sink) and if this is the case it checks 
 * if SRTP or SRTCP is active for the RTP/RTCP packets. ZRTP filter uses the SSRC 
 * to check this. If SRTP/SRTCP is active the filter calls SRTP/SRTCP to decrypt 
 * the packets and then forwards the packets to the upstream plugin.
 * 
 * The ZRTP filter checks data packets it gets via its send sinks if these packets
 * are valid RTP/RTCP packets. If this is the case it then checks if SRTP/SRTCP is 
 * active for the SSRC. If yes then the filter calls SRTP/SRTCP to encrypt the 
 * packets before it forwards the packets to the downstream plugin.
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * gst-launch --gst-plugin-path=$HOME/devhome/gstZrtp/build/src -m \
 *   zrtpfilter name=zrtp \
 *   udpsrc port=5004 ! zrtp.recv_rtp_sink zrtp.recv_rtp_src ! \
 *       fakesink dump=true sync=false async=false \
 *   udpsrc port=5005 ! zrtp.recv_rtcp_sink zrtp.recv_rtcp_src ! \
 *       fakesink dump=true sync=false async=false \
 *   zrtptester name=testsrc \
 *   testsrc.src ! zrtp.send_rtp_sink zrtp.send_rtp_src ! \
 *       udpsink clients="127.0.0.1:5002" sync=false async=false \
 *   testsrc.rtcp_src ! zrtp.send_rtcp_sink zrtp.send_rtcp_src ! \
 *       udpsink clients="127.0.0.1:5003" sync=false async=false
 * ]|
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>

#include <gst/gst.h>
#include <gst/rtp/gstrtpbuffer.h>

#include "gstzrtpfilter.h"

GST_DEBUG_CATEGORY_STATIC (gst_zrtp_filter_debug);
#define GST_CAT_DEFAULT gst_zrtp_filter_debug

/* Filter signals and args */
enum
{
    /* FILL ME */
    LAST_SIGNAL
};

enum
{
    PROP_0,
    PROP_SILENT
};

#define GST_ZRTP_LOCK(sess)   g_mutex_lock ((sess)->zrtpMutex)
#define GST_ZRTP_UNLOCK(sess) g_mutex_unlock ((sess)->zrtpMutex)


/* the capabilities of the inputs and outputs.
 * 
 * describe the real formats here.
 */
static GstStaticPadTemplate zrtp_recv_rtcp_sink_template =
GST_STATIC_PAD_TEMPLATE ("recv_rtcp_sink",
                         GST_PAD_SINK,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate zrtp_recv_rtcp_src_template =
GST_STATIC_PAD_TEMPLATE ("recv_rtcp_src",
                         GST_PAD_SRC,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate zrtp_recv_rtp_sink_template =
GST_STATIC_PAD_TEMPLATE ("recv_rtp_sink",
                         GST_PAD_SINK,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate zrtp_recv_rtp_src_template =
GST_STATIC_PAD_TEMPLATE ("recv_rtp_src",
                         GST_PAD_SRC,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);


static GstStaticPadTemplate zrtp_send_rtcp_sink_template =
GST_STATIC_PAD_TEMPLATE ("send_rtcp_sink",
                         GST_PAD_SINK,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate zrtp_send_rtcp_src_template =
GST_STATIC_PAD_TEMPLATE ("send_rtcp_src",
                         GST_PAD_SRC,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate zrtp_send_rtp_sink_template =
GST_STATIC_PAD_TEMPLATE ("send_rtp_sink",
                         GST_PAD_SINK,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate zrtp_send_rtp_src_template =
GST_STATIC_PAD_TEMPLATE ("send_rtp_src",
                         GST_PAD_SRC,
                         GST_PAD_ALWAYS,
                         GST_STATIC_CAPS ("ANY")
);


GST_BOILERPLATE (GstZrtpFilter, gst_zrtp_filter, GstElement, GST_TYPE_ELEMENT);

static void gst_zrtp_filter_finalize (GObject * object);
static void gst_zrtp_filter_set_property (GObject * object, guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_zrtp_filter_get_property (GObject * object, guint prop_id, GValue * value, GParamSpec * pspec);

static gboolean gst_zrtp_filter_set_caps (GstPad * pad, GstCaps * caps);

static GstFlowReturn gst_zrtp_filter_chain_rtp_up    (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_zrtp_filter_chain_rtp_down  (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_zrtp_filter_chain_rtcp_up   (GstPad * pad, GstBuffer * buf);
static GstFlowReturn gst_zrtp_filter_chain_rtcp_down (GstPad * pad, GstBuffer * buf);

/*                                     1
                              1234567890123456   */
static gchar clientId[] =    "GST ZRTP 2.1.0  ";

static gboolean zrtp_initialize(GstZrtpFilter* filter, const gchar *zidFilename, gboolean autoEnable);
static void zrtp_filter_startZrtp(GstZrtpFilter *zrtp);
static void zrtp_filter_stopZrtp(GstZrtpFilter *zrtp);

/* Forward declaration of thethe ZRTP specific callback functions that this
   adapter must implement */
static int32_t zrtp_sendDataZRTP(ZrtpContext* ctx, const uint8_t* data, int32_t length) ;
static int32_t zrtp_activateTimer(ZrtpContext* ctx, int32_t time) ;
static int32_t zrtp_cancelTimer(ZrtpContext* ctx) ;
static void zrtp_sendInfo(ZrtpContext* ctx, int32_t severity, int32_t subCode) ;
static int32_t zrtp_srtpSecretsReady(ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part) ;
static void zrtp_srtpSecretsOff(ZrtpContext* ctx, int32_t part) ;
static void zrtp_srtpSecretsOn(ZrtpContext* ctx, char* c, char* s, int32_t verified) ;
static void zrtp_handleGoClear(ZrtpContext* ctx) ;
static void zrtp_zrtpNegotiationFailed(ZrtpContext* ctx, int32_t severity, int32_t subCode) ;
static void zrtp_zrtpNotSuppOther(ZrtpContext* ctx) ;
static void zrtp_synchEnter(ZrtpContext* ctx) ;
static void zrtp_synchLeave(ZrtpContext* ctx) ;
static void zrtp_zrtpAskEnrollment(ZrtpContext* ctx, int32_t info) ;
static void zrtp_zrtpInformEnrollment(ZrtpContext* ctx, int32_t info) ;
static void zrtp_signSAS(ZrtpContext* ctx, char* sas) ;
static int32_t zrtp_checkSASSignature(ZrtpContext* ctx, char* sas) ;

/* The callback function structure for ZRTP */
static zrtp_Callbacks c_callbacks =
{
    &zrtp_sendDataZRTP,
    &zrtp_activateTimer,
    &zrtp_cancelTimer,
    &zrtp_sendInfo,
    &zrtp_srtpSecretsReady,
    &zrtp_srtpSecretsOff,
    &zrtp_srtpSecretsOn,
    &zrtp_handleGoClear,
    &zrtp_zrtpNegotiationFailed,
    &zrtp_zrtpNotSuppOther,
    &zrtp_synchEnter,
    &zrtp_synchLeave,
    &zrtp_zrtpAskEnrollment,
    &zrtp_zrtpInformEnrollment,
    &zrtp_signSAS,
    &zrtp_checkSASSignature
};

/* GObject vmethod implementations */

static void
gst_zrtp_filter_base_init (gpointer gclass)
{
    GstElementClass *element_class = GST_ELEMENT_CLASS (gclass);

    gst_element_class_set_details_simple(element_class,
                                         "ZrtpFilter",
                                         "Filter/Network/ZRTP",
                                         "Implement an ZRTP session",
                                         "Werner Dittmann <Werner.Dittmann@t-online.de>");

    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_recv_rtp_sink_template));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_recv_rtp_src_template));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_send_rtp_sink_template));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_send_rtp_src_template));

    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_recv_rtcp_sink_template));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_recv_rtcp_src_template));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_send_rtcp_sink_template));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&zrtp_send_rtcp_src_template));
}

/* initialize the zrtpfilter's class */
static void
gst_zrtp_filter_class_init (GstZrtpFilterClass * klass)
{
    GObjectClass *gobject_class;
    GstElementClass *gstelement_class;

    gobject_class = (GObjectClass *) klass;
    gstelement_class = (GstElementClass *) klass;

    gobject_class->finalize = gst_zrtp_filter_finalize;
    gobject_class->set_property = gst_zrtp_filter_set_property;
    gobject_class->get_property = gst_zrtp_filter_get_property;

    g_object_class_install_property (gobject_class, PROP_SILENT,
                                     g_param_spec_boolean ("silent", "Silent", "Produce verbose output ?",
                                     FALSE, G_PARAM_READWRITE));
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_zrtp_filter_init (GstZrtpFilter * filter,
                      GstZrtpFilterClass * gclass)
{
    /* At first initialize the non-pad stuff  */
    /* Create the empty wrapper */
    filter->zrtpCtx = zrtp_CreateWrapper();
    filter->clientIdString = clientId;    /* Set standard name */
    filter->zrtpSeq = 1;                  /* TODO: randomize */
    filter->zrtpMutex = g_mutex_new();
    filter->sysclock = gst_system_clock_obtain();
    filter->mitmMode = FALSE;
    filter->localSSRC = 0;
    filter->peerSSRC = 0;

    // TODO: filter chain, caps setter, getter checks
    // Initialize the receive (upstream) RTP data path
    filter->recv_rtp_sink = gst_pad_new_from_static_template (&zrtp_recv_rtp_sink_template, "recv_rtp_sink");
    gst_pad_set_setcaps_function (filter->recv_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    gst_pad_set_getcaps_function (filter->recv_rtp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function   (filter->recv_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtp_up));

    filter->recv_rtp_src = gst_pad_new_from_static_template (&zrtp_recv_rtp_src_template, "recv_rtp_src");
    gst_pad_set_getcaps_function (filter->recv_rtp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtp_src);


    // Initialize the send (downstream) RTP data path
    filter->send_rtp_sink = gst_pad_new_from_static_template (&zrtp_send_rtp_sink_template, "send_rtp_sink");
    gst_pad_set_setcaps_function (filter->send_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    gst_pad_set_getcaps_function (filter->send_rtp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function   (filter->send_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtp_down));

    filter->send_rtp_src = gst_pad_new_from_static_template (&zrtp_send_rtp_src_template, "send_rtp_src");
    gst_pad_set_getcaps_function (filter->send_rtp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtp_src);


    // Initialize the receive (upstream) RTCP data path
    filter->recv_rtcp_sink = gst_pad_new_from_static_template (&zrtp_recv_rtcp_sink_template, "recv_rtcp_sink");
    gst_pad_set_setcaps_function (filter->recv_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    gst_pad_set_getcaps_function (filter->recv_rtcp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function (filter->recv_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtcp_up));

    filter->recv_rtcp_src = gst_pad_new_from_static_template (&zrtp_recv_rtcp_src_template, "recv_rtcp_src");
    gst_pad_set_getcaps_function (filter->recv_rtcp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtcp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtcp_src);


    // Initialize the send (downstream) RTCP data path
    filter->send_rtcp_sink = gst_pad_new_from_static_template (&zrtp_send_rtcp_sink_template, "send_rtcp_sink");
    gst_pad_set_setcaps_function (filter->send_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    gst_pad_set_getcaps_function (filter->send_rtcp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function (filter->send_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtcp_down));

    filter->send_rtcp_src = gst_pad_new_from_static_template (&zrtp_send_rtcp_src_template, "send_rtcp_src");
    gst_pad_set_getcaps_function (filter->send_rtcp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtcp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtcp_src);


    // TODO: remove dummy call 
    zrtp_initialize(filter, "gstZrtpCache.dat", TRUE);
}

static void
gst_zrtp_filter_set_property (GObject * object, guint prop_id,
                              const GValue * value, GParamSpec * pspec)
{
    GstZrtpFilter *filter = GST_ZRTPFILTER (object);

    switch (prop_id) {
        case PROP_SILENT:
//            filter->silent = g_value_get_boolean (value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static void
gst_zrtp_filter_finalize (GObject* object)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER(object);

    zrtp_filter_stopZrtp(zrtp);

    G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
gst_zrtp_filter_get_property (GObject * object, guint prop_id,
                              GValue * value, GParamSpec * pspec)
{
    GstZrtpFilter *filter = GST_ZRTPFILTER (object);

    switch (prop_id) {
        case PROP_SILENT:
//            g_value_set_boolean (value, filter->silent);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

/* GstElement vmethod implementations */

/* this function handles the link with other elements */
static gboolean
gst_zrtp_filter_set_caps (GstPad * pad, GstCaps * caps)
{
    GstZrtpFilter *filter;
//     GstPad *otherpad;
// 
//     filter = GST_ZRTPFILTER (gst_pad_get_parent (pad));
//     otherpad = (pad == filter->srcpad) ? filter->sinkpad : filter->srcpad;
//     gst_object_unref (filter);
// 
//     return gst_pad_set_caps (otherpad, caps);
    return 1;
}

/* chain function - rtp upstream, from UDP to RTP session
 * this function does the actual processing
 */
static GstFlowReturn
gst_zrtp_filter_chain_rtp_up (GstPad* pad, GstBuffer* gstBuf)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (GST_OBJECT_PARENT (pad));
    guint8* buffer = GST_BUFFER_DATA(gstBuf);
    GstFlowReturn rc = GST_FLOW_ERROR;

    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xf0) != 0x10)
    {
        g_print ("process RTP buffer upstream.\n");
        //  Could be real RTP, check if we are in secure mode
        if (zrtp->srtpReceive == NULL)
        {
            rc = gst_pad_push (zrtp->recv_rtp_src, gstBuf);
        }
        else
        {
            rc = zsrtp_unprotect(zrtp->srtpReceive, gstBuf);
            if (rc == 1)
            {
                zrtp->unprotect++;
                rc = gst_pad_push (zrtp->recv_rtp_src, gstBuf);
                zrtp->unprotect_err = 0;
            }
            else
            {
                if (rc == -1) {
                    g_print ("untrotect failed - authentication error.\n");
//                     zrtp->userCallback->zrtp_showMessage(zrtp->userCallback->userData,
//                                                          zrtp_Warning,
//                                                          zrtp_WarningSRTPauthError);
                }
                else {
                    g_print ("untrotect failed - replay error.\n");
//                     zrtp->userCallback->zrtp_showMessage(zrtp->userCallback->userData,
//                                                          zrtp_Warning,
//                                                          zrtp_WarningSRTPreplayError);
                }
                zrtp->unprotect_err = rc;
                gst_buffer_unref(gstBuf);
                rc = GST_FLOW_ERROR;
            }
        }
        if (!zrtp->started && zrtp->enableZrtp)
            zrtp_filter_startZrtp(zrtp);
        return rc;
    }

    /* We assume all other packets are ZRTP packets here. Process
     * if ZRTP processing is enabled. Because valid RTP packets are
     * already handled we delete (unref buffer) any packets here after
     * processing.
     */
    if (zrtp->enableZrtp && zrtp->zrtpCtx != NULL)
    {
        // Get CRC value into crc (see above how to compute the offset)
        gint temp = GST_BUFFER_SIZE(gstBuf) - CRC_SIZE;
        guint32 crc = *(guint32*)(buffer + temp);
        crc = g_ntohl(crc);

        g_print ("process ZRTP buffer.\n");

        if (!zrtp_CheckCksum(buffer, temp, crc))
        {
            g_print ("ZRTP CRC check failed.\n");
//             if (zrtp->userCallback != NULL)
//                 zrtp->userCallback->zrtp_showMessage(zrtp->userCallback->userData, zrtp_Warning, zrtp_WarningCRCmismatch);
            return rc;
        }

        guint32 magic = *(guint32*)(buffer + 4);
        magic = g_ntohl(magic);

        // Check if it is really a ZRTP packet, return, no further processing
        if (magic != ZRTP_MAGIC || zrtp->zrtpCtx == NULL)
        {
            gst_buffer_unref(gstBuf);
            return GST_FLOW_ERROR;
        }
        // cover the case if the other party sends _only_ ZRTP packets at the
        // beginning of a session. Start ZRTP in this case as well.
        if (!zrtp->started)
        {
            zrtp_filter_startZrtp(zrtp);
        }
        // this now points beyond the undefined and length field.
        // We need them, thus adjust
        unsigned char* zrtpMsg = (buffer + 12);

        // store peer's SSRC in host order, used when creating the CryptoContext
        zrtp->peerSSRC = *(guint32*)(buffer + 8);
        zrtp->peerSSRC = g_ntohl(zrtp->peerSSRC);
        // If ZRTP engine was initialized and set up but not started these packets are ignored
        // by the state engine.
        zrtp_processZrtpMessage(zrtp->zrtpCtx, zrtpMsg, zrtp->peerSSRC);
    }

    gst_buffer_unref(gstBuf);
    return GST_FLOW_OK;
}

/* chain function - rtp downstream, from RTP session to UDP
 * this function does the actual processing
 */
static GstFlowReturn
gst_zrtp_filter_chain_rtp_down (GstPad * pad, GstBuffer* gstBuf)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (GST_OBJECT_PARENT (pad));
    GstFlowReturn rc = GST_FLOW_ERROR;

    if (zrtp->localSSRC == 0) {
        zrtp->localSSRC = gst_rtp_buffer_get_ssrc(gstBuf);   /* Learn own SSRC before starting ZRTP */
    }

    if (!zrtp->started && zrtp->enableZrtp)
    {
        zrtp_filter_startZrtp(zrtp);
    }

    if (zrtp->srtpSend == NULL)
    {
        rc = gst_pad_push (zrtp->send_rtp_src, gstBuf);
    }
    else
    {
        rc = zsrtp_protect(zrtp->srtpSend, gstBuf);
        zrtp->protect++;

        if (rc == 1)
            rc = gst_pad_push (zrtp->send_rtp_src, gstBuf);
        else {
            rc = GST_FLOW_ERROR;
            gst_buffer_unref(gstBuf);
        }
    }
    return rc;
}

/* chain function - rtcp upstream, from UDP to RTP session
 * this function does the actual processing
 */
static GstFlowReturn
gst_zrtp_filter_chain_rtcp_up (GstPad * pad, GstBuffer* gstBuf)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (GST_OBJECT_PARENT (pad));
    GstFlowReturn rc = GST_FLOW_ERROR;

    g_print("RTCP received\n");
    if (zrtp->srtcpReceive == NULL)
    {
        rc = gst_pad_push (zrtp->recv_rtcp_src, gstBuf);
    }
    else
    {
        rc = zsrtp_unprotectCtrl(zrtp->srtcpReceive, gstBuf);
        g_print("RTCP unprotect: %d\n", rc);
        if (rc == 1)
        {
            /* Call stream's callback */
            rc = gst_pad_push(zrtp->recv_rtcp_src, gstBuf);
        }
        else {
            rc = GST_FLOW_ERROR;
            gst_buffer_unref(gstBuf);
        }
    }
    return rc;
}

/* chain function - rtcp downstream, from RTP session to UDP
 * this function does the actual processing
 */
static GstFlowReturn
gst_zrtp_filter_chain_rtcp_down (GstPad * pad, GstBuffer* gstBuf)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (GST_OBJECT_PARENT (pad));
    GstFlowReturn rc = GST_FLOW_ERROR;

    if (zrtp->srtcpSend == NULL)
    {
        rc = gst_pad_push (zrtp->send_rtcp_src, gstBuf);
    }
    else
    {
        rc = zsrtp_protectCtrl(zrtp->srtcpSend, gstBuf);

        if (rc == 1)
            rc = gst_pad_push(zrtp->send_rtcp_src, gstBuf);
        else {
            rc = GST_FLOW_ERROR;
            gst_buffer_unref(gstBuf);
        }
    }
    return rc;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
zrtpfilter_init (GstPlugin * zrtpfilter)
{
    /* debug category for fltering log messages
     * 
     * exchange the string 'Template zrtpfilter' with your description
     */
    GST_DEBUG_CATEGORY_INIT (gst_zrtp_filter_debug, "zrtpfilter",
                             0, "Template zrtpfilter");

    return gst_element_register (zrtpfilter, "zrtpfilter", GST_RANK_NONE,
                                 GST_TYPE_ZRTPFILTER);
}

/* PACKAGE: this is usually set by autotools depending on some _INIT macro
 * in configure.ac and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use autotools to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "zrtpfilter"
#endif

/* gstreamer looks for this structure to register zrtpfilters
 * 
 * exchange the string 'Template zrtpfilter' with your zrtpfilter description
 */
GST_PLUGIN_DEFINE (
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    "zrtpfilter",
    "Template zrtpfilter",
    zrtpfilter_init,
    VERSION,
    "LGPL",
    "GStreamer",
    "http://gstreamer.net/"
)

/*
 * Support functions to set various flags and control the ZRTP engine
 */
static
gboolean zrtp_initialize(GstZrtpFilter* filter, const gchar *zidFilename, gboolean autoEnable)
{
    zrtp_initializeZrtpEngine(filter->zrtpCtx, &c_callbacks, filter->clientIdString,
                              zidFilename, filter, filter->mitmMode);
    filter->enableZrtp = autoEnable;
    return TRUE;
}

/*
 * Implement the specific ZRTP transport functions
 *
PJ_DECL(void) pjmedia_transport_zrtp_setEnableZrtp(pjmedia_transport *tp, pj_bool_t onOff)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    pj_assert(tp);

    zrtp->enableZrtp = onOff;
}

PJ_DECL(pj_bool_t) pjmedia_transport_zrtp_isEnableZrtp(pjmedia_transport *tp)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    PJ_ASSERT_RETURN(tp, PJ_FALSE);

    return zrtp->enableZrtp;

}

PJ_DEF(void) pjmedia_transport_zrtp_setUserCallback(pjmedia_transport *tp, zrtp_UserCallbacks* ucb)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    pj_assert(tp);

    zrtp->userCallback = ucb;
}

PJ_DEF(void* )pjmedia_transport_zrtp_getUserData(pjmedia_transport *tp){
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    pj_assert(tp);

    return zrtp->userCallback->userData;
}
*/
static
void zrtp_filter_startZrtp(GstZrtpFilter *zrtp)
{
    zrtp_startZrtpEngine(zrtp->zrtpCtx);
    zrtp->started = 1;
}

static
void zrtp_filter_stopZrtp(GstZrtpFilter *zrtp)
{
    /* TODO: check if we need to unref/free other data */
    zrtp_stopZrtpEngine(zrtp->zrtpCtx); /* switches off secure mode: zrtp_srtpSecretsOff() */
    zrtp_DestroyWrapper(zrtp->zrtpCtx);
    zrtp->zrtpCtx = NULL;
    zrtp->started = 0;
    zrtp->enableZrtp = FALSE;
    GST_ZRTP_LOCK(zrtp);                /* Just to make sure no other thread has it */
    GST_ZRTP_UNLOCK(zrtp);
    g_mutex_free (zrtp->zrtpMutex);
    g_object_unref(zrtp->sysclock);
}
/*
PJ_DECL(void) pjmedia_transport_zrtp_setLocalSSRC(pjmedia_transport *tp, uint32_t ssrc)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    pj_assert(tp);

    zrtp->localSSRC = ssrc;
}

PJ_DECL(pj_bool_t) pjmedia_transport_zrtp_isMitmMode(pjmedia_transport *tp)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    pj_assert(tp);

    return zrtp->mitmMode;
}

PJ_DECL(void) pjmedia_transport_zrtp_setMitmMode(pjmedia_transport *tp, pj_bool_t mitmMode)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    pj_assert(tp);

    zrtp->mitmMode = mitmMode;
}

PJ_DECL(ZrtpContext*) pjmedia_transport_zrtp_getZrtpContext(pjmedia_transport *tp)
{
    struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
    PJ_ASSERT_RETURN(tp, NULL);

    return zrtp->zrtpCtx;
}
*/
static
gboolean timer_callback(GstClock *clock, GstClockTime time,
                        GstClockID id, gpointer userData)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (userData);
    gst_clock_id_unref(zrtp->clockId);
    zrtp->clockId = NULL;

    zrtp_processTimeout(zrtp->zrtpCtx);
    return TRUE;
}

/*
 * The ZRTP callbacks that implement system specific (in this case gstreamer)
 * support functions.
 */

static
gint32 zrtp_sendDataZRTP(ZrtpContext* ctx, const uint8_t* data, int32_t length)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    guint totalLen = length + 12;     /* Fixed number of bytes of ZRTP header */
    guint32 crc;
    guint16* pus;
    guint32* pui;

    if ((totalLen) > MAX_ZRTP_SIZE)
        return 0;

    /* TODO: check to use gst_pad_alloc_buffer ()
     */
    GstBuffer* gstBuf = gst_buffer_new_and_alloc(totalLen);
    guint8* buffer = GST_BUFFER_DATA(gstBuf);

    /* Get some handy pointers */
    pus = (guint16*)buffer;
    pui = (guint32*)buffer;

    /* set up fixed ZRTP header */
    *buffer = 0x10;     /* invalid RTP version - refer to ZRTP spec chap 5 */
    *(buffer + 1) = 0;
    pus[1] = g_htons(zrtp->zrtpSeq);
    zrtp->zrtpSeq++;
    pui[1] = g_htonl(ZRTP_MAGIC);
    pui[2] = g_htonl(zrtp->localSSRC);   /* stored in host order */

    /* store ZRTP message data after the header data */
    g_memmove(buffer+12, data, length);

    /* Setup and compute ZRTP CRC */
    crc = zrtp_GenerateCksum(buffer, totalLen-CRC_SIZE);

    /* convert and store CRC in ZRTP packet.*/
    crc = zrtp_EndCksum(crc);
    *(guint32*)(buffer+totalLen-CRC_SIZE) = g_htonl(crc);

    /* Send the ZRTP packet using the downstream plugin */
    return (gst_pad_push (zrtp->send_rtp_src, gstBuf) == GST_FLOW_OK) ? 1 : 0;
}

static
gint32 zrtp_activateTimer(ZrtpContext* ctx, int32_t time)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    GstClockTime timeout = gst_clock_get_time(zrtp->sysclock);
    timeout = GST_TIME_AS_MSECONDS(timeout) + time;

    zrtp->clockId = gst_clock_new_single_shot_id(zrtp->sysclock, timeout*GST_MSECOND);

    /*GstClockReturn ret =*/ gst_clock_id_wait_async(zrtp->clockId, &timer_callback, zrtp);

    return 1;
}

static
gint32 zrtp_cancelTimer(ZrtpContext* ctx)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    if (zrtp->clockId) {
        gst_clock_id_unschedule (zrtp->clockId);
        gst_clock_id_unref(zrtp->clockId);
        zrtp->clockId = NULL;
    }
    return 1;
}

static
void zrtp_sendInfo(ZrtpContext* ctx, int32_t severity, int32_t subCode)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("sendInfo: severity: %d, code: %d\n", severity, subCode);
/*    if (zrtp->userCallback != NULL)
    {
        zrtp->userCallback->zrtp_showMessage(zrtp->userCallback->userData, severity, subCode);
    }
*/
}

static int32_t zrtp_srtpSecretsReady(ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);


    ZsrtpContext* recvCrypto;
    ZsrtpContext* senderCrypto;
    ZsrtpContextCtrl* recvCryptoCtrl;
    ZsrtpContextCtrl* senderCryptoCtrl;
    gint cipher;
    gint authn;
    gint authKeyLen;
    //    int srtcpAuthTagLen;

    if (secrets->authAlgorithm == zrtp_Sha1) {
        authn = SrtpAuthenticationSha1Hmac;
        authKeyLen = 20;
        //        srtcpAuthTagLen = 80;   // Always 80 bit for SRTCP / SHA1
    }

    if (secrets->authAlgorithm == zrtp_Skein) {
        authn = SrtpAuthenticationSkeinHmac;
        authKeyLen = 32;
        //        srtcpAuthTagLen = 64;   // Always 64 bit for SRTCP / Skein
    }

    if (secrets->symEncAlgorithm == zrtp_Aes)
        cipher = SrtpEncryptionAESCM;

    if (secrets->symEncAlgorithm == zrtp_TwoFish)
        cipher = SrtpEncryptionTWOCM;

    if (part == ForSender) {
        // To encrypt packets: intiator uses initiator keys,
        // responder uses responder keys
        // Create a "half baked" crypto context first and store it. This is
        // the main crypto context for the sending part of the connection.
        if (secrets->role == Initiator) {
            senderCrypto = zsrtp_CreateWrapper(zrtp->localSSRC,
                                               0,
                                               0L,                                      // keyderivation << 48,
                                               cipher,                                  // encryption algo
                                               authn,                                   // authtentication algo
                                               (unsigned char*)secrets->keyInitiator,   // Master Key
                                               secrets->initKeyLen / 8,                 // Master Key length
                                               (unsigned char*)secrets->saltInitiator,  // Master Salt
                                               secrets->initSaltLen / 8,                // Master Salt length
                                               secrets->initKeyLen / 8,                 // encryption keyl
                                               authKeyLen,                              // authentication key len
                                               secrets->initSaltLen / 8,                // session salt len
                                               secrets->srtpAuthTagLen / 8);            // authentication tag lenA

            senderCryptoCtrl = zsrtp_CreateWrapperCtrl(zrtp->localSSRC,
                                                       cipher,                                    // encryption algo
                                                       authn,                                     // authtication algo
                                                       (unsigned char*)secrets->keyInitiator,     // Master Key
                                                       secrets->initKeyLen / 8,                   // Master Key length
                                                       (unsigned char*)secrets->saltInitiator,    // Master Salt
                                                       secrets->initSaltLen / 8,                  // Master Salt length
                                                       secrets->initKeyLen / 8,                   // encryption keyl
                                                       authKeyLen,                                // authentication key len
                                                       secrets->initSaltLen / 8,                  // session salt len
                                                       secrets->srtpAuthTagLen / 8);              // authentication tag len
            //                                                              srtcpAuthTagLen / 8);                      // authentication tag len
        }
        else {
            senderCrypto = zsrtp_CreateWrapper(zrtp->localSSRC,
                                               0,
                                               0L,                                      // keyderivation << 48,
                                               cipher,                                  // encryption algo
                                               authn,                                   // authtentication algo
                                               (unsigned char*)secrets->keyResponder,   // Master Key
                                               secrets->respKeyLen / 8,                 // Master Key length
                                               (unsigned char*)secrets->saltResponder,  // Master Salt
                                               secrets->respSaltLen / 8,                // Master Salt length
                                               secrets->respKeyLen / 8,                 // encryption keyl
                                               authKeyLen,                              // authentication key len
                                               secrets->respSaltLen / 8,                // session salt len
                                               secrets->srtpAuthTagLen / 8);            // authentication tag len

            senderCryptoCtrl = zsrtp_CreateWrapperCtrl(zrtp->localSSRC,
                                                       cipher,                                    // encryption algo
                                                       authn,                                     // authtication algo
                                                       (unsigned char*)secrets->keyResponder,     // Master Key
                                                       secrets->respKeyLen / 8,                   // Master Key length
                                                       (unsigned char*)secrets->saltResponder,    // Master Salt
                                                       secrets->respSaltLen / 8,                  // Master Salt length
                                                       secrets->respKeyLen / 8,                   // encryption keyl
                                                       authKeyLen,                                // authentication key len
                                                       secrets->respSaltLen / 8,                  // session salt len
                                                       secrets->srtpAuthTagLen / 8);              // authentication tag len
            //                                                              srtcpAuthTagLen / 8);                      // authentication tag len
        }
        if (senderCrypto == NULL) {
            return 0;
        }
        // Create a SRTP crypto context for real SSRC sender stream.
        // Note: key derivation can be done at this time only if the
        // key derivation rate is 0 (disabled). For ZRTP this is the
        // case: the key derivation is defined as 2^48
        // which is effectively 0.
        zsrtp_deriveSrtpKeys(senderCrypto, 0L);
        zrtp->srtpSend = senderCrypto;

        zsrtp_deriveSrtpKeysCtrl(senderCryptoCtrl);
        zrtp->srtcpSend = senderCryptoCtrl;
    }
    if (part == ForReceiver) {
        // To decrypt packets: intiator uses responder keys,
        // responder initiator keys
        // See comment above.
        if (secrets->role == Initiator) {
            recvCrypto = zsrtp_CreateWrapper(zrtp->peerSSRC,
                                             0,
                                             0L,                                      // keyderivation << 48,
                                             cipher,                                  // encryption algo
                                             authn,                                   // authtentication algo
                                             (unsigned char*)secrets->keyResponder,   // Master Key
                                             secrets->respKeyLen / 8,                 // Master Key length
                                             (unsigned char*)secrets->saltResponder,  // Master Salt
                                             secrets->respSaltLen / 8,                // Master Salt length
                                             secrets->respKeyLen / 8,                 // encryption keyl
                                             authKeyLen,                              // authentication key len
                                             secrets->respSaltLen / 8,                // session salt len
                                             secrets->srtpAuthTagLen / 8);            // authentication tag len

            recvCryptoCtrl = zsrtp_CreateWrapperCtrl(zrtp->peerSSRC,
                                                     cipher,                                    // encryption algo
                                                     authn,                                     // authtication algo
                                                     (unsigned char*)secrets->keyResponder,     // Master Key
                                                     secrets->respKeyLen / 8,                   // Master Key length
                                                     (unsigned char*)secrets->saltResponder,    // Master Salt
                                                     secrets->respSaltLen / 8,                  // Master Salt length
                                                     secrets->respKeyLen / 8,                   // encryption keyl
                                                     authKeyLen,                                // authentication key len
                                                     secrets->respSaltLen / 8,                  // session salt len
                                                     secrets->srtpAuthTagLen / 8);              // authentication tag len
            //                                                            srtcpAuthTagLen / 8);                      // authentication tag len
        }
        else {
            recvCrypto = zsrtp_CreateWrapper(zrtp->peerSSRC,
                                             0,
                                             0L,                                      // keyderivation << 48,
                                             cipher,                                  // encryption algo
                                             authn,                                   // authtentication algo
                                             (unsigned char*)secrets->keyInitiator,   // Master Key
                                             secrets->initKeyLen / 8,                 // Master Key length
                                             (unsigned char*)secrets->saltInitiator,  // Master Salt
                                             secrets->initSaltLen / 8,                // Master Salt length
                                             secrets->initKeyLen / 8,                 // encryption keyl
                                             authKeyLen,                              // authentication key len
                                             secrets->initSaltLen / 8,                // session salt len
                                             secrets->srtpAuthTagLen / 8);            // authentication tag len

            recvCryptoCtrl = zsrtp_CreateWrapperCtrl(zrtp->peerSSRC,
                                                     cipher,                                    // encryption algo
                                                     authn,                                     // authtication algo
                                                     (unsigned char*)secrets->keyInitiator,     // Master Key
                                                     secrets->initKeyLen / 8,                   // Master Key length
                                                     (unsigned char*)secrets->saltInitiator,    // Master Salt
                                                     secrets->initSaltLen / 8,                  // Master Salt length
                                                     secrets->initKeyLen / 8,                   // encryption keyl
                                                     authKeyLen,                                // authentication key len
                                                     secrets->initSaltLen / 8,                  // session salt len
                                                     secrets->srtpAuthTagLen / 8);              // authentication tag len
            //                                                            srtcpAuthTagLen / 8);                      // authentication tag len
        }
        if (recvCrypto == NULL) {
            return 0;
        }
        // Create a SRTP crypto context for real SSRC input stream.
        // If the sender didn't provide a SSRC just insert the template
        // into the queue. After we received the first packet the real
        // crypto context will be created.
        //
        // Note: key derivation can be done at this time only if the
        // key derivation rate is 0 (disabled). For ZRTP this is the
        // case: the key derivation is defined as 2^48
        // which is effectively 0.
        zsrtp_deriveSrtpKeys(recvCrypto, 0L);
        zrtp->srtpReceive = recvCrypto;

        zsrtp_deriveSrtpKeysCtrl(recvCryptoCtrl);
        zrtp->srtcpReceive = recvCryptoCtrl;
    }

    return 1;
}

static
void zrtp_srtpSecretsOff(ZrtpContext* ctx, int32_t part)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("secretsOff: part: %d\n", part);

    if (part == ForSender)
    {
        zsrtp_DestroyWrapper(zrtp->srtpSend);
        zsrtp_DestroyWrapperCtrl(zrtp->srtcpSend);
        zrtp->srtpSend = NULL;
        zrtp->srtcpSend = NULL;
    }
    if (part == ForReceiver)
    {
         zsrtp_DestroyWrapper(zrtp->srtpReceive);
         zsrtp_DestroyWrapperCtrl(zrtp->srtcpReceive);
         zrtp->srtpReceive = NULL;
         zrtp->srtcpReceive = NULL;
    }
}

static
void zrtp_srtpSecretsOn(ZrtpContext* ctx, char* c, char* s, int32_t verified)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("secretsOn: code: %s, sas: %s, verified: %d\n", c, s, verified);

//     if (zrtp->userCallback != NULL)
//     {
//         zrtp->userCallback->zrtp_secureOn(zrtp->userCallback->userData, c);
// 
//         if (strlen(s) > 0)
//         {
//             zrtp->userCallback->zrtp_showSAS(zrtp->userCallback->userData, s, verified);
//         }
//     }
}

static
void zrtp_handleGoClear(ZrtpContext* ctx)
{
}

static
void zrtp_zrtpNegotiationFailed(ZrtpContext* ctx, int32_t severity, int32_t subCode)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("negotiationFailed: severity: %d, code: %d\n", severity, subCode);

//     if (zrtp->userCallback != NULL)
//     {
//         zrtp->userCallback->zrtp_zrtpNegotiationFailed(zrtp->userCallback->userData, severity, subCode);
//     }

}

static
void zrtp_zrtpNotSuppOther(ZrtpContext* ctx)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("not supported by other peer\n");

//     if (zrtp->userCallback != NULL)
//     {
//         zrtp->userCallback->zrtp_zrtpNotSuppOther(zrtp->userCallback->userData);
//     }

}

static
void zrtp_synchEnter(ZrtpContext* ctx)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    GST_ZRTP_LOCK(zrtp) ;
}

static
void zrtp_synchLeave(ZrtpContext* ctx)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    GST_ZRTP_UNLOCK(zrtp);
}

static
void zrtp_zrtpAskEnrollment(ZrtpContext* ctx, int32_t info)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("askEnrollment: info: %d\n", info);

//     if (zrtp->userCallback != NULL)
//     {
//         zrtp->userCallback->zrtp_zrtpAskEnrollment(zrtp->userCallback->userData, info);
//     }
}

static
void zrtp_zrtpInformEnrollment(ZrtpContext* ctx, int32_t info)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("informEnrollment: info: %d\n", info);

//     if (zrtp->userCallback != NULL)
//     {
//         zrtp->userCallback->zrtp_zrtpInformEnrollment(zrtp->userCallback->userData, info);
//     }
}

static
void zrtp_signSAS(ZrtpContext* ctx, char* sas)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("signSAS: sas: %s\n", sas);

//     if (zrtp->userCallback != NULL)
//     {
//         zrtp->userCallback->zrtp_signSAS(zrtp->userCallback->userData, sas);
//     }
}

static
gint32 zrtp_checkSASSignature(ZrtpContext* ctx, char* sas)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_print ("checkAsaSignature: sas: %s\n", sas);

//     if (zrtp->userCallback != NULL)
//     {
//         return zrtp->userCallback->zrtp_checkSASSignature(zrtp->userCallback->userData, sas);
//     }
    return 0;
}

