/*
 * GStreamer - ZRTP filter
 * Copyright (C) 2012 Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 * gstzrtpfilter.c:
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
 * SECTION:zrtpfilter
 *
 * The ZRTP filter sits between the raw media transport (usually UDP) and the 
 * upstream plugin, usually a RTP plugin. 
 * 
 * The ZRTP filter monitors the data packets it receives via its receiver sinks
 * and checks if they belong to the ZRTP protocol. The filter
 * forwards ZRTP packets to the ZRTP protocol engine and discards them after
 * the ZRTP packets were processed.
 * 
 * Data packets that do not belong to ZRTP are either RTP or RTCP packets
 * (depending on the input sink) and the filter checks if SRTP or SRTCP is active.
 * If this is the case the filter calls SRTP/SRTCP unprotect functions to decrypt
 * the packets. If the unprotect functions do not return an error the filter
 * forwards the decrypted packets to the upstream plugin.
 * 
 * The ZRTP filter protects (encrypts) data packets it gets via its send sinks if
 * if SRTP/SRTCP is active. If yes then the filter calls SRTP/SRTCP protect
 * functions before it forwards the packets to the send plugin.
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * gst-launch me/gstZrtp/build/src zrtpfilter name=zrtp cache-name=gstZrtpCache.dat initialize=true \
 *   udpsrc port=5004 ! zrtp.recv_rtp_sink zrtp.recv_rtp_src ! fakesink dump=true sync=false async=false \
 *   udpsrc port=5005 ! zrtp.recv_rtcp_sink zrtp.recv_rtcp_src ! fakesink dump=true sync=false async=false \
 *   zrtptester name=testsrc \
 *   testsrc.src ! zrtp.send_rtp_sink zrtp.send_rtp_src ! udpsink clients="127.0.0.1:5002" sync=false async=false \
 *   testsrc.rtcp_src ! zrtp.send_rtcp_sink zrtp.send_rtcp_src ! udpsink clients="127.0.0.1:5003" sync=false async=false
 * ]|
 * This filter receives data from its peer at ports 5004 and 5005 (RTP and RTCP) and
 * sends data to its peer on ports 5002 and 5003 (RTP and RTCP). The filter uses the RTP
 * ports (5002 and 5004) to send and receive ZRTP data. ZRTP does not use the RTCP ports.
 * <para/>
 * <note>
 * <para>
 *   The ZRTP property @initialize should be always the last property to set
 *   for the zrtpfilter otherwise the ZRTP cache file name is not recognized.
 *   Processing the initialize property also checks and opens the ZRTP cache. If
 *   the cache name property is not set the ZRTP filter uses the default
 *   file name "$HOME/.GNUccRTP.zid"
 * </para>
 * </note>
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
enum {
    SIGNAL_ALGORITHM,
    SIGNAL_SAS,
    SIGNAL_STATUS,
    SIGNAL_SECURITY_OFF,
    SIGNAL_NEGOTIATION,
    SIGNAL_NOT_SUPP,
    SIGNAL_ASK_ENROLL,
    SIGNAL_INFORM_ENROLL,
    SIGNAL_SIGN_SAS,
    SIGNAL_CHECK_SAS_SIGN,
    LAST_SIGNAL
};

enum {
    PROP_0,
    PROP_ENABLE_ZRTP,
    PROP_LOCAL_SSRC,
    PROP_MITM_MODE,
    PROP_CACHE_NAME,
    PROP_INITALIZE,
    PROP_START,
    PROP_STOP,
    PROP_MULTI_PARAM,
    PROP_IS_MULTI,
    PROP_MULTI_AVAILABLE,
    PROP_LAST,
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

// static gboolean gst_zrtp_filter_set_caps (GstPad * pad, GstCaps * caps);

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

/* Forward declaration of the ZRTP specific callback functions that this
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
static void zrtp_signSAS(ZrtpContext* ctx, guint8* sas) ;
static int32_t zrtp_checkSASSignature(ZrtpContext* ctx, guint8* sas) ;

/* The callback function structure for ZRTP */
static zrtp_Callbacks c_callbacks = {
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

static guint gst_zrtp_filter_signals[LAST_SIGNAL] = { 0 };

#define GST_TYPE_ZRTP_FILTER_MSG_SEVERITY (gst_zrtp_filter_msg_severity_get_type())
static GType
gst_zrtp_filter_msg_severity_get_type(void)
{
    static GType zrtpfilter_msg_severity_type = 0;
    static const GEnumValue zrtpfilter_msg_severity[] = {
        {zrtp_Info,      "Info", "Status and info message"},
        {zrtp_Warning,   "Warning", " Warning message - security can be established"},
        {zrtp_Severe,    "Severe", "Severe error, security will not be established"},
        {zrtp_ZrtpError, "ZrtpError", "ZRTP error, security will not be established"},
        {0, NULL, NULL},
    };

    if (!zrtpfilter_msg_severity_type) {
        zrtpfilter_msg_severity_type =
            g_enum_register_static ("GstZrtpMsgSeverity", zrtpfilter_msg_severity);
    }
    return zrtpfilter_msg_severity_type;
}

#define GST_TYPE_ZRTP_FILTER_INFO (gst_zrtp_filter_info_get_type())
static GType
gst_zrtp_filter_info_get_type(void)
{
    static GType zrtpfilter_info_type = 0;
    static const GEnumValue zrtpfilter_info[] = {
        {zrtp_InfoHelloReceived,      "InfoHelloReceived", "Hello received, preparing a Commit"},
        {zrtp_InfoCommitDHGenerated,  "InfoCommitDHGenerated", "Commit: Generated a public DH key"},
        {zrtp_InfoRespCommitReceived, "InfoRespCommitReceived", "Responder: Commit received, preparing DHPart1"},
        {zrtp_InfoDH1DHGenerated,     "InfoDH1DHGenerated", "DH1Part: Generated a public DH key"},
        {zrtp_InfoInitDH1Received,    "InfoInitDH1Received", "Initiator: DHPart1 received, preparing DHPart2"},
        {zrtp_InfoRespDH2Received,    "InfoRespDH2Received", "Responder: DHPart2 received, preparing Confirm1"},
        {zrtp_InfoInitConf1Received,  "InfoInitConf1Received", "Initiator: Confirm1 received, preparing Confirm2"},
        {zrtp_InfoRespConf2Received,  "InfoRespConf2Received", "Responder: Confirm2 received, preparing Conf2Ack"},
        {zrtp_InfoRSMatchFound,       "InfoRSMatchFound", "At least one retained secrets matches - forward security OK"},
        {zrtp_InfoSecureStateOn,      "InfoSecureStateOn", "Entered secure state"},
        {zrtp_InfoSecureStateOff,     "InfoSecureStateOff", "No more security for this session"},
        {0, NULL, NULL},
    };

    if (!zrtpfilter_info_type) {
        zrtpfilter_info_type =
            g_enum_register_static ("GstZrtpInfo", zrtpfilter_info);
    }
    return zrtpfilter_info_type;
}

#define GST_TYPE_ZRTP_FILTER_WARNING (gst_zrtp_filter_warning_get_type())
static GType
gst_zrtp_filter_warning_get_type(void)
{
    static GType zrtpfilter_warning_type = 0;
    static const GEnumValue zrtpfilter_warning[] = {
        {zrtp_WarningDHAESmismatch,     "WarningDHAESmismatch", "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096"},
        {zrtp_WarningGoClearReceived,   "WarningGoClearReceived", "Received a GoClear message"},
        {zrtp_WarningDHShort,           "WarningDHShort", "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096"},
        {zrtp_WarningNoRSMatch,         "WarningNoRSMatch", "No retained shared secrets available - must verify SAS"},
        {zrtp_WarningCRCmismatch,       "WarningCRCmismatch", "Internal ZRTP packet checksum mismatch - packet dropped"},
        {zrtp_WarningSRTPauthError,     "WarningSRTPauthError", "Dropping packet because SRTP authentication failed!"},
        {zrtp_WarningSRTPreplayError,   "WarningSRTPreplayError", "Dropping packet because SRTP replay check failed!"},
        {zrtp_WarningNoExpectedRSMatch, "WarningNoExpectedRSMatch", "Valid retained shared secrets availabe but no matches found - must verify SAS"},
        {0, NULL, NULL},
    };

    if (!zrtpfilter_warning_type) {
        zrtpfilter_warning_type =
            g_enum_register_static ("GstZrtpWarning", zrtpfilter_warning);
    }
    return zrtpfilter_warning_type;
}

#define GST_TYPE_ZRTP_FILTER_SEVERE (gst_zrtp_filter_severe_get_type())
static GType
gst_zrtp_filter_severe_get_type(void)
{
    static GType zrtpfilter_severe_type = 0;
    static const GEnumValue zrtpfilter_severe[] = {
        {zrtp_SevereHelloHMACFailed,  "SevereHelloHMACFailed", "Hash HMAC check of Hello failed!"},
        {zrtp_SevereCommitHMACFailed, "SevereCommitHMACFailed", "Hash HMAC check of Commit failed"},
        {zrtp_SevereDH1HMACFailed,    "SevereDH1HMACFailed", "Hash HMAC check of DHPart1 failed!"},
        {zrtp_SevereDH2HMACFailed,    "SevereDH2HMACFailed", "Hash HMAC check of DHPart2 failed!"},
        {zrtp_SevereCannotSend,       "SevereCannotSend", "Cannot send data - connection or peer down?"},
        {zrtp_SevereProtocolError,    "SevereProtocolError", "Internal protocol error occured!"},
        {zrtp_SevereNoTimer,          "SevereNoTimer", "Cannot start a timer - internal resources exhausted?"},
        {zrtp_SevereTooMuchRetries,   "SevereTooMuchRetries", "Too much retries during ZRTP negotiation - connection or peer down?"},
        {0, NULL, NULL},
    };

    if (!zrtpfilter_severe_type) {
        zrtpfilter_severe_type =
            g_enum_register_static ("GstZrtpSevere", zrtpfilter_severe);
    }
    return zrtpfilter_severe_type;
}

#define GST_TYPE_ZRTP_FILTER_ERROR (gst_zrtp_filter_error_get_type())
static GType
gst_zrtp_filter_error_get_type(void)
{
    static GType zrtpfilter_error_type = 0;
    static const GEnumValue zrtpfilter_error[] = {
        {zrtp_MalformedPacket,   "MalformedPacket", "Malformed packet (CRC OK, but wrong structure)"},
        {zrtp_CriticalSWError,   "CriticalSWError", "Critical software error"},
        {zrtp_UnsuppZRTPVersion, "UnsuppZRTPVersion", "Unsupported ZRTP version"},
        {zrtp_HelloCompMismatch, "HelloCompMismatch", "Hello components mismatch"},
        {zrtp_UnsuppHashType,    "UnsuppHashType", "Hash type not supported"},
        {zrtp_UnsuppCiphertype,  "UnsuppCiphertype", "Cipher type not supported"},
        {zrtp_UnsuppPKExchange,  "UnsuppPKExchange", "Public key exchange not supported"},
        {zrtp_UnsuppSRTPAuthTag, "UnsuppSRTPAuthTag", "SRTP auth. tag not supported"},
        {zrtp_UnsuppSASScheme,   "UnsuppSASScheme", "SAS scheme not supported"},
        {zrtp_NoSharedSecret,    "NoSharedSecret", "No shared secret available, DH mode required"},
        {zrtp_DHErrorWrongPV,    "DHErrorWrongPV", "DH Error: bad pvi or pvr ( == 1, 0, or p-1)"},
        {zrtp_DHErrorWrongHVI,   "DHErrorWrongHVI", "DH Error: hvi != hashed data"},
        {zrtp_SASuntrustedMiTM,  "SASuntrustedMiTM", "Received relayed SAS from untrusted MiTM"},
        {zrtp_ConfirmHMACWrong,  "ConfirmHMACWrong", "Auth. Error: Bad Confirm pkt HMAC"},
        {zrtp_NonceReused,       "NonceReused", "Nonce reuse"},
        {zrtp_EqualZIDHello,     "EqualZIDHello", "Equal ZIDs in Hello"},
        {zrtp_GoCleatNotAllowed, "GoCleatNotAllowed", "GoClear packet received, but not allowed"},
        {0, NULL, NULL},
    };

    if (!zrtpfilter_error_type) {
        zrtpfilter_error_type =
            g_enum_register_static ("GstZrtpError", zrtpfilter_error);
    }
    return zrtpfilter_error_type;
}

#define GST_TYPE_ZRTP_FILTER_ENROLLMENT (gst_zrtp_filter_enrollment_get_type())
static GType
gst_zrtp_filter_enrollment_get_type(void)
{
    static GType zrtpfilter_enrollment_type = 0;
    static const GEnumValue zrtpfilter_enrollment[] = {
        {zrtp_EnrollmentRequest,  "EnrollmentRequest", "Aks user to confirm or deny an Enrollemnt request"},
        {zrtp_EnrollmentCanceled, "EnrollmentCanceled", "User did not confirm the PBX enrollement"},
        {zrtp_EnrollmentFailed,   "EnrollmentFailed", "Enrollment process failed, no PBX secret available"},
        {zrtp_EnrollmentOk,       "EnrollmentOk", "Enrollment process for this PBX was ok"},
        {0, NULL, NULL},
    };

    if (!zrtpfilter_enrollment_type) {
        zrtpfilter_enrollment_type =
            g_enum_register_static ("GstZrtpInfoEnrollment", zrtpfilter_enrollment);
    }
    return zrtpfilter_enrollment_type;
}

/* Marshalls two gint to application signal callback */
static void
marshal_VOID__INT_INT(GClosure * closure, GValue * return_value,
                       guint n_param_values, const GValue* param_values, gpointer invocation_hint,
                       gpointer marshal_data)
{
    typedef void (*marshalfunc_VOID__MINIOBJECT_OBJECT) (gpointer obj, gint arg1, gint arg2, gpointer data2);

    register marshalfunc_VOID__MINIOBJECT_OBJECT callback;
    register GCClosure *cc = (GCClosure *) closure;
    register gpointer data1, data2;

    g_return_if_fail (n_param_values == 3);

    if (G_CCLOSURE_SWAP_DATA(closure)) {
        data1 = closure->data;
        data2 = g_value_peek_pointer(param_values + 0);
    } else {
        data1 = g_value_peek_pointer(param_values + 0);
        data2 = closure->data;
    }
    callback = (marshalfunc_VOID__MINIOBJECT_OBJECT)(marshal_data ? marshal_data : cc->callback);

    callback (data1, g_value_get_int(param_values + 1), g_value_get_int(param_values + 2), data2);
}

/* Marshalls one gchar* and one gint to application signal callback */
static void
marshal_VOID__STRING_INT(GClosure * closure, GValue * return_value,
                          guint n_param_values, const GValue * param_values, gpointer invocation_hint,
                          gpointer marshal_data)
{
    typedef void (*marshalfunc_VOID__MINIOBJECT_OBJECT) (gpointer obj, const gchar* arg1, gint arg2, gpointer data2);

    register marshalfunc_VOID__MINIOBJECT_OBJECT callback;
    register GCClosure *cc = (GCClosure *) closure;
    register gpointer data1, data2;

    g_return_if_fail (n_param_values == 3);

    if (G_CCLOSURE_SWAP_DATA(closure)) {
        data1 = closure->data;
        data2 = g_value_peek_pointer(param_values + 0);
    } else {
        data1 = g_value_peek_pointer(param_values + 0);
        data2 = closure->data;
    }
    callback = (marshalfunc_VOID__MINIOBJECT_OBJECT)(marshal_data ? marshal_data : cc->callback);

    callback (data1, g_value_get_string(param_values + 1), g_value_get_int(param_values + 2), data2);
}

/* GObject vmethod implementations */

static void
gst_zrtp_filter_base_init(gpointer gclass)
{
    GstElementClass *element_class = GST_ELEMENT_CLASS (gclass);

    gst_element_class_set_details_simple(element_class,
                                         "ZrtpFilter",
                                         "Filter/Network/ZRTP",
                                         "Enable RTP streams to use ZRTP and SRTP/SRTCP.",
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
gst_zrtp_filter_class_init(GstZrtpFilterClass * klass)
{
    GObjectClass *gobject_class;
    //    GstElementClass *gstelement_class;

    gobject_class = (GObjectClass *) klass;
    //    gstelement_class = (GstElementClass *) klass;

    gobject_class->finalize = gst_zrtp_filter_finalize;
    gobject_class->set_property = gst_zrtp_filter_set_property;
    gobject_class->get_property = gst_zrtp_filter_get_property;

    g_object_class_install_property(gobject_class, PROP_ENABLE_ZRTP,
                                    g_param_spec_boolean ("enable", "Enable", "Enable ZRTP processing.",
                                                          FALSE, G_PARAM_READWRITE));

    g_object_class_install_property(gobject_class, PROP_LOCAL_SSRC,
                                    g_param_spec_uint("local-ssrc", "LocalSSRC", "Set local SSRC if it cannot be determined.",
                                                      1, 0xffffffff, 1, G_PARAM_READWRITE));

    g_object_class_install_property(gobject_class, PROP_MITM_MODE,
                                    g_param_spec_boolean ("set-mitm-mode", "MITM", "Enable MitM (PBX) enrollment.",
                                                          FALSE, G_PARAM_READWRITE));

    g_object_class_install_property(gobject_class, PROP_CACHE_NAME,
                                    g_param_spec_string("cache-name", "Cache", "ZRTP cache filename.",
                                                        NULL, G_PARAM_READWRITE));

    g_object_class_install_property(gobject_class, PROP_INITALIZE,
                                    g_param_spec_boolean ("initialize", "Initialize", "Initialize ZRTP engine and enable.",
                                                          FALSE, G_PARAM_WRITABLE));

    g_object_class_install_property(gobject_class, PROP_START,
                                    g_param_spec_boolean ("start", "Start", "Start ZRTP engine explicitly.",
                                                          FALSE, G_PARAM_READWRITE));

    /* Don't stop manually, will be done when GStreamer calls the finalize function.'
     *    g_object_class_install_property (gobject_class, PROP_STOP,
     *                                    g_param_spec_boolean ("stop", "Stop", "Stop ZRTP engine explicitly.",
     *                                    FALSE, G_PARAM_WRITABLE));
     */

    g_object_class_install_property(gobject_class, PROP_MULTI_PARAM,
                                    g_param_spec_boxed("multi-param", "Multiparam", "Get or Set multi-stream parameters.",
                                                       G_TYPE_BYTE_ARRAY, G_PARAM_READWRITE));

    g_object_class_install_property(gobject_class, PROP_IS_MULTI,
                                    g_param_spec_boolean("is-multi", "IsMulti", "Check if this is a multi-stream session.",
                                                         FALSE, G_PARAM_READABLE));

    g_object_class_install_property(gobject_class, PROP_MULTI_AVAILABLE,
                                    g_param_spec_boolean("multi-available", "MultiAvailable",
                                                         "Check if master session supports multi-stream mode.",
                                                          FALSE, G_PARAM_READABLE));
    /**
     * GstZrtpFilter::status:
     * @zrtpfilter: the zrtpfilter instance
     * @severity: the sevrity of the status information
     * @subcode: information subcode
     *
     * This signal gets emitted when ZRTP calls send_info callback.
     */
    gst_zrtp_filter_signals[SIGNAL_STATUS] =
        g_signal_new("status", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, status), NULL, NULL,
                     marshal_VOID__INT_INT, G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_INT);

    /**
     * GstZrtpFilter::sas:
     * @zrtpfilter: the zrtpfilter instance
     * @sas: the sas string
     * @verified: boolean, true if SAS was verfied in a previous session, false otherwise
     *
     * This signal gets emitted when ZRTP calls secretsOn callback.
     */
    gst_zrtp_filter_signals[SIGNAL_SAS] =
        g_signal_new("sas", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, sas), NULL, NULL,
                     marshal_VOID__STRING_INT, G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_INT);

    /**
     * GstZrtpFilter::algorithm:
     * @zrtpfilter: the zrtpfilter instance
     * @algorithm: the human readabe negotiated enryption and authentication algorithms
     *
     * This signal gets emitted when ZRTP calls secretsOn callback.
     *
     * The the application receives a copy of the @algorithm string and may use @g_free to
     * deallocate it.
     */
    gst_zrtp_filter_signals[SIGNAL_ALGORITHM] =
        g_signal_new("algorithm", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, algorithm), NULL, NULL,
                     g_cclosure_marshal_VOID__STRING, G_TYPE_NONE, 1, G_TYPE_STRING);

    /**
     * GstZrtpFilter::secure-off:
     * @zrtpfilter: the zrtpfilter instance
     *
     * This signal gets emitted when ZRTP calls secretsOff callback.
     */
    gst_zrtp_filter_signals[SIGNAL_SECURITY_OFF] =
        g_signal_new("security-off", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, secureOff), NULL, NULL,
                     g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);

    /**
     * GstZrtpFilter::negotiation:
     * @zrtpfilter: the zrtpfilter instance
     * @severity: the sevrity of the fail information
     * @subcode: information subcode
     *
     * This signal gets emitted when ZRTP calls negotiation failed callback.
     */
    gst_zrtp_filter_signals[SIGNAL_NEGOTIATION] =
        g_signal_new("negotiation", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET(GstZrtpFilterClass, negotiation), NULL, NULL,
                     marshal_VOID__INT_INT, G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_INT);

    /**
     * GstZrtpFilter::not-supported:
     * @zrtpfilter: the zrtpfilter instance
     *
     * This signal gets emitted when ZRTP calls not supported callback.
     */
    gst_zrtp_filter_signals[SIGNAL_NOT_SUPP] =
        g_signal_new("not-supported", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, noSupport), NULL, NULL,
                     g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);

    /**
     * GstZrtpFilter::ask-enrollment:
     * @zrtpfilter: the zrtpfilter instance
     * @info: the enrollment information code
     *
     * This signal gets emitted when ZRTP calls askEnrollment callback.
     */
    gst_zrtp_filter_signals[SIGNAL_ASK_ENROLL] =
        g_signal_new("ask-enrollment", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, askEnroll), NULL, NULL,
                     g_cclosure_marshal_VOID__INT, G_TYPE_NONE, 1, G_TYPE_INT);

    /**
     * GstZrtpFilter::inform-enrollment:
     * @zrtpfilter: the zrtpfilter instance
     * @info: the enrollment information code
     *
     * This signal gets emitted when ZRTP calls informEnrollment callback.
     */
    gst_zrtp_filter_signals[SIGNAL_INFORM_ENROLL] =
        g_signal_new("inform-enrollment", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                     G_STRUCT_OFFSET (GstZrtpFilterClass, askEnroll), NULL, NULL,
                     g_cclosure_marshal_VOID__INT, G_TYPE_NONE, 1, G_TYPE_INT);

    /*
     * GstZrtpFilter::sign-sas: - not yet implemented
     * @zrtpfilter: the zrtpfilter instance
     * @info: the enrollment information code
     *
     * This signal gets emitted when ZRTP calls signSAS callback.
     */
    //   gst_zrtp_filter_signals[SIGNAL_SIGN_SAS] =
    //       g_signal_new("sign-sas", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
    //       G_STRUCT_OFFSET (GstZrtpFilterClass, signSas), NULL, NULL,
    //       g_cclosure_marshal_VOID__INT, G_TYPE_NONE, 1, G_TYPE_uint8_pointer);

    /*
     * GstZrtpFilter::check-sas-sign: - not yet implemented
     * @zrtpfilter: the zrtpfilter instance
     * @info: the enrollment information code
     *
     * This signal gets emitted when ZRTP calls sasCheckSign callback.
     */
    //   gst_zrtp_filter_signals[SIGNAL_CHECK_SAS_SIGN] =
    //       g_signal_new("check-sas-sign", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
    //       G_STRUCT_OFFSET (GstZrtpFilterClass, sasCheckSign), NULL, NULL,
    //       g_cclosure_marshal_VOID__INT, G_TYPE_NONE, 1, G_TYPE_uint8_pointer);

    /* Install enums and make them available for applications */
    GST_TYPE_ZRTP_FILTER_MSG_SEVERITY;
    GST_TYPE_ZRTP_FILTER_INFO;
    GST_TYPE_ZRTP_FILTER_WARNING;
    GST_TYPE_ZRTP_FILTER_SEVERE;
    GST_TYPE_ZRTP_FILTER_ERROR;
    GST_TYPE_ZRTP_FILTER_ENROLLMENT;
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_zrtp_filter_init(GstZrtpFilter * filter, GstZrtpFilterClass * gclass)
{
    /* At first initialize the non-pad stuff  */
    /* Create the empty wrapper */
    filter->zrtpCtx = zrtp_CreateWrapper();
    filter->clientIdString = clientId;    /* Set standard name */
    filter->cacheName = NULL;
    filter->zrtpSeq = 1;                  /* TODO: randomize */
    filter->zrtpMutex = g_mutex_new();
    filter->sysclock = gst_system_clock_obtain();
    filter->mitmMode = FALSE;
    filter->localSSRC = 0;
    filter->peerSSRC = 0;
    filter->gotMultiParam = FALSE;

    // TODO: caps setter, getter checks?
    // Initialize the receive (upstream) RTP data path
    filter->recv_rtp_sink = gst_pad_new_from_static_template (&zrtp_recv_rtp_sink_template, "recv_rtp_sink");
    //     gst_pad_set_setcaps_function (filter->recv_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    //     gst_pad_set_getcaps_function (filter->recv_rtp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function   (filter->recv_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtp_up));

    filter->recv_rtp_src = gst_pad_new_from_static_template (&zrtp_recv_rtp_src_template, "recv_rtp_src");
    //     gst_pad_set_getcaps_function (filter->recv_rtp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtp_src);


    // Initialize the send (downstream) RTP data path
    filter->send_rtp_sink = gst_pad_new_from_static_template (&zrtp_send_rtp_sink_template, "send_rtp_sink");
    //     gst_pad_set_setcaps_function (filter->send_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    //     gst_pad_set_getcaps_function (filter->send_rtp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function   (filter->send_rtp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtp_down));

    filter->send_rtp_src = gst_pad_new_from_static_template (&zrtp_send_rtp_src_template, "send_rtp_src");
    //     gst_pad_set_getcaps_function (filter->send_rtp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtp_src);


    // Initialize the receive (upstream) RTCP data path
    filter->recv_rtcp_sink = gst_pad_new_from_static_template (&zrtp_recv_rtcp_sink_template, "recv_rtcp_sink");
    //     gst_pad_set_setcaps_function (filter->recv_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    //     gst_pad_set_getcaps_function (filter->recv_rtcp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function (filter->recv_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtcp_up));

    filter->recv_rtcp_src = gst_pad_new_from_static_template (&zrtp_recv_rtcp_src_template, "recv_rtcp_src");
    //     gst_pad_set_getcaps_function (filter->recv_rtcp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtcp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->recv_rtcp_src);


    // Initialize the send (downstream) RTCP data path
    filter->send_rtcp_sink = gst_pad_new_from_static_template (&zrtp_send_rtcp_sink_template, "send_rtcp_sink");
    //    gst_pad_set_setcaps_function (filter->send_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_set_caps));
    //    gst_pad_set_getcaps_function (filter->send_rtcp_sink, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function (filter->send_rtcp_sink, GST_DEBUG_FUNCPTR(gst_zrtp_filter_chain_rtcp_down));

    filter->send_rtcp_src = gst_pad_new_from_static_template (&zrtp_send_rtcp_src_template, "send_rtcp_src");
    //    gst_pad_set_getcaps_function (filter->send_rtcp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtcp_sink);
    gst_element_add_pad (GST_ELEMENT (filter), filter->send_rtcp_src);
}

static void
gst_zrtp_filter_set_property (GObject* object, guint prop_id,
                              const GValue* value, GParamSpec* pspec)
{
    GstZrtpFilter *filter = GST_ZRTPFILTER (object);
    GByteArray* mspArr;

    GST_DEBUG_OBJECT(filter, "set property '%s', value: ", g_param_spec_get_name(pspec));
    switch (prop_id) {
    case PROP_ENABLE_ZRTP:
        filter->enableZrtp = g_value_get_boolean(value);
        GST_DEBUG("%s", filter->enableZrtp ? "TRUE" : "FALSE");
        break;
    case PROP_LOCAL_SSRC:
        filter->localSSRC = g_value_get_uint(value);
        GST_DEBUG("%x", filter->localSSRC);
        break;
    case PROP_MITM_MODE:
        filter->mitmMode = g_value_get_boolean(value);
        GST_DEBUG("%s", filter->mitmMode ? "TRUE" : "FALSE");
        break;
    case PROP_CACHE_NAME:
        g_free(filter->cacheName);
        filter->cacheName = g_value_dup_string(value);
        GST_DEBUG("'%s'", filter->cacheName);
        break;
    case PROP_INITALIZE:
        GST_DEBUG("%s", g_value_get_boolean(value) ? "TRUE" : "FALSE");
        zrtp_initialize(filter, filter->cacheName, g_value_get_boolean(value));
        break;
    case PROP_START:
        zrtp_filter_startZrtp(filter);
        break;
        /*        case PROP_STOP:
                  zrtp_filter_stopZrtp(filter);
                  break;
        */
    case PROP_MULTI_PARAM:
        mspArr = g_value_get_boxed(value);
        if (filter->gotMultiParam) {
            GST_ERROR_OBJECT(filter, "Cannot set multi-stream parameters on master ZRTP session.\n");
            break;
        }
        GST_DEBUG("%p, length: %d", mspArr->data, mspArr->len);
        zrtp_setMultiStrParams(filter->zrtpCtx, (char*)mspArr->data, mspArr->len);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
gst_zrtp_filter_get_property (GObject * object, guint prop_id,
                              GValue * value, GParamSpec * pspec)
{
    GstZrtpFilter *filter = GST_ZRTPFILTER (object);
    gint32 len;
    gpointer param;

    switch (prop_id) {
    case PROP_ENABLE_ZRTP:
        g_value_set_boolean(value, filter->enableZrtp);
        break;
    case PROP_LOCAL_SSRC:
        g_value_set_uint(value, filter->localSSRC);
        break;
    case PROP_MITM_MODE:
        g_value_set_boolean(value, filter->mitmMode);
        break;
    case PROP_CACHE_NAME:
        g_value_set_string(value, filter->cacheName);
        break;
    case PROP_START:
        g_value_set_boolean(value, filter->started);
        break;
    case PROP_MULTI_PARAM:
        param = zrtp_getMultiStrParams(filter->zrtpCtx, &len);
        if (param == NULL) {
            g_value_set_boxed(value, g_byte_array_new()); /* Return empty byte array */
            break;
        }
        /* Copy data to a Glib byte array to enable the application to simply free the data */
        GByteArray* mspArr = g_byte_array_sized_new(len);
        mspArr = g_byte_array_append(mspArr, param, len);
        g_value_set_boxed(value, mspArr);
        filter->gotMultiParam = TRUE;

        /* Free the param data after copying - data was allocated by C wrapper with malloc*/
        free(param);
        break;
    case PROP_IS_MULTI:
        g_value_set_boolean(value, zrtp_isMultiStream(filter->zrtpCtx));
        break;
    case PROP_MULTI_AVAILABLE:
        g_value_set_boolean(value, zrtp_isMultiStreamAvailable(filter->zrtpCtx));
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

/* GstElement vmethod implementations */

/* this function handles the link with other elements */
// static gboolean
// gst_zrtp_filter_set_caps (GstPad * pad, GstCaps * caps)
// {
//    GstZrtpFilter *filter;
//     GstPad *otherpad;
// 
//     filter = GST_ZRTPFILTER (gst_pad_get_parent (pad));
//     otherpad = (pad == filter->srcpad) ? filter->sinkpad : filter->srcpad;
//     gst_object_unref (filter);
// 
//     return gst_pad_set_caps (otherpad, caps);
//     return 1;
// }

/* chain function - rtp upstream, from UDP to RTP session
 * this function does the actual processing
 */
static GstFlowReturn
gst_zrtp_filter_chain_rtp_up (GstPad* pad, GstBuffer* gstBuf)
{
    GstZrtpFilter* zrtp = GST_ZRTPFILTER (GST_OBJECT_PARENT (pad));
    guint8* buffer = GST_BUFFER_DATA(gstBuf);
    GstFlowReturn rc = GST_FLOW_ERROR;

    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xf0) != 0x10) {
        //  Could be real RTP, check if we are in secure mode
        if (zrtp->srtpReceive == NULL) {
            GST_TRACE_OBJECT(zrtp, "Received upstream RTP buffer - SRTP inactive");
            rc = gst_pad_push (zrtp->recv_rtp_src, gstBuf);
        } else {
            rc = zsrtp_unprotect(zrtp->srtpReceive, gstBuf);
            GST_TRACE_OBJECT(zrtp, "Decrypted upstream SRTP buffer, result: %d", rc);
            if (rc == 1) {
                zrtp->unprotect++;
                rc = gst_pad_push (zrtp->recv_rtp_src, gstBuf);
                zrtp->unprotect_err = 0;
            } else {
                if (rc == -1) {
                    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_STATUS], 0, zrtp_Warning, zrtp_WarningSRTPauthError);
                } else {
                    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_STATUS], 0, zrtp_Warning, zrtp_WarningSRTPreplayError);
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
    if (zrtp->enableZrtp && zrtp->zrtpCtx != NULL) {
        // Get CRC value into crc (see above how to compute the offset)
        gint temp = GST_BUFFER_SIZE(gstBuf) - CRC_SIZE;
        guint32 crc = *(guint32*)(buffer + temp);
        crc = g_ntohl(crc);

        GST_TRACE_OBJECT(zrtp, "Check received upstream packet - possibly ZRTP");
        guint32 magic = *(guint32*)(buffer + 4);
        magic = g_ntohl(magic);

        // Check if it is really a ZRTP packet, return, no further processing
        if (magic != ZRTP_MAGIC || zrtp->zrtpCtx == NULL) {
            gst_buffer_unref(gstBuf);
            return GST_FLOW_ERROR;
        }

        if (!zrtp_CheckCksum(buffer, temp, crc)) {
            GST_WARNING_OBJECT(zrtp, "Upstream ZRTP packet found, CRC check failed.");
            g_signal_emit (zrtp, gst_zrtp_filter_signals[SIGNAL_STATUS], 0, zrtp_Warning, zrtp_WarningCRCmismatch);
            return rc;
        }
        GST_TRACE_OBJECT(zrtp, "Upstream ZRTP packet found, CRC ok.");
        // cover the case if the other party sends _only_ ZRTP packets at the
        // beginning of a session. Start ZRTP in this case as well.
        if (!zrtp->started) {
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
        zrtp_processZrtpMessage(zrtp->zrtpCtx, zrtpMsg, zrtp->peerSSRC, GST_BUFFER_SIZE(gstBuf));
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
    GstZrtpFilter *zrtp = GST_ZRTPFILTER(GST_OBJECT_PARENT(pad));
    GstFlowReturn rc = GST_FLOW_ERROR;

    if (zrtp->localSSRC == 0) {
        zrtp->localSSRC = gst_rtp_buffer_get_ssrc(gstBuf);   /* Learn own SSRC before starting ZRTP */
    }

    if (!zrtp->started && zrtp->enableZrtp) {
        zrtp_filter_startZrtp(zrtp);
    }

    if (zrtp->srtpSend == NULL) {
        GST_TRACE_OBJECT(zrtp, "Received downstream RTP buffer - SRTP inactive");
        rc = gst_pad_push (zrtp->send_rtp_src, gstBuf);
    }
    else {
        rc = zsrtp_protect(zrtp->srtpSend, gstBuf);
        GST_TRACE_OBJECT(zrtp, "Encrypted downstream RTP buffer, result: %d", rc);
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
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (GST_OBJECT_PARENT(pad));
    GstFlowReturn rc = GST_FLOW_ERROR;

    if (zrtp->srtcpReceive == NULL) {
        GST_TRACE_OBJECT(zrtp, "Received upstream RTCP buffer - SRTP inactive");
        rc = gst_pad_push (zrtp->recv_rtcp_src, gstBuf);
    }
    else {
        rc = zsrtp_unprotectCtrl(zrtp->srtcpReceive, gstBuf);
        GST_TRACE_OBJECT(zrtp, "Decrypted upstream SRTCP buffer, result: %d", rc);
        if (rc == 1)
            rc = gst_pad_push(zrtp->recv_rtcp_src, gstBuf);
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

    if (zrtp->srtcpSend == NULL) {
        GST_TRACE_OBJECT(zrtp, "Received downstream RTCP buffer - SRTP inactive");
        rc = gst_pad_push (zrtp->send_rtcp_src, gstBuf);
    }
    else {
        rc = zsrtp_protectCtrl(zrtp->srtcpSend, gstBuf);
        GST_TRACE_OBJECT(zrtp, "Encrypted downstream RTCP buffer, result: %d", rc);

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
gboolean zrtp_initialize(GstZrtpFilter* filter, const gchar* zidFilename, gboolean autoEnable)
{
    zrtp_initializeZrtpEngine(filter->zrtpCtx, &c_callbacks, filter->clientIdString,
                              zidFilename, filter, filter->mitmMode);
    filter->enableZrtp = autoEnable;
    return TRUE;
}

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
    g_free(zrtp->cacheName);
    g_object_unref(zrtp->sysclock);
    g_mutex_free (zrtp->zrtpMutex);
}

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

    GST_TRACE_OBJECT(zrtp, "Send ZRTP packet downstream.");
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

    g_signal_emit (zrtp, gst_zrtp_filter_signals[SIGNAL_STATUS], 0, severity, subCode);
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
        GST_DEBUG_OBJECT(zrtp, "Activate SRTP/SRTCP for sender (downstream).");
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
        } else {
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
        GST_DEBUG_OBJECT(zrtp, "Activate SRTP/SRTCP for receiver (upstream).");
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
        } else {
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

    if (part == ForSender) {
        zsrtp_DestroyWrapper(zrtp->srtpSend);
        zsrtp_DestroyWrapperCtrl(zrtp->srtcpSend);
        zrtp->srtpSend = NULL;
        zrtp->srtcpSend = NULL;
    }
    if (part == ForReceiver) {
        zsrtp_DestroyWrapper(zrtp->srtpReceive);
        zsrtp_DestroyWrapperCtrl(zrtp->srtcpReceive);
        zrtp->srtpReceive = NULL;
        zrtp->srtcpReceive = NULL;
    }
    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_SECURITY_OFF], 0);
}

static
void zrtp_srtpSecretsOn(ZrtpContext* ctx, char* c, char* s, int32_t verified)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    gchar* galgo = g_strdup(c); /* duplicate to make if available for g_free() */
    g_signal_emit (zrtp, gst_zrtp_filter_signals[SIGNAL_ALGORITHM], 0, galgo, verified);

    if (strlen(s) > 0) {
        gchar* gsas = g_strdup(s);
        g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_SAS], 0, gsas, verified);
    }
}

static
void zrtp_handleGoClear(ZrtpContext* ctx)
{
}

static
void zrtp_zrtpNegotiationFailed(ZrtpContext* ctx, int32_t severity, int32_t subCode)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);
    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_NEGOTIATION], 0, severity, subCode);
}

static
void zrtp_zrtpNotSuppOther(ZrtpContext* ctx)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_NOT_SUPP], 0);
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

    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_ASK_ENROLL], 0, info);
}

static
void zrtp_zrtpInformEnrollment(ZrtpContext* ctx, int32_t info)
{
    GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);

    g_signal_emit(zrtp, gst_zrtp_filter_signals[SIGNAL_INFORM_ENROLL], 0, info);
}

static
void zrtp_signSAS(ZrtpContext* ctx, guint8* sas)
{
    //     GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);
    //
    //     g_print ("signSAS: sas: %s\n", sas);
    //
}

static
gint32 zrtp_checkSASSignature(ZrtpContext* ctx, guint8* sas)
{
    //     GstZrtpFilter *zrtp = GST_ZRTPFILTER (ctx->userData);
    //
    //     g_print ("checkAsaSignature: sas: %s\n", sas);
    return 0;
}
