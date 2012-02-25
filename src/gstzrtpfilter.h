/*
 * GStreamer
 * Copyright (C) 2005 Thomas Vander Stichele <thomas@apestaart.org>
 * Copyright (C) 2005 Ronald S. Bultje <rbultje@ronald.bitfreak.net>
 * Copyright (C) 2012 werner <<user@hostname.org>>
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

#ifndef __GST_ZRTPFILTER_H__
#define __GST_ZRTPFILTER_H__

#include <gst/gst.h>

#include <libzrtpcpp/ZrtpCWrapper.h>

#include "gstSrtpCWrapper.h"

G_BEGIN_DECLS

/* Ugly workaround: gtk-doc sees this but don't use it it actual
 * compile to avoid synchroinzation problems with libzrtpcpp includes.
 */
#if 0
/*
 * IMPORTANT: keep the following enums in synch with ZrtpCodes. We copy them here
 * to avoid any C++ header includes and defines. The protocol states are located
 * ZrtpStateClass.h .
 */
/**
 * zrtp_MessageSeverity:
 * @zrtp_Info: keeps the user informed about ongoing processing and
 *     security setup. The enumeration InfoCodes defines the subcodes.
 * @zrtp_Warning: is an information about some security issues, e.g. if
 *     an AES 256 encryption is request but only DH 3072 as public key scheme
 *     is supported. ZRTP will establish a secure session (SRTP). The
 *     enumeration WarningCodes defines the sub-codes.
 * @zrtp_Severe: is used if an error occured during ZRTP protocol usage.
 *     In case of <em>Severe</em> ZRTP will <b>not</b> establish a secure session.
 *     The enumeration SevereCodes defines the sub-codes.
 * @zrtp_ZrtpError: shows a ZRTP security problem. Refer to the enumeration
 *     ZrtpErrorCodes for sub-codes. GNU ZRTP of course will <b>not</b>
 *     establish a secure session.
 *
 * This enum defines the information message severity.
 *
 * The ZRTP implementation issues information messages to inform the user
 * about ongoing processing, unusual behavior, or alerts in case of severe
 * problems. Each main severity code a number of sub-codes exist that
 * specify the exact nature of the problem.
 *
 * An application gets message severity codes and the associated sub-codes
 * via the ZrtpUserCallback#showMessage method.
 *
 */
typedef enum {
    zrtp_Info = 1,
    zrtp_Warning,
    zrtp_Severe,
    zrtp_ZrtpError
} zrtp_MessageSeverity;

/**
 * zrtp_InfoCodes:
 * @zrtp_InfoHelloReceived: Hello received, preparing a Commit
 * @zrtp_InfoCommitDHGenerated: Commit: Generated a public DH key
 * @zrtp_InfoRespCommitReceived: Responder: Commit received, preparing DHPart1
 * @zrtp_InfoDH1DHGenerated: DH1Part: Generated a public DH key
 * @zrtp_InfoInitDH1Received: Initiator: DHPart1 received, preparing DHPart2
 * @zrtp_InfoRespDH2Received: Responder: DHPart2 received, preparing Confirm1
 * @zrtp_InfoInitConf1Received: Initiator: Confirm1 received, preparing Confirm2
 * @zrtp_InfoRespConf2Received: Responder: Confirm2 received, preparing Conf2Ack
 * @zrtp_InfoRSMatchFound: At least one retained secrets matches - forward security OK
 * @zrtp_InfoSecureStateOn: Entered secure state
 * @zrtp_InfoSecureStateOff: No more security for this session
 *
 * Sub-codes for Info
 */
typedef enum {
    zrtp_InfoHelloReceived = 1,
    zrtp_InfoCommitDHGenerated,
    zrtp_InfoRespCommitReceived,
    zrtp_InfoDH1DHGenerated,
    zrtp_InfoInitDH1Received,
    zrtp_InfoRespDH2Received,
    zrtp_InfoInitConf1Received,
    zrtp_InfoRespConf2Received,
    zrtp_InfoRSMatchFound,
    zrtp_InfoSecureStateOn,
    zrtp_InfoSecureStateOff
} zrtp_InfoCodes;

/**
 * zrtp_WarningCodes:
 * @zrtp_WarningDHAESmismatch: Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096
 * @zrtp_WarningGoClearReceived: Received a GoClear message
 * @zrtp_WarningDHShort: Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096
 * @zrtp_WarningNoRSMatch: No retained shared secrets available - must verify SAS
 * @zrtp_WarningCRCmismatch: Internal ZRTP packet checksum mismatch - packet dropped
 * @zrtp_WarningSRTPauthError: Dropping packet because SRTP authentication failed!
 * @zrtp_WarningSRTPreplayError: Dropping packet because SRTP replay check failed!
 * @zrtp_WarningNoExpectedRSMatch: Valid retained shared secrets availabe but no matches found - must verify SAS
 *
 * Sub-codes for Warning
 */
typedef enum {
    zrtp_WarningDHAESmismatch = 1,
    zrtp_WarningGoClearReceived,
    zrtp_WarningDHShort,
    zrtp_WarningNoRSMatch,
    zrtp_WarningCRCmismatch,
    zrtp_WarningSRTPauthError,
    zrtp_WarningSRTPreplayError,
    zrtp_WarningNoExpectedRSMatch
} zrtp_WarningCodes;

/**
 * zrtp_SevereCodes:
 * @zrtp_SevereHelloHMACFailed: Hash HMAC check of Hello failed!
 * @zrtp_SevereCommitHMACFailed: Hash HMAC check of Commit failed
 * @zrtp_SevereDH1HMACFailed: Hash HMAC check of DHPart1 failed!
 * @zrtp_SevereDH2HMACFailed: Hash HMAC check of DHPart2 failed!
 * @zrtp_SevereCannotSend: Cannot send data - connection or peer down?
 * @zrtp_SevereProtocolError: Internal protocol error occured!
 * @zrtp_SevereNoTimer: Cannot start a timer - internal resources exhausted?
 * @zrtp_SevereTooMuchRetries: Too much retries during ZRTP negotiation - connection or peer down?
 *
 * Sub-codes for Severe
 */
typedef enum {
    zrtp_SevereHelloHMACFailed = 1,
    zrtp_SevereCommitHMACFailed,
    zrtp_SevereDH1HMACFailed,
    zrtp_SevereDH2HMACFailed,
    zrtp_SevereCannotSend,
    zrtp_SevereProtocolError,
    zrtp_SevereNoTimer,
    zrtp_SevereTooMuchRetries
} zrtp_SevereCodes;

/**
 * zrtp_ZrtpErrorCodes:
 * @zrtp_MalformedPacket: Malformed packet (CRC OK, but wrong structure)
 * @zrtp_CriticalSWError: Critical software error
 * @zrtp_UnsuppZRTPVersion: Unsupported ZRTP version
 * @zrtp_HelloCompMismatch: Hello components mismatch
 * @zrtp_UnsuppHashType: Hash type not supported
 * @zrtp_UnsuppCiphertype: Cipher type not supported
 * @zrtp_UnsuppPKExchange: Public key exchange not supported
 * @zrtp_UnsuppSRTPAuthTag: SRTP auth. tag not supported
 * @zrtp_UnsuppSASScheme: SAS scheme not supported
 * @zrtp_NoSharedSecret: No shared secret available, DH mode required
 * @zrtp_DHErrorWrongPV: DH Error: bad pvi or pvr ( == 1, 0, or p-1)
 * @zrtp_DHErrorWrongHVI: DH Error: hvi != hashed data
 * @zrtp_SASuntrustedMiTM: Received relayed SAS from untrusted MiTM
 * @zrtp_ConfirmHMACWrong: Auth. Error: Bad Confirm pkt HMAC
 * @zrtp_NonceReused: Nonce reuse
 * @zrtp_EqualZIDHello: Equal ZIDs in Hello
 * @zrtp_GoCleatNotAllowed: GoClear packet received, but not allowed
 *
 * Error codes according to the ZRTP specification chapter 6.9
 *
 * GNU ZRTP uses these error codes in two ways: to fill the appropriate
 * field ing the ZRTP Error packet and as sub-code in
 * ZrtpUserCallback#showMessage(). GNU ZRTP uses thes error codes also
 * to report received Error packts, in this case the sub-codes are their
 * negative values.
 *
 * The enumeration member comments are copied from the ZRTP specification.
 */
typedef enum {
    zrtp_MalformedPacket =   0x10,
    zrtp_CriticalSWError =   0x20,
    zrtp_UnsuppZRTPVersion = 0x30,
    zrtp_HelloCompMismatch = 0x40,
    zrtp_UnsuppHashType =    0x51,
    zrtp_UnsuppCiphertype =  0x52,
    zrtp_UnsuppPKExchange =  0x53,
    zrtp_UnsuppSASScheme =   0x55,
    zrtp_NoSharedSecret =    0x56,
    zrtp_DHErrorWrongPV =    0x61,
    zrtp_DHErrorWrongHVI =   0x62,
    zrtp_SASuntrustedMiTM =  0x63,
    zrtp_ConfirmHMACWrong =  0x70,
    zrtp_NonceReused =       0x80,
    zrtp_EqualZIDHello =     0x90,
    zrtp_GoCleatNotAllowed = 0x100,
    /*< private >*/
    zrtp_IgnorePacket =      0x7fffffff
} zrtp_ZrtpErrorCodes;

/**
 * zrtp_InfoEnrollment:
 * @zrtp_EnrollmentRequest: Aks user to confirm or deny an Enrollemnt request
 * @zrtp_EnrollmentCanceled: User did not confirm the PBX enrollement
 * @zrtp_EnrollmentFailed: Enrollment process failed, no PBX secret available
 * @zrtp_EnrollmentOk: Enrollment process for this PBX was ok
 *
 * Information codes for the Enrollment user callbacks.
 */
typedef enum {
    zrtp_EnrollmentRequest,
    zrtp_EnrollmentCanceled,
    zrtp_EnrollmentFailed,
    zrtp_EnrollmentOk
} zrtp_InfoEnrollment;

#endif

/* #defines don't like whitespacey bits */
#define GST_TYPE_ZRTPFILTER \
(gst_zrtp_filter_get_type())
#define GST_ZRTPFILTER(obj) \
(G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_ZRTPFILTER,GstZrtpFilter))
#define GST_ZRTPFILTER_CLASS(klass) \
(G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_ZRTPFILTER,GstZrtpFilterClass))
#define GST_IS_ZRTPFILTER(obj) \
(G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_ZRTPFILTER))
#define GST_IS_ZRTPFILTER_CLASS(klass) \
(G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_ZRTPFILTER))

typedef struct _GstZrtpFilter      GstZrtpFilter;
typedef struct _GstZrtpFilterClass GstZrtpFilterClass;

/**
 * GstZrtpFilter:
 *
 * Opaque #GstZrtpFilter data structure.
 */
struct _GstZrtpFilter
{
    GstElement element;

    /*< private >*/
    GstPad  *recv_rtcp_sink;
    GstPad  *recv_rtcp_src;

    GstPad  *recv_rtp_sink;
    GstPad  *recv_rtp_src;

    GstPad  *send_rtcp_sink;
    GstPad  *send_rtcp_src;

    GstPad  *send_rtp_sink;
    GstPad  *send_rtp_src;

    guint64  protect;
    guint64  unprotect;
    gint32   unprotect_err;
    gint32   refcount;

    /* Clock for current ZRTP protocol timeout */
    GstClock   *sysclock;
    GstClockID clockId;

    GMutex* zrtpMutex;
    ZsrtpContext* srtpReceive;
    ZsrtpContext* srtpSend;
    ZsrtpContextCtrl* srtcpReceive;
    ZsrtpContextCtrl* srtcpSend;
    GstBuffer* sendBuffer;
    GstBuffer* sendBufferCtrl;
    GstBuffer* zrtpBuffer;
    gint32  sendBufferLen;
    guint32 peerSSRC;       /* stored in host order */
    guint32 localSSRC;      /* stored in host order */
    gchar* clientIdString;
    gchar* cacheName;
    gboolean gotMultiParam;
    ZrtpContext* zrtpCtx;
    guint16 zrtpSeq;
    gboolean enableZrtp;
    gboolean started;
    gboolean close_slave;
    gboolean mitmMode;

};

struct _GstZrtpFilterClass
{
    GstElementClass parent_class;

    /*< public >*/
    /* signals */
    void (*sendInfo)(GstElement *element, gint severity, gint subcode);
    void (*sas)(GstElement *element, gchar* sas, gint verified);
    void (*algorithm)(GstElement *element, gchar* algo);
    void (*secureOff)(GstElement *element);
    void (*negotiation)(GstElement *element, gint severity, gint subcode);
    void (*noSupport)(GstElement *element);
    void (*askEnroll)(GstElement *element, gint info);
    void (*informEnroll)(GstElement *element, gint info);
    void (*signSas)(GstElement *element, gchar* sasSign);
    void (*checkSasSign)(GstElement *element, gchar* checkSign);
};

GType gst_zrtp_filter_get_type (void);

G_END_DECLS

#endif /* __GST_ZRTPFILTER_H__ */
