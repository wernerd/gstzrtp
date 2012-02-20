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
typedef struct _GstZrtpPrivate     GstZrtpPrivate;

struct _GstZrtpFilter
{
    GstElement element;

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
