/*
 * GStreamer
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
 * SECTION:element-zrtptester
 *
 * zrtptester - a quick hacked plugin to use in ZRTP tests.
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * gst-launch -v -m ....
 * ]|
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>

#include <gst/gst.h>
#include <gst/rtp/gstrtpbuffer.h>

#include "gstzrtptester.h"

GST_DEBUG_CATEGORY_STATIC (gst_zrtptester_debug);
#define GST_CAT_DEFAULT gst_zrtptester_debug

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
static GstStaticPadTemplate sink_factory = GST_STATIC_PAD_TEMPLATE ("sink",
                                                                    GST_PAD_SINK,
                                                                    GST_PAD_ALWAYS,
                                                                    GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate src_factory = GST_STATIC_PAD_TEMPLATE ("src",
                                                                   GST_PAD_SRC,
                                                                   GST_PAD_ALWAYS,
                                                                   GST_STATIC_CAPS ("ANY")
);

static GstStaticPadTemplate rtcp_src = GST_STATIC_PAD_TEMPLATE ("rtcp_src",
                                                                GST_PAD_SRC,
                                                                GST_PAD_ALWAYS,
                                                                GST_STATIC_CAPS_ANY);


GST_BOILERPLATE (Gstzrtptester, gst_zrtptester, GstElement, GST_TYPE_ELEMENT);

static void gst_zrtptester_finalize (GObject * object);
static void gst_zrtptester_set_property (GObject * object, guint prop_id, const GValue * value, GParamSpec * pspec);
static void gst_zrtptester_get_property (GObject * object, guint prop_id, GValue * value, GParamSpec * pspec);

static gboolean gst_zrtptester_set_caps (GstPad * pad, GstCaps * caps);
static GstFlowReturn gst_zrtptester_chain (GstPad * pad, GstBuffer * buf);

static GstStateChangeReturn gst_zrtptester_change_state (GstElement * element, GstStateChange transition);

/* GObject vmethod implementations */

static void
gst_zrtptester_base_init (gpointer gclass)
{
    GstElementClass *element_class = GST_ELEMENT_CLASS (gclass);

    gst_element_class_set_details_simple(element_class,
                                         "Zrtptester",
                                         "Filter/Network/ZRTP",
                                         "Testdriver plugin for ZRTP",
                                         "Werner Dittmann <Werner.Dittmann@t-online.de>");
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&src_factory));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&sink_factory));
    gst_element_class_add_pad_template (element_class, gst_static_pad_template_get (&rtcp_src));
}

/* initialize the zrtptester's class */
static void
gst_zrtptester_class_init (GstzrtptesterClass * klass)
{
    GObjectClass *gobject_class;
    GstElementClass *gstelement_class;

    gobject_class = (GObjectClass *) klass;
    gstelement_class = (GstElementClass *) klass;

    gobject_class->finalize = gst_zrtptester_finalize;
    gobject_class->set_property = gst_zrtptester_set_property;
    gobject_class->get_property = gst_zrtptester_get_property;

    g_object_class_install_property (gobject_class, PROP_SILENT,
                                     g_param_spec_boolean ("silent", "Silent", "Produce verbose output ?",
                                     FALSE, G_PARAM_READWRITE));
    gstelement_class->change_state = GST_DEBUG_FUNCPTR (gst_zrtptester_change_state);
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_zrtptester_init (Gstzrtptester * filter,
                     GstzrtptesterClass * gclass)
{
    filter->zrtpMutex = g_mutex_new();
    filter->start = FALSE;
    filter->sysclock = gst_system_clock_obtain();

    filter->sinkpad = gst_pad_new_from_static_template (&sink_factory, "sink");
    gst_pad_set_setcaps_function (filter->sinkpad,
                                  GST_DEBUG_FUNCPTR(gst_zrtptester_set_caps));
    gst_pad_set_getcaps_function (filter->sinkpad,
                                  GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));
    gst_pad_set_chain_function (filter->sinkpad,
                                GST_DEBUG_FUNCPTR(gst_zrtptester_chain));

    filter->srcpad = gst_pad_new_from_static_template (&src_factory, "src");
    gst_pad_set_getcaps_function (filter->srcpad,
                                  GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->sinkpad);
    gst_element_add_pad (GST_ELEMENT (filter), filter->srcpad);

    filter->rtcp_src = gst_pad_new_from_static_template (&rtcp_src, "rtcp_src");
    gst_pad_set_getcaps_function (filter->rtcp_src, GST_DEBUG_FUNCPTR(gst_pad_proxy_getcaps));

    gst_element_add_pad (GST_ELEMENT (filter), filter->rtcp_src);

    filter->silent = FALSE;
    filter->thread_stopped = TRUE;
    filter->thread = NULL;
    filter->counter = 0;
}

static void
gst_zrtptester_set_property (GObject * object, guint prop_id,
                             const GValue * value, GParamSpec * pspec)
{
    Gstzrtptester *filter = GST_ZRTPTESTER (object);

    switch (prop_id) {
        case PROP_SILENT:
            filter->silent = g_value_get_boolean (value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static void
gst_zrtptester_get_property (GObject * object, guint prop_id,
                             GValue * value, GParamSpec * pspec)
{
    Gstzrtptester *filter = GST_ZRTPTESTER (object);

    switch (prop_id) {
        case PROP_SILENT:
            g_value_set_boolean (value, filter->silent);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static void
gst_zrtptester_finalize (GObject* object)
{
    Gstzrtptester *zrtp = GST_ZRTPTESTER(object);
    GST_ZRTP_LOCK(zrtp);                /* Just to make sure no other thread has it */
    GST_ZRTP_UNLOCK(zrtp);
    g_mutex_free (zrtp->zrtpMutex);

    g_object_unref(zrtp->sysclock);
    G_OBJECT_CLASS (parent_class)->finalize (object);
}

/* GstElement vmethod implementations */

/* this function handles the link with other elements */
static gboolean
gst_zrtptester_set_caps (GstPad * pad, GstCaps * caps)
{
    Gstzrtptester *filter;
    GstPad *otherpad;

    filter = GST_ZRTPTESTER (gst_pad_get_parent (pad));
    otherpad = (pad == filter->srcpad) ? filter->sinkpad : filter->srcpad;
    gst_object_unref (filter);

    return gst_pad_set_caps (otherpad, caps);
}

/* chain function
 * this function does the actual processing
 */
static GstFlowReturn
gst_zrtptester_chain (GstPad * pad, GstBuffer * buf)
{
    Gstzrtptester *filter;

    filter = GST_ZRTPTESTER (GST_OBJECT_PARENT (pad));

    if (filter->silent == FALSE)
        g_print ("I'm plugged, therefore I'm in.\n");

    /* just push out the incoming buffer without touching it */
    return gst_pad_push (filter->srcpad, buf);
}


/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
zrtptester_init (GstPlugin * zrtptester)
{
    /* debug category for fltering log messages
     *
     * exchange the string 'Template zrtptester' with your description
     */
    GST_DEBUG_CATEGORY_INIT (gst_zrtptester_debug, "zrtptester",
                             0, "Template zrtptester");

    return gst_element_register (zrtptester, "zrtptester", GST_RANK_NONE,
                                 GST_TYPE_ZRTPTESTER);
}

/* PACKAGE: this is usually set by autotools depending on some _INIT macro
 * in configure.ac and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use autotools to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "myfirstzrtptester"
#endif

/* gstreamer looks for this structure to register zrtptesters
 *
 * exchange the string 'Template zrtptester' with your zrtptester description
 */
GST_PLUGIN_DEFINE (
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    "zrtptester",
    "Template zrtptester",
    zrtptester_init,
    VERSION,
    "LGPL",
    "GStreamer",
    "http://gstreamer.net/"
)
// BYE packet has empty RR; 20: SDES header plus SDES chunk; 16: BYE RTCP packet, length: 44 bytes
static gchar bye[] = {0x80, 0xc9, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, // RR - sender SSRC 0x1234
                      0x81, 0xca, 0x00, 0x04,                         // SDES with CNAME AAAAAA
                      0x01, 0x02, 0x03, 0x04, 0x01, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                      0x00, 0x00, 0x00, 0x00,
                      0x81, 0xcb, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04,       // BYE with reason CCCCCC
                      0x06, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x00};

// Only RR packet plus SDES, length: 28
static gchar rr[] = {0x80, 0xc9, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, // empty RR, sender SSRC 0x1234
                     0x81, 0xca, 0x00, 0x04,                         // SDES with CNAME AAAAAA
                     0x01, 0x02, 0x03, 0x04, 0x01, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                     0x00, 0x00, 0x00, 0x00};

static gchar* data1 = "1234567890-";
static gchar* data2 = "-0987654321";

static void
zrtptester_thread (Gstzrtptester* zrtptester)
{
    GstClockID id;
    GstClockTime current_time;
    GstClockTime next_timeout;
    GstClock *sysclock;

    GST_DEBUG_OBJECT (zrtptester, "entering zrtptester thread");

    sysclock = zrtptester->sysclock;
    current_time = gst_clock_get_time(sysclock);

    GST_DEBUG_OBJECT (zrtptester, "starting at %" GST_TIME_FORMAT, GST_TIME_ARGS (current_time));

    GstBuffer* buf = gst_buffer_new_and_alloc(28);
    memcpy(GST_BUFFER_DATA(buf), rr, 28);
    gst_pad_push(zrtptester->rtcp_src, buf);

    while (zrtptester->start && zrtptester->counter < 10) {
        /* get initial estimate */
        next_timeout = current_time + 200 * GST_MSECOND;

        GST_DEBUG_OBJECT (zrtptester, "next send time %" GST_TIME_FORMAT, GST_TIME_ARGS (next_timeout));

       /* leave if no more timeouts, the session ended */
        if (next_timeout == GST_CLOCK_TIME_NONE)
            break;

        id = zrtptester->clockId = gst_clock_new_single_shot_id (sysclock, next_timeout);
        gst_clock_id_wait (id, NULL);

        gst_clock_id_unref (id);
        zrtptester->clockId = NULL;

        if (!zrtptester->start)
            break;

        GstBuffer* buf = gst_rtp_buffer_new_allocate (12, 0, 0);
        gst_rtp_buffer_set_ssrc(buf, 0x01020304);
        gst_rtp_buffer_set_seq(buf, zrtptester->counter + 1);

        gpointer payl = gst_rtp_buffer_get_payload (buf);

        gchar* cp = ((zrtptester->counter & 1) == 1) ? data2 : data1;
        memcpy(payl, cp, 12);

        GST_INFO("Sending RTP packet");
        gst_pad_push (zrtptester->srcpad, buf);

        /* update current time */
        current_time = gst_clock_get_time (sysclock);

        zrtptester->counter++;
    }
    GST_DEBUG("sending RTCP BYE");

    buf = gst_buffer_new_and_alloc(44);
    memcpy(GST_BUFFER_DATA(buf), bye, 44);
    gst_pad_push(zrtptester->rtcp_src, buf);

    buf = gst_rtp_buffer_new_allocate (12, 0, 0);
    gst_rtp_buffer_set_ssrc(buf, 0x01020304);
    gst_rtp_buffer_set_seq(buf, zrtptester->counter + 1);
    memcpy(gst_rtp_buffer_get_payload (buf), "exit", 5);
    gst_pad_push(zrtptester->srcpad, buf);

    id = zrtptester->clockId = gst_clock_new_single_shot_id (sysclock, gst_clock_get_time (sysclock) + 2000 * GST_MSECOND);
    gst_clock_id_wait (id, NULL);

    gst_clock_id_unref (id);
    zrtptester->clockId = NULL;

    gst_pad_push_event(zrtptester->srcpad, gst_event_new_eos ());
    gst_pad_push_event(zrtptester->rtcp_src, gst_event_new_eos ());
    GST_DEBUG_OBJECT (zrtptester, "leaving zrtptester thread");

    /* mark the thread as stopped now */
    zrtptester->thread_stopped = TRUE;
}

static void
stop_zrtptester_thread (Gstzrtptester* zrtptester)
{
    GST_DEBUG_OBJECT (zrtptester, "stopping zrtptester thread");

    zrtptester->start = FALSE;
    if (zrtptester->clockId)
        gst_clock_id_unschedule (zrtptester->clockId);

}

static void
join_zrtptester_thread (Gstzrtptester* zrtptester)
{
  /* don't try to join when we have no thread */
  if (zrtptester->thread != NULL) {
    GST_DEBUG_OBJECT (zrtptester, "joining zrtptester thread");

    g_thread_join (zrtptester->thread);

    /* after the join, take the lock and clear the thread structure. The caller
     * is supposed to not concurrently call start and join. */
    zrtptester->thread = NULL;
  }
}

static gboolean
start_zrtptester_thread (Gstzrtptester* zrtptester)
{
    GError *error = NULL;
    gboolean res;

    GST_DEBUG_OBJECT (zrtptester, "starting zrtptester thread");

    zrtptester->start = TRUE;
    if (zrtptester->thread_stopped) {
        /* if the thread stopped, and we still have a handle to the thread, join it
         * now. We can safely join with the lock held, the thread will not take it
         * anymore. */
        if (zrtptester->thread)
            g_thread_join (zrtptester->thread);
        /* only create a new thread if the old one was stopped. Otherwise we can
         * just reuse the currently running one. */
#if !GLIB_CHECK_VERSION (2, 31, 0)
        zrtptester->thread = g_thread_create ((GThreadFunc) zrtptester_thread, zrtptester, TRUE, &error);
#else
        zrtptester->thread = g_thread_try_new ("zrtptester-thread",
                                               (GThreadFunc) zrtptester_thread, zrtptester, &error);
#endif
        zrtptester->thread_stopped = FALSE;
    }

    if (error != NULL) {
        res = FALSE;
        GST_DEBUG_OBJECT (zrtptester, "failed to start thread, %s", error->message);
        g_error_free (error);
    } else {
        res = TRUE;
    }
    return res;
}

static GstStateChangeReturn
gst_zrtptester_change_state (GstElement * element, GstStateChange transition)
{
    GstStateChangeReturn res;
    Gstzrtptester* zrtptester = GST_ZRTPTESTER (element);

    switch (transition) {
        case GST_STATE_CHANGE_NULL_TO_READY:
            break;
        case GST_STATE_CHANGE_READY_TO_PAUSED:
            break;
        case GST_STATE_CHANGE_PAUSED_TO_PLAYING:
            break;
        case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
        case GST_STATE_CHANGE_PAUSED_TO_READY:
            /* no need to join yet, we might want to continue later. Also, the
             * dataflow could block downstream so that a join could just block
             * forever. */
            stop_zrtptester_thread (zrtptester);
            break;
        default:
            break;
    }

    res = parent_class->change_state (element, transition);

    switch (transition) {
        case GST_STATE_CHANGE_PAUSED_TO_PLAYING:
            if (!start_zrtptester_thread (zrtptester))
                goto failed_thread;
            break;
        case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
            break;
        case GST_STATE_CHANGE_PAUSED_TO_READY:
            /* downstream is now releasing the dataflow and we can join. */
            join_zrtptester_thread (zrtptester);
            break;
        case GST_STATE_CHANGE_READY_TO_NULL:
            break;
        default:
            break;
    }
    return res;

    /* ERRORS */
    failed_thread:
    {
        return GST_STATE_CHANGE_FAILURE;
    }
}

