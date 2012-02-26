#include <gst/gst.h>
#include <glib.h>
#include <sys/socket.h>

/*
 * This small demo program shows how to setup and use a RTP - ZRTP send pipeline.
 *
 * The ZRTP protocol always needs a sender and receiver to run the key negotiation protocol.
 *
 * In GStreamer gst-launch pipe notation:
 *
 * gst-launch me/gstZrtp/build/src zrtpfilter name=zrtp cache-name=gstZrtpCache.dat initialize=true \
 *   udpsrc port=5004 ! zrtp.recv_rtp_sink zrtp.recv_rtp_src ! fakesink dump=true sync=false async=false \
 *   udpsrc port=5005 ! zrtp.recv_rtcp_sink zrtp.recv_rtcp_src ! fakesink dump=true sync=false async=false \
 *   zrtptester name=testsrc \
 *   testsrc.src ! zrtp.send_rtp_sink zrtp.send_rtp_src ! udpsink clients="127.0.0.1:5002" sync=false async=false \
 *   testsrc.rtcp_src ! zrtp.send_rtcp_sink zrtp.send_rtcp_src ! udpsink clients="127.0.0.1:5003" sync=false async=false
 *
 * This filter receives data from its peer at ports 5004 and 5005 (RTP and RTCP) and
 * sends data to its peer on ports 5002 and 5003 (RTP and RTCP). The filter uses the RTP
 * ports (5002 and 5004) to send and receive ZRTP data. ZRTP does not use the RTCP ports.
 * 
 * IMPORTANT: the ZRTP property "initialize" should be always the last property to set
 *            for the zrtpfilter otherwise the ZRTP cache file name is not recognized.
 *            Processing the initialize property also checks and opens the ZRTP cache. If
 *            the cache name property is not set the ZRTP filter uses the default
 *            file name "$HOME/.GNUccRTP.zid"
 */

static gboolean
bus_call (GstBus     *bus,
          GstMessage *msg,
          gpointer    data)
{
    GMainLoop *loop = (GMainLoop *) data;

    switch (GST_MESSAGE_TYPE (msg)) {

        case GST_MESSAGE_EOS:
            g_print ("End of stream\n");
            g_main_loop_quit (loop);
            break;

        case GST_MESSAGE_ERROR: {
            gchar  *debug;
            GError *error;

            gst_message_parse_error (msg, &error, &debug);
            g_free (debug);

            g_printerr ("Error: %s\n", error->message);
            g_error_free (error);

            g_main_loop_quit (loop);
            break;
        }
        default:
            break;
    }

    return TRUE;
}

const char* InfoCodes[] =
{
    "EMPTY",
    "Hello received, preparing a Commit",
    "Commit: Generated a public DH key",
    "Responder: Commit received, preparing DHPart1",
    "DH1Part: Generated a public DH key",
    "Initiator: DHPart1 received, preparing DHPart2",
    "Responder: DHPart2 received, preparing Confirm1",
    "Initiator: Confirm1 received, preparing Confirm2",
    "Responder: Confirm2 received, preparing Conf2Ack",
    "At least one retained secrets matches - security OK",
    "Entered secure state",
    "No more security for this session"
};

/**
 * Sub-codes for Warning
 */
const char* WarningCodes [] =
{
    "EMPTY",
    "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096",
    "Received a GoClear message",
    "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096",
    "No retained shared secrets available - must verify SAS",
    "Internal ZRTP packet checksum mismatch - packet dropped",
    "Dropping packet because SRTP authentication failed!",
    "Dropping packet because SRTP replay check failed!",
    "Valid retained shared secrets availabe but no matches found - must verify SAS"
};

/**
 * Sub-codes for Severe
 */
const char* SevereCodes[] =
{
    "EMPTY",
    "Hash HMAC check of Hello failed!",
    "Hash HMAC check of Commit failed!",
    "Hash HMAC check of DHPart1 failed!",
    "Hash HMAC check of DHPart2 failed!",
    "Cannot send data - connection or peer down?",
    "Internal protocol error occured!",
    "Cannot start a timer - internal resources exhausted?",
    "Too much retries during ZRTP negotiation - connection or peer down?"
};

/* TODO: Check if we can / shall use glib ENUM type for the severity part?
 */
enum zrtp_MessageSeverity {
    zrtp_Info = 1,                      /*!< Just an info message */
    zrtp_Warning,                       /*!< A Warning message - security can be established */
    zrtp_Severe,                        /*!< Severe error, security will not be established */
    zrtp_ZrtpError                      /*!< ZRTP error, security will not be established  */
};



static void
zrtp_statusInfo (GstElement *element, gint severity, gint subCode, gpointer data)  {
    switch (severity) {
        case zrtp_Info:
            g_print("ZRTP status info message: %s\n", InfoCodes[subCode]);
            break;

        case zrtp_Warning:
            g_print("ZRTP status warning message: %s\n", WarningCodes[subCode]);
            break;

        case zrtp_Severe:
            g_print("ZRTP status severe message: %s\n", SevereCodes[subCode]);
            break;

        case zrtp_ZrtpError:
            g_print("ZRTP Error: severity: %d, subcode: %x\n", severity, subCode*-1);
            break;
    }
}

static void
zrtp_negotiationFail (GstElement *element, gint severity, gint subCode, gpointer data)  {
    g_print("ZRTP status severe message: %s\n", SevereCodes[subCode]);
}

static void
zrtp_sas (GstElement *element, gchar* sas, gint verified, gpointer data)  {

    g_print("zrtpSend got SAS code: %s, verified status: %d\n", sas, verified);
}

static void
zrtp_algorithm(GstElement *element, gchar* algorithms, gpointer data)  {

    g_print("zrtpSend negotiated algorithms: %s\n", algorithms);
}

static void
zrtp_securityOff(GstElement *element, gpointer data)  {

    g_print("zrtpSend: security switched off.\n");
}

static void
zrtp_notSupported(GstElement *element, gpointer data)  {

    g_print("zrtpSend: other peer does not support ZRTP.\n");
}

int
main (int   argc,
      char *argv[])
{
    GMainLoop *loop;

    GstElement *rtpPipe,
                *udpRtpRecv, *udpRtcpRecv, *udpRtpSend, *udpRtcpSend,
                *zrtp, *sinkRtp, *sinkRtcp,
                *tstSrc;
    GstBus *bus;

    /* Initialisation */
    gst_init (&argc, &argv);

    loop = g_main_loop_new (NULL, FALSE);

    /* Create gstreamer elements */
    rtpPipe  = gst_pipeline_new ("rtp-recv");

    udpRtpRecv  = gst_element_factory_make("udpsrc", "udp-rtp-recv");
    udpRtcpRecv = gst_element_factory_make("udpsrc", "udp-rtcp-recv");

    udpRtpSend  = gst_element_factory_make("udpsink", "udp-rtp-send");
    udpRtcpSend = gst_element_factory_make("udpsink", "udp-rtcp-send");

    zrtp        = gst_element_factory_make("zrtpfilter", "ZRTP");

    sinkRtp     = gst_element_factory_make("fakesink", "rtp-sink");
    sinkRtcp    = gst_element_factory_make("fakesink", "rtcp-sink");

    tstSrc      = gst_element_factory_make("zrtptester", "testsrc");

    if (!rtpPipe || !udpRtpRecv || !udpRtcpRecv || !udpRtpSend || !zrtp || !sinkRtp || !sinkRtcp ||
        !tstSrc) {
        g_printerr ("One element could not be created. Exiting.\n");
        return -1;
    }

//     GType ty = g_type_from_name("GstFakeSinkStateError");
//     gpointer tyClass = g_type_class_peek(ty);
//     g_print("Type: %d, name: %s, pointer: %p\n", ty, g_type_name(ty), tyClass);

//     gst_debug_set_threshold_for_name ("zrtpfilter", GST_LEVEL_TRACE);
    gst_debug_set_threshold_for_name ("zrtptester", GST_LEVEL_INFO);

    /* Setup for RTP and RTCP receiver, even port is RTP, odd port is RTCP */
    g_object_set(G_OBJECT(udpRtpRecv), "port", 5004, NULL);
    g_object_set(G_OBJECT(udpRtcpRecv), "port", 5005, NULL);

    /* UDP sink sends RTP to loclhost, port 5002 */
    g_object_set(G_OBJECT(udpRtpSend), "clients", "127.0.0.1:5002", NULL);
    g_object_set(G_OBJECT(udpRtpSend), "sync", FALSE, NULL);
    g_object_set(G_OBJECT(udpRtpSend), "async", FALSE, NULL);

    /* UDP sink sends RTCP to loclhost, port 5003 */
    g_object_set(G_OBJECT(udpRtcpSend), "clients", "127.0.0.1:5003", NULL);
    g_object_set(G_OBJECT(udpRtcpSend), "sync", FALSE, NULL);
    g_object_set(G_OBJECT(udpRtcpSend), "async", FALSE, NULL);

    /* Setup the RTP and RTCP sinks (fakesinks) after the ZRTP filter */
    g_object_set(G_OBJECT(sinkRtp), "sync", FALSE, NULL);
    g_object_set(G_OBJECT(sinkRtp), "async", FALSE, NULL);
    g_object_set(G_OBJECT(sinkRtp), "dump", TRUE, NULL);

    g_object_set(G_OBJECT(sinkRtcp), "sync", FALSE, NULL);
    g_object_set(G_OBJECT(sinkRtcp), "async", FALSE, NULL);
    g_object_set(G_OBJECT(sinkRtcp), "dump", TRUE, NULL);

    /* Set the ZRTP cache name and initialize ZRTP with autosense mode ON
     */
    g_object_set(G_OBJECT(zrtp), "cache-name", "gstZrtpCacheSend.dat", NULL);
    g_object_set(G_OBJECT(zrtp), "initialize", TRUE, NULL);

    /* we add a message handler */
    bus = gst_pipeline_get_bus(GST_PIPELINE(rtpPipe));
    gst_bus_add_watch(bus, bus_call, loop);
    gst_object_unref(bus);

    /* Set up the pipeline, we add all elements into the pipeline */
    gst_bin_add_many(GST_BIN(rtpPipe), udpRtpRecv, udpRtcpRecv, zrtp, sinkRtp, sinkRtcp, udpRtpSend,
                     udpRtcpSend, tstSrc, NULL);

    /* setup the RTP and RTCP receiver and the sender for ZRTP communication */
    gst_element_link_pads(udpRtpRecv, "src", zrtp, "recv_rtp_sink");
    gst_element_link_pads(zrtp, "recv_rtp_src", sinkRtp, "sink");

    gst_element_link_pads(udpRtcpRecv, "src", zrtp, "recv_rtcp_sink");
    gst_element_link_pads(zrtp, "recv_rtcp_src", sinkRtcp, "sink");

    gst_element_link_pads(tstSrc, "src", zrtp, "send_rtp_sink");
    gst_element_link_pads(zrtp, "send_rtp_src", udpRtpSend, "sink");

    gst_element_link_pads(tstSrc, "rtcp_src", zrtp, "send_rtcp_sink");
    gst_element_link_pads(zrtp, "send_rtcp_src", udpRtcpSend, "sink");

    /* Connect the ZRTP callback (signal) functions.*/
    g_signal_connect (zrtp, "status",        G_CALLBACK(zrtp_statusInfo), zrtp);
    g_signal_connect (zrtp, "sas",           G_CALLBACK(zrtp_sas), zrtp);
    g_signal_connect (zrtp, "algorithm",     G_CALLBACK(zrtp_algorithm), zrtp);
    g_signal_connect (zrtp, "negotiation",   G_CALLBACK(zrtp_negotiationFail), zrtp);
    g_signal_connect (zrtp, "security-off",  G_CALLBACK(zrtp_securityOff), zrtp);
    g_signal_connect (zrtp, "not-supported", G_CALLBACK(zrtp_notSupported), zrtp);

    g_print("Starting ZRTP send pipeline\n");
    gst_element_set_state(rtpPipe, GST_STATE_PLAYING);

    g_print("Sending...\n");
    g_main_loop_run (loop);

    g_print("Exit main loop\n");
    gst_element_set_state(rtpPipe, GST_STATE_NULL);

    g_print ("Deleting ZRTP pipe\n");
    gst_object_unref(GST_OBJECT(rtpPipe));

    return 0;
}


