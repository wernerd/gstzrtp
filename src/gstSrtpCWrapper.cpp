/*
    This file implements the ZRTP SRTP C-to-C++ wrapper.
    Copyright (C) 2010  Werner Dittmann

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <CryptoContext.h>
#include <CryptoContextCtrl.h>

#include <gst/gst.h>
#include <gst/rtp/gstrtpbuffer.h>

#include <string.h>

#include <gstSrtpCWrapper.h>
// #include <arpa/inet.h>

ZsrtpContext* zsrtp_CreateWrapper(uint32_t ssrc, int32_t roc,
                                  int64_t  keyDerivRate,
                                  const  int32_t ealg,
                                  const  int32_t aalg,
                                  uint8_t* masterKey,
                                  int32_t  masterKeyLength,
                                  uint8_t* masterSalt,
                                  int32_t  masterSaltLength,
                                  int32_t  ekeyl,
                                  int32_t  akeyl,
                                  int32_t  skeyl,
                                  int32_t  tagLength)
{
    ZsrtpContext* zc = new ZsrtpContext;
    zc->srtp = new CryptoContext(ssrc, roc, keyDerivRate, ealg, aalg,
                                 masterKey, masterKeyLength, masterSalt,
                                 masterSaltLength, ekeyl, akeyl, skeyl,
                                 tagLength);
    return zc;
}

void zsrtp_DestroyWrapper (ZsrtpContext* ctx)
{

    if (ctx == NULL)
        return;

    delete ctx->srtp;
    ctx->srtp = NULL;

    delete ctx;
}

#if GST_CHECK_VERSION(1,0,0)
static void
resize_buffer(GstBuffer *buffer, gsize len)
{
    gsize size, maxsize, offset;

    size = gst_buffer_get_sizes(buffer, &offset, &maxsize);
    g_return_if_fail(len > size);

    if (len < maxsize) {
        gst_buffer_resize(buffer, offset, len);
    } else {
        GstMemory *mem = gst_allocator_alloc (NULL, len - size, NULL);
        gst_buffer_append_memory(buffer, mem);
    }
}
#endif

gint32 zsrtp_protect(ZsrtpContext* ctx, GstBuffer* gstBuf)
{
    CryptoContext* pcc = ctx->srtp;
#if GST_CHECK_VERSION(1,0,0)
    GstMapInfo mapInfo;
    GstRTPBuffer rtp = {NULL, };
    GstRTPBuffer *rtpBuf = &rtp;

    gint32  length = gst_buffer_get_size(gstBuf);

    gst_rtp_buffer_map(gstBuf, GST_MAP_READ, &rtp);
#else
    GstBuffer *rtpBuf = gstBuf;

    /* Need original length of original RTP packet */
    gint32  length = GST_BUFFER_SIZE(gstBuf);
#endif

    int32_t payloadlen;
    uint16_t seqnum;
    uint32_t ssrc;


    if (pcc == NULL) {
        return 0;
    }
    /* Get payloadlen including all padding - padding is also encrypted */
    payloadlen = length - gst_rtp_buffer_get_header_len(rtpBuf);

    seqnum = gst_rtp_buffer_get_seq(rtpBuf);
    uint64_t index = ((uint64_t)pcc->getRoc() << 16) | (uint64_t)seqnum;

    ssrc = gst_rtp_buffer_get_ssrc(rtpBuf);

    /* SRTP stores authentication after the RTP data, thus we need to reallocate some data.
     * The gst_rtp_buffer_set_packet_len(...) function clears the padding bit - this is not
     * correct when performing SRTP encryption. Thus re-allocate manually, mainly copied from
     * gst_rtp_buffer_set_packet_len(...) function.
     * */
    gint newLength = length + pcc->getTagLength();

#if GST_CHECK_VERSION(1,0,0)
    gst_rtp_buffer_unmap(&rtp);

    resize_buffer(gstBuf, newLength);

    g_warn_if_fail(gst_buffer_map(gstBuf, &mapInfo, (GstMapFlags) GST_MAP_READWRITE));
    gst_rtp_buffer_map(gstBuf, (GstMapFlags) GST_MAP_READWRITE, &rtp);
    guint8* data = mapInfo.data;
#else
    guint8* data = reinterpret_cast<uint8_t*>(g_realloc (GST_BUFFER_MALLOCDATA(gstBuf), newLength));
    GST_BUFFER_MALLOCDATA(gstBuf) = data;
    GST_BUFFER_DATA(gstBuf) = data;
    GST_BUFFER_SIZE(gstBuf) = newLength;
#endif

    /* Encrypt the packet */
    uint8_t* payl = reinterpret_cast<uint8_t*>(gst_rtp_buffer_get_payload(rtpBuf));
    pcc->srtpEncrypt(data, payl, payloadlen, index, ssrc);

    // NO MKI support yet - here we assume MKI is zero. To build in MKI
    // take MKI length into account when storing the authentication tag.

    /* Compute MAC and store at end of RTP packet data */
    pcc->srtpAuthenticate(data, length, pcc->getRoc(), data+length);


    /* Update the ROC if necessary */
    if (seqnum == 0xFFFF ) {
        pcc->setRoc(pcc->getRoc() + 1);
    }
#if GST_CHECK_VERSION(1,0,0)
    gst_rtp_buffer_unmap(&rtp);
    gst_buffer_unmap(gstBuf, &mapInfo);
#endif
    return 1;
}

int32_t zsrtp_unprotect(ZsrtpContext* ctx, GstBuffer* gstBuf)
{
    CryptoContext* pcc = ctx->srtp;
#if GST_CHECK_VERSION(1,0,0)
    GstMapInfo mapInfo;
    GstRTPBuffer rtp = { NULL, };
    GstRTPBuffer *rtpBuf = &rtp;

    g_warn_if_fail(gst_buffer_map(gstBuf, &mapInfo, (GstMapFlags) GST_MAP_READWRITE));
    gst_rtp_buffer_map(gstBuf, (GstMapFlags) GST_MAP_READWRITE, &rtp);

    gint32  length = mapInfo.size;
    guint8  *bufdata = mapInfo.data;
#else
    GstBuffer *rtpBuf = gstBuf;

    /* Need length of original SRTP packet */
    gint32  length = GST_BUFFER_SIZE(gstBuf);
    guint8  *bufdata = GST_BUFFER_DATA(gstBuf);
#endif

    /* In case of SRTP the padding length field is also encrypted, thus
     * it gives a wrong length. Compute payload length without padding:
     * SRTP packet length minus header length.
     */
    gint32 payloadlen = length - gst_rtp_buffer_get_header_len(rtpBuf);

    uint16_t seqnum;
    uint32_t ssrc;

    if (pcc == NULL) {
        return 0;
    }
    /*
     * This is the setting of the packet data when we come to this
     * point:
     *
     * length:      complete length of received SRTP data
     * payloadlen:  length of data excluding header size
     *
     * Because this is an SRTP packet we need to adjust some values here.
     * The SRTP MKI and authentication data is always at the end of a
     * packet. Thus compute the position of this data.
     */
    uint32_t srtpDataIndex = length - (pcc->getTagLength() + pcc->getMkiLength());

    /* Adjust the total RTP packet length. */
    length = srtpDataIndex;

    /* Adjust payload length also */
    payloadlen -= pcc->getTagLength() + pcc->getMkiLength();

    /* Get address of SRTP authentication tag */
    uint8_t* tag = bufdata + srtpDataIndex + pcc->getMkiLength();

    /* Need sequence number for Replay control and crypto index */
    seqnum = gst_rtp_buffer_get_seq(rtpBuf);
    if (!pcc->checkReplay(seqnum)) {
        return -2;
    }
    /* Guess the index */
    uint64_t guessedIndex = pcc->guessIndex(seqnum);

    uint32_t guessedRoc = guessedIndex >> 16;
    uint8_t  mac[20];

    /* Compute MAC over SRTP buffer and compare with tag in SRTP packet */
    pcc->srtpAuthenticate(bufdata, length, guessedRoc, mac);
    if (memcmp(tag, mac, pcc->getTagLength()) != 0) {
        return -1;
    }

    /* Decrypt the content */
    ssrc = gst_rtp_buffer_get_ssrc(rtpBuf);
    uint8_t* payl = reinterpret_cast<uint8_t*>(gst_rtp_buffer_get_payload(rtpBuf));
    pcc->srtpEncrypt(bufdata, payl, payloadlen, guessedIndex, ssrc);
#if GST_CHECK_VERSION(1,0,0)
    mapInfo.size = srtpDataIndex;
#else
    GST_BUFFER_SIZE(gstBuf) = srtpDataIndex;
#endif

    /* Update the Crypto-context */
    pcc->update(seqnum);

#if GST_CHECK_VERSION(1,0,0)
    gst_rtp_buffer_unmap(&rtp);
    gst_buffer_unmap(gstBuf, &mapInfo);
#endif
    return 1;
}

void zsrtp_newCryptoContextForSSRC(ZsrtpContext* ctx, uint32_t ssrc,
                                   int32_t roc, int64_t keyDerivRate)
{
    CryptoContext* newCrypto = ctx->srtp->newCryptoContextForSSRC(ssrc, 0, 0L);
    ctx->srtp = newCrypto;
}

void zsrtp_deriveSrtpKeys(ZsrtpContext* ctx, uint64_t index)
{
    ctx->srtp->deriveSrtpKeys(index);
}


/*
 * Implement the wrapper for SRTCP crypto context
 */
ZsrtpContextCtrl* zsrtp_CreateWrapperCtrl( uint32_t ssrc,
                                           const  int32_t ealg,
                                           const  int32_t aalg,
                                           uint8_t* masterKey,
                                           int32_t  masterKeyLength,
                                           uint8_t* masterSalt,
                                           int32_t  masterSaltLength,
                                           int32_t  ekeyl,
                                           int32_t  akeyl,
                                           int32_t  skeyl,
                                           int32_t  tagLength )
{
    ZsrtpContextCtrl* zc = new ZsrtpContextCtrl;
    zc->srtcp = new CryptoContextCtrl(ssrc, ealg, aalg, masterKey, masterKeyLength, masterSalt,
                                      masterSaltLength, ekeyl, akeyl, skeyl, tagLength );

    zc->srtcpIndex = 0;
    return zc;
}


void zsrtp_DestroyWrapperCtrl (ZsrtpContextCtrl* ctx)
{
    if (ctx == NULL)
        return;

    delete ctx->srtcp;
    ctx->srtcp = NULL;

    delete ctx;
}

int32_t zsrtp_protectCtrl(ZsrtpContextCtrl* ctx, GstBuffer* gstBuf)
{
    CryptoContextCtrl* pcc = ctx->srtcp;
#if GST_CHECK_VERSION(1,0,0)
    GstMapInfo mapInfo;
#endif

    if (pcc == NULL) {
        return 0;
    }

#if GST_CHECK_VERSION(1,0,0)
    gint32 length = gst_buffer_get_size(gstBuf);
#else
    /* Need length of original RTP packet */
    gint32 length = GST_BUFFER_SIZE(gstBuf);
#endif

    /* SRTP stores authentication after the RTP data, thus we need to reallocate some data.
     * The gst_rtp_buffer_set_packet_len(...) function clears the padding bit - this is not
     * correct when performing SRTP encryption. Thus re-allocate manually, mainly copied from
     * gst_rtp_buffer_set_packet_len(...) function.
     * */
    gint32 newLength = length + pcc->getTagLength() + sizeof(uint32_t);

#if GST_CHECK_VERSION(1,0,0)
    resize_buffer(gstBuf, newLength);

    g_warn_if_fail(gst_buffer_map(gstBuf, &mapInfo, (GstMapFlags) GST_MAP_READWRITE));
    guint8* data = mapInfo.data;
#else
    guint8* data = reinterpret_cast<uint8_t*>(g_realloc (GST_BUFFER_MALLOCDATA(gstBuf), newLength));
    GST_BUFFER_MALLOCDATA(gstBuf) = data;
    GST_BUFFER_DATA(gstBuf) = data;
    GST_BUFFER_SIZE(gstBuf) = newLength;
#endif

    guint32 ssrc = *(reinterpret_cast<guint32*>(data + 4)); // always SSRC of sender
    ssrc = g_ntohl(ssrc);

    /* Encrypt the packet */
    pcc->srtcpEncrypt(data + 8, length - 8, ctx->srtcpIndex, ssrc);

    uint32_t encIndex = ctx->srtcpIndex | 0x80000000;  // set the E flag

    // Fill SRTCP index as last word
    uint32_t* ip = reinterpret_cast<uint32_t*>(data+length);
    *ip = g_htonl(encIndex);

    // NO MKI support yet - here we assume MKI is zero. To build in MKI
    // take MKI length into account when storing the authentication tag.

    // Compute MAC and store in packet after the SRTCP index field
    pcc->srtcpAuthenticate(data, length, encIndex,
                           data + length + sizeof(uint32_t));

    ctx->srtcpIndex++;
    ctx->srtcpIndex &= ~0x80000000;       // clear possible overflow

#if GST_CHECK_VERSION(1,0,0)
    gst_buffer_unmap(gstBuf, &mapInfo);
#endif
    return 1;
}

int32_t zsrtp_unprotectCtrl(ZsrtpContextCtrl* ctx, GstBuffer* gstBuf)
{
    CryptoContextCtrl* pcc = ctx->srtcp;
#if GST_CHECK_VERSION(1,0,0)
    GstMapInfo mapInfo;
#endif

    if (pcc == NULL) {
        return 0;
    }

#if GST_CHECK_VERSION(1,0,0)
    g_warn_if_fail(gst_buffer_map(gstBuf, &mapInfo, (GstMapFlags) GST_MAP_READWRITE));
    gint32 length = mapInfo.size;
    guint8 *bufdata = mapInfo.data;
#else
    /* Need length of original SRTP packet */
    gint32 length = GST_BUFFER_SIZE(gstBuf);
    guint8 *bufdata = GST_BUFFER_DATA(gstBuf);
#endif

    // Compute the total length of the payload
    int32_t payloadLen = length - (pcc->getTagLength() + pcc->getMkiLength() + 4);

    // point to the SRTCP index field just after the real payload
    const uint32_t* index = reinterpret_cast<uint32_t*>(bufdata + payloadLen);

    uint32_t encIndex = g_ntohl(*index);
    uint32_t remoteIndex = encIndex & ~0x80000000;    // index without Encryption flag

    if (!pcc->checkReplay(remoteIndex)) {
       return -2;
    }

    uint8_t mac[20];

    // Now get a pointer to the authentication tag field
    const uint8_t* tag = bufdata + (length - pcc->getTagLength());

    // Authenticate includes the index, but not MKI and not (obviously) the tag itself
    pcc->srtcpAuthenticate(bufdata, payloadLen, encIndex, mac);
    if (memcmp(tag, mac, pcc->getTagLength()) != 0) {
        return -1;
    }
    guint32 ssrc = *(reinterpret_cast<guint32*>(bufdata + 4)); // always SSRC of sender
    ssrc = g_ntohl(ssrc);

    // Decrypt the content, exclude the very first SRTCP header (fixed, 8 bytes)
    if (encIndex & 0x80000000)
        pcc->srtcpEncrypt(bufdata + 8,
                          payloadLen - 8, remoteIndex, ssrc);

    // Update the Crypto-context
    pcc->update(remoteIndex);
#if GST_CHECK_VERSION(1,0,0)
    mapInfo.size = payloadLen;
#else
    GST_BUFFER_SIZE(gstBuf) = payloadLen;
#endif

#if GST_CHECK_VERSION(1,0,0)
    gst_buffer_unmap(gstBuf, &mapInfo);
#endif
    return 1;
}

void zsrtp_newCryptoContextForSSRCCtrl(ZsrtpContextCtrl* ctx, uint32_t ssrc)
{
    CryptoContextCtrl* newCrypto = ctx->srtcp->newCryptoContextForSSRC(ssrc);
    ctx->srtcp = newCrypto;
}

void zsrtp_deriveSrtpKeysCtrl(ZsrtpContextCtrl* ctx)
{
    ctx->srtcp->deriveSrtcpKeys();
}



