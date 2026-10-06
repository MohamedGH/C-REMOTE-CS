/*
 * io_framing.c — Exact-Length Network Framing over Abstract Streams & OpenSSL
 *
 * Guarantees:
 * - Never assumes a single read() or SSL_read() returns the full header or payload.
 * - Handles fragmented reads (1 byte at a time) and partial writes cleanly.
 * - Validates payload_length bounds before reading payload bytes into memory.
 */
#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "protocol.h"

int sac_io_read_exact(sac_io_stream_t *stream, void *buf, size_t len) {
    if (!stream || !stream->read_some || (!buf && len > 0)) {
        return -1;
    }
    uint8_t *dst = (uint8_t *)buf;
    size_t total_read = 0;

    while (total_read < len) {
        ssize_t n = stream->read_some(stream->ctx, dst + total_read, len - total_read);
        if (n > 0) {
            total_read += (size_t)n;
        } else if (n == 0) {
            /* Clean EOF before expected bytes were received */
            return -1;
        } else {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
    }
    return 0;
}

int sac_io_write_all(sac_io_stream_t *stream, const void *buf, size_t len) {
    if (!stream || !stream->write_some || (!buf && len > 0)) {
        return -1;
    }
    const uint8_t *src = (const uint8_t *)buf;
    size_t total_written = 0;

    while (total_written < len) {
        ssize_t n = stream->write_some(stream->ctx, src + total_written, len - total_written);
        if (n > 0) {
            total_written += (size_t)n;
        } else if (n == 0) {
            return -1;
        } else {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
    }
    return 0;
}

int sac_write_request_frame(
    sac_io_stream_t *stream,
    uint8_t          opcode,
    uint32_t         seq,
    const char      *payload,
    size_t           payload_len
) {
    if (payload_len > SAC_MAX_PATH_LEN) {
        return -1;
    }
    sac_frame_header_t net_hdr = {
        .magic          = htonl(SAC_MAGIC_BYTES),
        .version        = SAC_PROTOCOL_VERSION,
        .opcode         = opcode,
        .sequence_num   = htonl(seq),
        .payload_length = htons((uint16_t)payload_len)
    };
    if (sac_io_write_all(stream, &net_hdr, sizeof(net_hdr)) != 0) {
        return -1;
    }
    if (payload_len > 0) {
        if (!payload || sac_io_write_all(stream, payload, payload_len) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Reads the 12-byte request header and, if payload_length <= SAC_MAX_PATH_LEN,
 * reads the exact payload bytes.
 * Note: If payload_length > SAC_MAX_PATH_LEN, we still populate out_host_hdr so
 * the caller can return an explicit SAC_ERR_PAYLOAD_TOO_LARGE response frame
 * before closing the connection.
 */
int sac_read_request_frame(
    sac_io_stream_t    *stream,
    sac_frame_header_t *out_host_hdr,
    char               *out_payload,
    size_t              payload_cap
) {
    if (!stream || !out_host_hdr || !out_payload || payload_cap <= SAC_MAX_PATH_LEN) {
        return -1;
    }
    sac_frame_header_t net_hdr;
    if (sac_io_read_exact(stream, &net_hdr, sizeof(net_hdr)) != 0) {
        return -1;
    }

    out_host_hdr->magic          = ntohl(net_hdr.magic);
    out_host_hdr->version        = net_hdr.version;
    out_host_hdr->opcode         = net_hdr.opcode;
    out_host_hdr->sequence_num   = ntohl(net_hdr.sequence_num);
    out_host_hdr->payload_length = ntohs(net_hdr.payload_length);

    out_payload[0] = '\0';

    if (out_host_hdr->payload_length > SAC_MAX_PATH_LEN) {
        /* Header read succeeded; caller will reject oversized payload_length */
        return 0;
    }

    if (out_host_hdr->payload_length > 0) {
        if (sac_io_read_exact(stream, out_payload, out_host_hdr->payload_length) != 0) {
            return -1;
        }
        out_payload[out_host_hdr->payload_length] = '\0';
    }
    return 0;
}

int sac_write_response_frame(
    sac_io_stream_t         *stream,
    const sac_resp_header_t *host_resp_hdr,
    const char              *payload,
    size_t                   payload_len
) {
    if (!stream || !host_resp_hdr || payload_len > SAC_MAX_PAYLOAD_LEN) {
        return -1;
    }
    sac_resp_header_t net_hdr = {
        .magic          = htonl(host_resp_hdr->magic),
        .version        = host_resp_hdr->version,
        .status_code    = host_resp_hdr->status_code,
        .error_domain   = host_resp_hdr->error_domain,
        .fs_status      = host_resp_hdr->fs_status,
        .sequence_echo  = htonl(host_resp_hdr->sequence_echo),
        .payload_length = htonl((uint32_t)payload_len)
    };
    if (sac_io_write_all(stream, &net_hdr, sizeof(net_hdr)) != 0) {
        return -1;
    }
    if (payload_len > 0) {
        if (!payload || sac_io_write_all(stream, payload, payload_len) != 0) {
            return -1;
        }
    }
    return 0;
}

int sac_read_response_frame(
    sac_io_stream_t   *stream,
    sac_resp_header_t *out_host_resp_hdr,
    char              *out_payload,
    size_t             payload_cap
) {
    if (!stream || !out_host_resp_hdr || !out_payload || payload_cap == 0) {
        return -1;
    }
    sac_resp_header_t net_hdr;
    if (sac_io_read_exact(stream, &net_hdr, sizeof(net_hdr)) != 0) {
        return -1;
    }

    out_host_resp_hdr->magic          = ntohl(net_hdr.magic);
    out_host_resp_hdr->version        = net_hdr.version;
    out_host_resp_hdr->status_code    = net_hdr.status_code;
    out_host_resp_hdr->error_domain   = net_hdr.error_domain;
    out_host_resp_hdr->fs_status      = net_hdr.fs_status;
    out_host_resp_hdr->sequence_echo  = ntohl(net_hdr.sequence_echo);
    out_host_resp_hdr->payload_length = ntohl(net_hdr.payload_length);

    if (out_host_resp_hdr->magic != SAC_MAGIC_BYTES ||
        out_host_resp_hdr->version != SAC_PROTOCOL_VERSION ||
        out_host_resp_hdr->payload_length > SAC_MAX_PAYLOAD_LEN ||
        out_host_resp_hdr->payload_length >= payload_cap) {
        return -1;
    }

    out_payload[0] = '\0';
    if (out_host_resp_hdr->payload_length > 0) {
        if (sac_io_read_exact(stream, out_payload, out_host_resp_hdr->payload_length) != 0) {
            return -1;
        }
        out_payload[out_host_resp_hdr->payload_length] = '\0';
    }
    return 0;
}
