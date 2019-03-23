/* -*- Mode: C; tab-width: 4; c-file-style: "bsd"; c-basic-offset: 4; fill-column: 108; indent-tabs-mode: nil; -*-
 *
 * Copyright (c) 2002-2019 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file contains a TLS Shim that allows mDNSPosix to use mbedtls to do TLS session
 * establishment and also to accept TLS connections.
 */

#include "mDNSEmbeddedAPI.h"           // Defines the interface provided to the client layer above
#include "DNSCommon.h"
#include "mDNSPosix.h"               // Defines the specific types needed to run mDNS on this platform
#include "PlatformCommon.h"
#include "PosixTLS.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#ifdef USE_MBEDTLS
// Posix TLS server context

struct PosixTLSContextStruct {
    mbedtls_tls_context context;
};

struct PosixTLSServerContextStruct {
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config config;
};

// Context that is shared amongs all TLS connections, regardless of which server cert/key is in use.
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

void
mDNSPosixTLSInit(void)
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    status = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (status != 0) {
        ERROR("Unable to seed RNG: %x", -status);
        return false;
    }
}

static int
tls_io_send(void *ctx, const unsigned char *buf, size_t len)
{
    ssize_t ret;
    TCPSocket *sock = ctx;
    ret = mDNSPosixWriteTCP(sock->events.fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        } else {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    } else {
        return (int)ret;
    }
}

static int
tls_io_recv(void *ctx, unsigned char *buf, size_t max)
{
    ssize_t ret;
    TCPSocket *comm = ctx;
    ret = mDNSPosixReadTCP(sock->events.fd, buf, max);
    if (ret < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        } else {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    } else if (ret == 0) {
        return MBEDTLS_ERR_SSL_CONN_EOF;
    } else {
        return (int)ret;
    }
}

PosixTLSContext *
PosixTLSAccept(TCPSocket *sock, TCPListenContext *listenContext)
{
    int status;
    PosixTLSContext *context = mDNSPlatformAllocClear("PosixTLSAccept: PosixTLSContext", sizeof *context);

    if (context == mDNSNULL)
        return context;

    status = mbedtls_ssl_setup(&context->context, listenContext->config);
    if (status != 0) {
        LogInfo("Unable to set up TLS listener state: %x", -status);
        return false;
    }

    // Set up the I/O functions.
    mbedtls_ssl_set_bio(&context->context, comm, tls_io_send, tls_io_recv, NULL);

    // Start the TLS handshake
    status = mbedtls_ssl_handshake(&comm->tls_context->context);
    if (status != 0 && status != MBEDTLS_ERR_SSL_WANT_READ && status != MBEDTLS_ERR_SSL_WANT_WRITE) {
        LogInfo("TLS handshake failed: %x", -status);
        tls_context_free(context);
    }
    
    return context;
}

int
mDNSPosixTLSRead(TCPSocket *sock, void *buf, unsigned long buflen, mDNSBool *closed)
{
    int ret;

    // Shouldn't ever happen.
    if (!socket->tls) {
        LogMsg("mDNSPosixTLSRead: called without TLS context!");
        *closed = mDNStrue;
        return 0;
    }

    ret = mbedtls_ssl_read(&TCPSocket->tls->context, buf, max);
    if (ret < 0) {
        switch (ret) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            return 0;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            LogMsg("Got SSL want write in TLS read!");
            // This means we got EWOULDBLOCK on a write operation.
            // Not implemented yet, but the right way to handle this is probably to
            // deselect read events until the socket is ready to write, then write,
            // and then re-enable read events.   What we don't want is to keep calling
            // read, because that will spin.
            return 0;
        case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            LogMsg("Got async in progress in TLS read!");
            // No idea how to handle this yet.
            return 0;
#ifdef MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS
        case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            LogMsg("Got crypto in progress in TLS read!");
            // No idea how to handle this.
            return 0;
#endif
        default:
            LogMsg("Unexpected response from SSL read: %x", -ret);
            return -1;
        }
    } else {
        // mbedtls returns 0 for EOF, just like read(), but we need a different signal,
        // so we treat 0 as an error (for now).   In principle, we should get a notification
        // when the remote end is done writing, so a clean close should be different than
        // an abrupt close.
        if (ret == 0) {
            if (closed) {
                *closed = mDNStrue;
            }
            return -1;
        }
        return ret;
    }
}

int
mDNSPosixTLSWrite(TCPSocket *sock, void *buf, unsigned long buflen)
{
    int ret;
    int i;
    ret = mbedtls_ssl_write(&sock->tls->context, buf, buflen);
    if (ret < 0) {
        switch (ret) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            return 0;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            LogMsg("Got SSL want write in TLS read!");
            return bytes_written;
        case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            LogMsg("Got async in progress in TLS read!");
            return bytes_written;
#ifdef MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS
        case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            LogMsg("Got crypto in progress in TLS read!");
            return bytes_written;
#endif
        default:
            LogMsg("Unexpected response from SSL read: %x", -ret);
            return -1;
        }
    }
    return ret;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
