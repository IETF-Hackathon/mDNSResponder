/* hash.c
 *
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
 * DNS SIG(0) hashature generation for DNSSD SRP using mbedtls.
 *
 * Functions required for loading, saving, and generating public/private keypairs, extracting the public key
 * into KEY RR data, and computing hashatures.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/errno.h>

#include "srp.h"
#include "dns-msg.h"
#define SRP_CRYPTO_MBEDTLS_INTERNAL
#include "srp-crypto.h"

// Function to generate a signature given some data and a private key
void
srp_hmac_iov(int hash_type, uint8_t *output, size_t max, struct iovec *iov, int count)
{
    int status;
    char errbuf[64];
    mbedtls_sha256_context sha;
	int i;

    if (hash_type != SRP_HASH_TYPE_SHA256) {
        ERROR("Unsupported HMAC hash type: %d", hash_type);
        return;
    }
    if (max < ECDSA_SHA256_HASH_SIZE) {
        ERROR("srp_hash_iov: not enough space in output buffer (%lu) for hash (%d).",
              (unsigned long)max, ECDSA_SHA256_HASH_SIZE);
        return;
    }

    mbedtls_sha256_init(&sha);

    // Calculate the hash across first the SIG RR (minus the hashature) and then the message
    // up to but not including the SIG RR.  There should be no reason for hashing to fail.
    if ((status = mbedtls_sha256_starts_ret(&sha, 0)) != 0) {
	kablooie:
        mbedtls_strerror(status, errbuf, sizeof errbuf);
        ERROR("srp_hash_iov failed: %s", errbuf);
        return;
    }
	for (i = 0; i < count; i++) {
        if ((status = srp_mbedtls_sha256_update_ret(&sha, iov[i].iov_base, iov[i].iov_len)) != 0) {
            goto kablooie;
        }
	}
	if ((status = srp_mbedtls_sha256_finish_ret(&sha, output)) != 0) {
        goto kablooie;
	}
}
    
int
srp_base64_parse(char *src, size_t *len_ret, uint8_t *buf, size_t buflen)
{
    size_t slen = strlen(src);
    int ret = mbedtls_base64_decode(buf, buflen, len_ret, (const unsigned char *)src, slen);
    if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return ENOBUFS;
    } else if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        return EILSEQ;
    } else if (ret < 0) {
        return EINVAL;
    }
    return 0;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
