/* wire.c
 *
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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
 * DNS wire-format functions.
 *
 * These are really simple functions for constructing DNS messages wire format.
 * The flow is that there is a transaction structure which contains pointers to both
 * a message output buffer and a response input buffer.   The structure is initialized,
 * and then the various wire format functions are called repeatedly to store data.
 * If an error occurs during this process, it's okay to just keep going, because the
 * error is recorded in the transaction; once all of the copy-in functions have been
 * called, the error status can be checked once at the end.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"

#ifndef NO_CLOCK
#include <sys/time.h>
#endif

int
dns_parse_label(const char *cur, const char *NONNULL * NONNULL nextp, uint8_t *NONNULL lenp, uint8_t *NONNULL buf, int max)
{
    const char *end;
    int tlen;
    const char *s;
    uint8_t *t;

    end = strchr(cur, '.');
    if (end == NULL) {
        end = cur + strlen(cur);
        if (end == cur) {
            *lenp = 0;
            *nextp = NULL;
            return 0;
        }
        *nextp = NULL;
    } else {
        if (end == cur) {
            return EINVAL;
        }
        *nextp = end + 1;
    }

    // Figure out the length of the label after escapes have been converted.
    tlen = 0;
    for (s = cur; s < end; s++) {
        if (*s == '\\') {
            if (s + 4 <= end) {
                tlen++;
                s += 3;
            } else {
                tlen++;
                }
        } else {
            tlen++;
        }
    }
    
    // Is there no space?

    if (tlen >= max) {
        return ENOBUFS;
    }

    // Is the label too long?
    if (end - cur > DNS_MAX_LABEL_SIZE) {
        return ENAMETOOLONG;
    }

    // Store the label length
    *lenp = (uint8_t)(tlen);

    // Store the label.
    t = buf;
    for (s = cur; s < end; s++) {
        if (*s == '\\') {
            if (s + 4 <= end) {
                int v0 = s[1] - '0';
                int v1 = s[2] - '0';
                int v2 = s[3] - '0';
                int val = v0 * 100 + v1 * 10 + v2;
                if (val < 255) {
                    *t++ = val;
                    s += 3;
                } else {
                    return EINVAL;
                }
            } else {
                return EINVAL;
            }
        } else {
            *t++ = *s;
        }
    }
    return 0;
}

// Convert a name to wire format.   Does not store the root label (0) at the end.   Does not support binary labels.
void
dns_name_to_wire_(dns_name_pointer_t *NULLABLE r_pointer,
                  dns_towire_state_t *NONNULL txn,
                  const char *NONNULL name, int line)
{
    const char *next, *cur;
    int status;
    dns_name_pointer_t np;

    if (!txn->error) {
        memset(&np, 0, sizeof np);
        np.message_start = (u_int8_t *)txn->message;
        np.name_start = txn->p;

        cur = name;
        do {
            // Note that nothing is stored through txn->p until dns_name_parse has verified that
            // there is space in the buffer for the label as well as the length.
            status = dns_parse_label(cur, &next, txn->p, txn->p + 1, txn->lim - txn->p - 1);
            if (status) {
                if (status == ENOBUFS) {
                    txn->truncated = true;
                }
                txn->error = status; 
                txn->line = line;
                return;
            }

            // Don't use the root label if it was parsed.
            if (*txn->p != 0) {
                np.num_labels++;
                np.length += 1 + *txn->p;
                txn->p = txn->p + *txn->p + 1;
                cur = next;
            }
        } while (next != NULL);

        if (np.length > DNS_MAX_NAME_SIZE) {
            txn->error = ENAMETOOLONG;
            txn->line = line;
            return;
        }
        if (r_pointer != NULL) {
            *r_pointer = np;
        }
    }
}

// Like dns_name_to_wire, but includes the root label at the end.
void
dns_full_name_to_wire_(dns_name_pointer_t *NULLABLE r_pointer,
                       dns_towire_state_t *NONNULL txn,
                       const char *NONNULL name, int line)
{
    dns_name_pointer_t np;
    if (!txn->error) {
        memset(&np, 0, sizeof np);
        dns_name_to_wire(&np, txn, name);
        if (!txn->error) {
            if (txn->p + 1 >= txn->lim) {
                txn->error = ENOBUFS;
                txn->truncated = true;
                txn->line = line;
                return;
            }
            *txn->p++ = 0;
            np.num_labels++;
            np.length += 1;
            if (np.length > DNS_MAX_NAME_SIZE) {
                txn->error = ENAMETOOLONG; 
                txn->line = line;
                return;
            }
            if (r_pointer) {
                *r_pointer = np;
            }
        }
    }
}

// Store a pointer to a name that's already in the message.
void
dns_pointer_to_wire_(dns_name_pointer_t *NULLABLE r_pointer,
                     dns_towire_state_t *NONNULL txn,
                     dns_name_pointer_t *NONNULL pointer, int line)
{
    if (!txn->error) {
        u_int16_t offset = pointer->name_start - pointer->message_start;
        if (offset > DNS_MAX_POINTER) {
            txn->error = ETOOMANYREFS;
            txn->line = line;
            return;
        }
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        *txn->p++ = 0xc0 | (offset >> 8);
        *txn->p++ = offset & 0xff;
        if (r_pointer) {
            r_pointer->num_labels += pointer->num_labels;
            r_pointer->length += pointer->length + 1;
            if (r_pointer->length > DNS_MAX_NAME_SIZE) {
                txn->error = ENAMETOOLONG;
                txn->line = line;
                return;
            }
        }
    }
}

void
dns_u8_to_wire_(dns_towire_state_t *NONNULL txn, uint8_t val, int line)
{
    if (!txn->error) {
        if (txn->p + 1 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        *txn->p++ = val;
    }
}

// Store a 16-bit integer in network byte order
void
dns_u16_to_wire_(dns_towire_state_t *NONNULL txn, uint16_t val, int line)
{
    if (!txn->error) {
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        *txn->p++ = val >> 8;
        *txn->p++ = val & 0xff;
    }
}

void
dns_u32_to_wire_(dns_towire_state_t *NONNULL txn,
                 uint32_t val, int line)
{
    if (!txn->error) {
        if (txn->p + 4 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        *txn->p++ = val >> 24;
        *txn->p++ = (val >> 16) & 0xff;
        *txn->p++ = (val >> 8) & 0xff;
        *txn->p++ = val & 0xff;
    }
}

void
dns_ttl_to_wire_(dns_towire_state_t *NONNULL txn,
                 int32_t val, int line)
{
    if (!txn->error) {
        dns_u32_to_wire_(txn, (uint32_t)val, line);
    }
}

void
dns_rdlength_begin_(dns_towire_state_t *NONNULL txn, int line)
{
    if (!txn->error) {
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        if (txn->p_rdlength != NULL) {
            txn->error = EINVAL;
            txn->line = line;
            return;
        }
        txn->p_rdlength = txn->p;
        txn->p += 2;
    }
}

void
dns_rdlength_end_(dns_towire_state_t *NONNULL txn, int line)
{
    int rdlength;
    if (!txn->error) {
        if (txn->p_rdlength == NULL) {
            txn->error = EINVAL;
            txn->line = line;
            return;
        }
        rdlength = txn->p - txn->p_rdlength - 2;
        txn->p_rdlength[0] = rdlength >> 8;
        txn->p_rdlength[1] = rdlength & 0xff;
        txn->p_rdlength = NULL;
    }
}

void
dns_rdata_a_to_wire_(dns_towire_state_t *NONNULL txn,
                     const char *NONNULL ip_address, int line)
{
    if (!txn->error) {
        if (txn->p + 4 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        if (!inet_pton(AF_INET, ip_address, txn->p)) {
            txn->error = EINVAL;
            txn->line = line;
            return;
        }
        txn->p += 4;
    }
}

void
dns_rdata_aaaa_to_wire_(dns_towire_state_t *NONNULL txn,
                        const char *NONNULL ip_address, int line)
{
    if (!txn->error) {
        if (txn->p + 16 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        if (!inet_pton(AF_INET6, ip_address, txn->p)) {
            txn->error = EINVAL;
            txn->line = line;
            return;
        }
        txn->p += 16;
    }
}

uint16_t
dns_rdata_key_to_wire_(dns_towire_state_t *NONNULL txn,
                       unsigned key_type,
                       unsigned name_type,
                       unsigned signatory,
                       srp_key_t *key, int line)
{
    int key_len = srp_pubkey_length(key);
    uint8_t *rdata = txn->p;
    uint32_t key_tag;
    int i, rdlen;
    
    if (!txn->error) {
        if (key_type > 3 || name_type > 3 || signatory > 15) {
            txn->error = EINVAL;
            txn->line = line;
            return 0;
        }
        if (txn->p + key_len + 4 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return 0;
        }
        *txn->p++ = (key_type << 6) | name_type;
        *txn->p++ = signatory;
        *txn->p++ = 3; // protocol type is always 3
        *txn->p++ = srp_key_algorithm(key);
        srp_pubkey_copy(txn->p, key_len, key);
        txn->p += key_len;
    }
    rdlen = txn->p - rdata;

    // Compute the key tag
    key_tag = 0;
    for (i = 0; i < rdlen; i++) {
        key_tag += (i & 1) ? rdata[i] : rdata[i] << 8;
    }
    key_tag += (key_tag >> 16) & 0xFFFF;
    return (uint16_t)(key_tag & 0xFFFF);
}

void
dns_rdata_txt_to_wire_(dns_towire_state_t *NONNULL txn,
                       const char *NONNULL txt_record, int line)
{
    if (!txn->error) {
        unsigned len = strlen(txt_record);
        if (txn->p + len + 1 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        if (len > 255) {
            txn->error = ENAMETOOLONG;
            txn->line = line;
            return;
        }
        *txn->p++ = (u_int8_t)len;
        memcpy(txn->p, txt_record, len);
        txn->p += len;
    }
}

void
dns_rdata_raw_data_to_wire_(dns_towire_state_t *NONNULL txn, const void *NONNULL raw_data, size_t length, int line)
{
    if (!txn->error) {
        if (txn->p + length >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        memcpy(txn->p, raw_data, length);
        txn->p += length;
    }
}

void
dns_edns0_header_to_wire_(dns_towire_state_t *NONNULL txn,
                          int mtu,
                          int xrcode,
                          int version,
                          int DO, int line)
{
    if (!txn->error) {
        if (txn->p + 9 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        *txn->p++ = 0; // root label
        dns_u16_to_wire(txn, dns_rrtype_opt);
        dns_u16_to_wire(txn, mtu);
        *txn->p++ = xrcode;
        *txn->p++ = version;
        *txn->p++ = DO << 7;	// flags (usb)
        *txn->p++ = 0;			// flags (lsb, mbz)
    }
}

void
dns_edns0_option_begin_(dns_towire_state_t *NONNULL txn, int line)
{
    if (!txn->error) {
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        if (txn->p_opt != NULL) {
            txn->error = EINVAL;
            txn->line = line;
            return;
        }
        txn->p_opt = txn->p;
        txn->p += 2;
    }
}

void
dns_edns0_option_end_(dns_towire_state_t *NONNULL txn, int line)
{
    int opt_length;
    if (!txn->error) {
        if (txn->p_opt == NULL) {
            txn->error = EINVAL;
            txn->line = line;
            return;
        }
        opt_length = txn->p - txn->p_opt - 2;
        txn->p_opt[0] = opt_length >> 8;
        txn->p_opt[1] = opt_length & 0xff;
        txn->p_opt = NULL;
    }
}

void
dns_sig0_signature_to_wire_(dns_towire_state_t *NONNULL txn,
                            srp_key_t *key,
                            uint16_t key_tag,
                            dns_name_pointer_t *NONNULL signer,
                            const char *NONNULL signer_fqdn, int line)
{
    int siglen = srp_signature_length(key);
    uint8_t *start, *p_signer, *p_signature, *rrstart = txn->p;
#ifndef NO_CLOCK
    struct timeval now;
#endif

    // 1 name (root)
    // 2 type (SIG)
    // 2 class (0)
    // 4 TTL (0)
    // 18 SIG RDATA up to signer name
    // 2 signer name (always a pointer)
    // 29 bytes so far
    // signature data (depends on algorithm, e.g. 64 for ECDSASHA256)
    // so e.g. 93 bytes total
    
    if (!txn->error) {
        dns_u8_to_wire(txn, 0);	// root label
        dns_u16_to_wire(txn, dns_rrtype_sig);
        dns_u16_to_wire(txn, 0); // class
        dns_ttl_to_wire(txn, 0); // SIG RR TTL
        dns_rdlength_begin(txn);
        start = txn->p;
        dns_u16_to_wire(txn, 0); // type = 0 for transaction signature
        dns_u8_to_wire(txn, srp_key_algorithm(key));
        dns_u8_to_wire(txn, 0); // labels field doesn't apply for transaction signature
        dns_ttl_to_wire(txn, 0); // original ttl doesn't apply
#ifdef NO_CLOCK
        dns_u32_to_wire(txn, 0); // Indicate that we have no clock: set expiry and inception times to zero
        dns_u32_to_wire(txn, 0);
#else        
        gettimeofday(&now, NULL);
        dns_u32_to_wire(txn, now.tv_sec + 300); // signature expiration time is five minutes from now
        dns_u32_to_wire(txn, now.tv_sec - 300); // signature inception time, five minutes in the past
#endif
        dns_u16_to_wire(txn, key_tag);
        p_signer = txn->p;
        // We store the name in uncompressed form because that's what we have to sign
        dns_full_name_to_wire(NULL, txn, signer_fqdn);
        // And that means we're going to have to copy the signature back earlier in the packet.
        p_signature = txn->p;

        // Sign the message, signature RRDATA (less signature) first.
        srp_sign(txn->p, siglen, (uint8_t *)txn->message, rrstart - (uint8_t *)txn->message,
                 start, txn->p - start, key);

        // Now that it's signed, back up and store the pointer to the name, because we're trying
        // to be as compact as possible.
        txn->p = p_signer;
        dns_pointer_to_wire(NULL, txn, signer); // Pointer to the owner name the key is attached to
        // And move the signature earlier in the packet.
        memmove(txn->p, p_signature, siglen);

        txn->p += siglen;
        dns_rdlength_end(txn);
        if (txn->error) {
            txn->outer_line = line;
        }
    }
}

int
dns_send_to_server(dns_transaction_t *NONNULL txn,
                   const char *NONNULL anycast_address, uint16_t port,
                   dns_response_callback_t NONNULL callback)
{
    union {
        struct sockaddr_storage s;
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } addr, from;
    socklen_t len, fromlen;
    ssize_t rv, datasize;

    if (!txn->towire.error) {
        memset(&addr, 0, sizeof addr);

        // Try IPv4 first because IPv6 addresses are never valid IPv4 addresses
        if (inet_pton(AF_INET, anycast_address, &addr.sin.sin_addr)) {
            addr.sin.sin_family = AF_INET;
            addr.sin.sin_port = htons(port);
            len = sizeof addr.sin;
        } else if (inet_pton(AF_INET6, anycast_address, &addr.sin6.sin6_addr)) {
            addr.sin6.sin6_family = AF_INET6;
            addr.sin6.sin6_port = htons(port);
            len = sizeof addr.sin6;
        } else {
            txn->towire.error = EPROTONOSUPPORT;
            return -1;
        }
#ifndef NOT_HAVE_SA_LEN
        addr.sa.sa_len = len;
#endif

        txn->sock = socket(addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
        if (txn->sock < 0) {
            txn->towire.error = errno;
            return -1;
        }

#if 0
        memset(&myaddr, 0, sizeof myaddr);
        myaddr.sin.sin_port = htons(9999);
        myaddr.sa.sa_len = len;
        myaddr.sa.sa_family = addr.sa.sa_family;
        rv = bind(txn->sock, &myaddr.sa, len);
        if (rv < 0) {
            txn->towire.error = errno;
            return -1;
        }
#endif

        datasize = txn->towire.p - ((u_int8_t *)txn->towire.message);
        rv = sendto(txn->sock, txn->towire.message, datasize, 0, &addr.sa, len);
        if (rv < 0) {
            txn->towire.error = errno;
            goto out;
        }
        if (rv != datasize) {
            txn->towire.error = EMSGSIZE;
            goto out;
        }
        fromlen = sizeof from;
        rv = recvfrom(txn->sock, txn->response, sizeof *txn->response, 0, &from.sa, &fromlen);
        if (rv < 0) {
            txn->towire.error = errno;
            goto out;
        }
        txn->response_length = rv;
    }
out:
    close(txn->sock);
    txn->sock = 0;

    if (txn->towire.error) {
        return -1;
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
