/* dnssd-proxy.c
 *
 * Copyright (c) 2018-2019 Apple Computer, Inc. All rights reserved.
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
 * This is a Discovery Proxy module for the SRP gateway.
 *
 * The motivation here is that it makes sense to co-locate the SRP relay and the Discovery Proxy because
 * these functions are likely to co-exist on the same node, listening on the same port.  For homenet-style
 * name resolution, we need a DNS proxy that implements DNSSD Discovery Proxy for local queries, but
 * forwards other queries to an ISP resolver.  The SRP gateway is already expecting to do this.
 * This module implements the functions required to allow the SRP gateway to also do Discovery Relay.
 * 
 * The Discovery Proxy relies on Apple's DNS-SD library and the mDNSResponder DNSSD server, which is included
 * in Apple's open source mDNSResponder package, available here:
 *
 *            https://opensource.apple.com/tarballs/mDNSResponder/
 */

#define __APPLE_USE_RFC_3542

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/time.h>
#include <ctype.h>

#include "dns_sd.h"
#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#define DNSMessageHeader dns_wire_t
#include "dso.h"
#include "ioloop.h"
#include "srp-tls.h"
#include "config-parse.h"

// Enumerate the list of interfaces, map them to interface indexes, give each one a name
// Have a tree of subdomains for matching

// Configuration file settings
uint16_t udp_port;
uint16_t tcp_port;
uint16_t tls_port;
char *my_name = NULL;
char *my_ipv4_addr = NULL;
char *my_ipv6_addr = NULL;

typedef struct hardwired hardwired_t;
struct hardwired {
    hardwired_t *next;
    uint16_t type;
    char *name;
    char *fullname;
    uint8_t *rdata;
    uint16_t rdlen;
};

typedef struct interface_config interface_config_t;
struct interface_config {
    interface_config_t *next;           // Active configurations, used for identifying a domain that matches
    char *domain;                       // The domain name of the interface, represented as a text string.
    char *domain_ld;                    // The same name, with a leading dot (if_domain_lp == if_domain + 1)
    dns_name_t *domain_name;            // The domain name, parsed into labels.
    char *name;                         // The name of the interface
    int ifindex;                        // The interface index (for use with sendmsg() and recvmsg().
    bool no_push;                       // If true, don't set up DNS Push for this domain
    hardwired_t *hardwired_responses;   // Hardwired responses for this interface
} *interfaces;

typedef struct dnssd_query {
    io_t io;
    DNSServiceRef ref;
    char *name;                     // The name we are looking up.
    interface_config_t *iface;      // If this is a local query, the interface for the query

                                    // If we've already copied out the enclosing domain once in a DNS message.
    dns_name_pointer_t enclosing_domain_pointer;

    message_t *question;
    comm_t *connection;
    dso_activity_t *activity;
    int serviceFlags;               // Service flags to use with this query.
    bool is_dns_push;
    bool is_edns0;
    uint16_t type, qclass;          // Original query type and class.
    dns_towire_state_t towire;
    uint8_t *p_dso_length;          // Where to store the DSO length just before we write out a push notification.
    dns_wire_t *response;
    size_t data_size;		        // Size of the data payload of the response
} dnssd_query_t;

const char push_subscription_activity_type[] = "push subscription";

const char local_suffix[] = ".local.";

#define TOWIRE_CHECK(note, towire, func) { func; if ((towire)->error != 0 && failnote == NULL) failnote = (note); }

int64_t dso_transport_idle(void *context, int64_t now, int64_t next_event)
{
    return next_event;
}

void dnssd_query_cancel(io_t *io)
{
    dnssd_query_t *query = (dnssd_query_t *)io;
    if (query->io.sock != -1) {
        DNSServiceRefDeallocate(query->ref);
        query->io.sock = -1;
    }
    query->connection = NULL;
}

void
dns_push_finalize(dso_activity_t *activity)
{
    dnssd_query_t *query = (dnssd_query_t *)activity->context;
    INFO("dnssd_push_finalize: %s", activity->name);
    dnssd_query_cancel(&query->io);
}

void
dnssd_query_finalize(io_t *io)
{
    dnssd_query_t *query = (dnssd_query_t *)io;
    INFO("dnssd_query_finalize on %s%s", query->name, query->iface ? ".local" : "");
    if (query->question) {
        message_free(query->question);
    }
    free(query->name);
    free(query);
}

static void
dnssd_query_callback(io_t *io)
{
    dnssd_query_t *query = (dnssd_query_t *)io;
    int status = DNSServiceProcessResult(query->ref);
    if (status != kDNSServiceErr_NoError) {
        ERROR("DNSServiceProcessResult on %s%s returned %d", query->name, query->iface ? ".local" : "", status);
        if (query->activity != NULL && query->connection != NULL) {
            dso_drop_activity(query->connection->dso, query->activity);
        } else {
            dnssd_query_cancel(&query->io);
        }
    }
}

static void
add_dnssd_query(dnssd_query_t *query)
{
    io_t *io = &query->io;
    io->sock = DNSServiceRefSockFD(query->ref);
    io->cancel = dnssd_query_cancel;
    io->cancel_on_close = &query->connection->io;
    add_reader(io, dnssd_query_callback, dnssd_query_finalize);
}

void
dp_simple_response(comm_t *comm, int rcode)
{
    if (comm->send_response) {
        struct iovec iov;
        dns_wire_t response;
        memset(&response, 0, DNS_HEADER_SIZE);

        // We take the ID and the opcode from the incoming message, because if the
        // header has been mangled, we (a) wouldn't have gotten here and (b) don't
        // have any better choice anyway.
        response.id = comm->message->wire.id;
        dns_qr_set(&response, dns_qr_response);
        dns_opcode_set(&response, dns_opcode_get(&comm->message->wire));
        dns_rcode_set(&response, rcode);
        iov.iov_base = &response;
        iov.iov_len = DNS_HEADER_SIZE; // No RRs
        comm->send_response(comm, comm->message, &iov, 1);
    }
}

bool
dso_send_formerr(dso_state_t *dso, const dns_wire_t *header)
{
    comm_t *transport = dso->transport;
    (void)header;
    dp_simple_response(transport, dns_rcode_formerr);
    return true;
}

interface_config_t *
dp_served(dns_name_t *name, char *buf, size_t bufsize)
{
    interface_config_t *ifc;
    dns_label_t *lim;
    
    for (ifc = interfaces; ifc; ifc = ifc->next) {
        if ((lim = dns_name_subdomain_of(name, ifc->domain_name))) {
            dns_name_print_to_limit(name, lim, buf, bufsize);
            return ifc;
        }
    }
    return NULL;
}

// Utility function to find "local" on the end of a string of labels.
bool
truncate_local(dns_name_t *name)
{
    dns_label_t *lp, *prev, *prevprev;
    
    prevprev = prev = NULL;
    // Find the root label.
    for (lp = name; lp && lp->len; lp = lp->next) {
        prevprev = prev;
        prev = lp;
    }
    if (lp && prev && prevprev) {
        if (prev->len == 5 && dns_labels_equal(prev->data, "local", 5)) {
            dns_name_free(prev);
            prevprev->next = NULL;
            return true;
        }
    }
    return false;
}    

void
dp_query_add_data_to_response(dnssd_query_t *query, const char *fullname,
                              uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, int32_t ttl)
{
    dns_towire_state_t *towire = &query->towire;
    const char *failnote = NULL;
    const uint8_t *rd = rdata;
    char pbuf[DNS_MAX_NAME_SIZE + 1];
    char rbuf[DNS_MAX_NAME_SIZE + 1];
    uint8_t *revert = query->towire.p; // Remember where we were in case there's no room.
    bool local;

    if (rdlen == 0) {
        INFO("Eliding zero-length response for %s %d %d", fullname, rrtype, rrclass);
        return;
    }
    // Don't send A records for 127.* nor AAAA records for ::1
    if (rrtype == dns_rrtype_a) {
        if (rdlen == 4 && rd[0] == 127) {
            INFO("Eliding localhost response for %s: %d.%d.%d.%d", fullname, rd[0], rd[1], rd[2], rd[3]);
            return;
        }
    } else if (rrtype == dns_rrtype_aaaa && rdlen == 16) {
        int i;
        for (i = 0; i < 15; i++) {
            if (rd[i] != 0) {
                break;
            }
        }
        if (i == 15 && rd[15] == 1) {
            char abuf[INET6_ADDRSTRLEN + 1];
            inet_ntop(AF_INET6, rdata, abuf, sizeof abuf);
            INFO("Eliding localhost response for %s: %s", fullname, abuf);
            return;
        }
    }
    INFO("dp_query_add_data_to_response: survived for rrtype %d rdlen %d", rrtype, rdlen);

    // Rewrite the domain if it's .local.
    if (query->iface != NULL) {
        TOWIRE_CHECK("concatenate_name_to_wire", towire,
                     dns_concatenate_name_to_wire(towire, NULL, query->name, query->iface->domain));
        INFO("%s answer:  type %02d class %02d %s.%s", query->is_dns_push ? "PUSH" : "DNS ",
             rrtype, rrclass, query->name, query->iface->domain);
    } else {
        TOWIRE_CHECK("compress_name_to_wire", towire, dns_concatenate_name_to_wire(towire, NULL, NULL, query->name));
        INFO("%s answer:  type %02d class %02d %s (p)",
             query->is_dns_push ? "push" : " dns", rrtype, rrclass, query->name);
    }
    TOWIRE_CHECK("rrtype", towire, dns_u16_to_wire(towire, rrtype));
    TOWIRE_CHECK("rrclass", towire, dns_u16_to_wire(towire, rrclass));
    TOWIRE_CHECK("ttl", towire, dns_ttl_to_wire(towire, ttl));

    if (rdlen > 0) {
        // If necessary, correct domain names inside of rrdata. 
        dns_rr_t answer;
        dns_name_t *name;
        unsigned offp = 0;
        
        answer.type = rrtype;
        answer.qclass = rrclass;
        if (dns_rdata_parse_data(&answer, rdata, &offp, rdlen, rdlen, 0)) {
            switch(rrtype) {
            case dns_rrtype_cname:
            case dns_rrtype_ptr:
            case dns_rrtype_ns:
            case dns_rrtype_md:
            case dns_rrtype_mf:
            case dns_rrtype_mb:
            case dns_rrtype_mg:
            case dns_rrtype_mr:
            case dns_rrtype_nsap_ptr:
            case dns_rrtype_dname:
                name = answer.data.ptr.name;
                TOWIRE_CHECK("rdlength begin", towire, dns_rdlength_begin(towire));
                break;
            case dns_rrtype_srv:
                name = answer.data.srv.name;
                TOWIRE_CHECK("rdlength begin", towire, dns_rdlength_begin(towire));
                TOWIRE_CHECK("answer.data.srv.priority", towire, dns_u16_to_wire(towire, answer.data.srv.priority));
                TOWIRE_CHECK("answer.data.srv.weight", towire, dns_u16_to_wire(towire, answer.data.srv.weight));
                TOWIRE_CHECK("answer.data.srv.port", towire, dns_u16_to_wire(towire, answer.data.srv.port));
                break;
            default:
                INFO("record type %d not translated", rrtype);
                goto raw;
            }
        
            dns_name_print(name, rbuf, sizeof rbuf);

            // If the name ends in .local, truncate it.
            if ((local = truncate_local(name))) {
                dns_name_print(name, pbuf, sizeof pbuf);
            }

            // If the name ended in .local, concatenate the interface domain name to the end.
            if (local) {
                TOWIRE_CHECK("concatenate_name_to_wire 2", towire,
                             dns_concatenate_name_to_wire(towire, name, NULL, query->iface->domain));
                INFO("translating %s to %s . %s", rbuf, pbuf, query->iface->domain);
            } else {
                TOWIRE_CHECK("concatenate_name_to_wire 2", towire,
                             dns_concatenate_name_to_wire(towire, name, NULL, NULL));
                INFO("compressing %s", rbuf);
            }
            dns_name_free(name);
            dns_rdlength_end(towire);
        } else {
            ERROR("dp_query_add_data_to_response: rdata from mDNSResponder didn't parse!!");
        raw:
            TOWIRE_CHECK("rdlen", towire, dns_u16_to_wire(towire, rdlen));
            TOWIRE_CHECK("rdata", towire, dns_rdata_raw_data_to_wire(towire, rdata, rdlen));
        }
    } else {
        TOWIRE_CHECK("rdlen", towire, dns_u16_to_wire(towire, rdlen));
    }
    if (towire->truncated || failnote) {
        ERROR("RR ADD FAIL: dp_query_add_data_to_response: %s", failnote);
        query->towire.p = revert;
    }
}

void
dnssd_hardwired_add(interface_config_t *ifc,
                    const char *name, const char *domain, size_t rdlen, uint8_t *rdata, uint16_t type)
{
    hardwired_t *hp;
    int namelen = strlen(name);
    size_t total = (sizeof *hp) + rdlen + namelen * 2 + strlen(ifc->domain_ld) + 2;

    hp = calloc(1, (sizeof *hp) + rdlen + namelen * 2 + strlen(ifc->domain_ld) + 2);
    hp->rdata = (uint8_t *)(hp + 1);
    hp->rdlen = rdlen;
    memcpy(hp->rdata, rdata, rdlen);
    hp->name = (char *)hp->rdata + rdlen;
    strcpy(hp->name, name);
    hp->fullname = hp->name + namelen + 1;
    strcpy(hp->fullname, name);
    strcpy(hp->fullname + namelen, ifc->domain_ld);
    if (hp->fullname + strlen(hp->fullname) + 1 != (char *)hp + total) {
        ERROR("%p != %p", hp->fullname + strlen(hp->fullname) + 1, ((char *)hp) + total);
    }
    hp->type = type;
    hp->next = ifc->hardwired_responses;
    ifc->hardwired_responses = hp;

    INFO("hardwired_add: fullname %s name %s type %d rdlen %d", hp->fullname, hp->name, hp->type, hp->rdlen);
}

void
dnssd_hardwired_setup(void)
{
    dns_wire_t wire;
    dns_towire_state_t towire;
    interface_config_t *ifc;

#define RESET \
    memset(&towire, 0, sizeof towire); \
    towire.message = &wire; \
    towire.p = wire.data; \
    towire.lim = towire.p + sizeof wire.data

    // For each interface, set up the hardwired names.
    for (ifc = interfaces; ifc; ifc = ifc->next) {
        // Browsing pointers...
        RESET;
        dnssd_hardwired_add(ifc, "b._dns-sd._udp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_ptr);
        dnssd_hardwired_add(ifc, "lb._dns-sd._udp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_ptr);

        // SRV
        // _dns-llq._udp
        // _dns-llq-tls._tcp
        // _dns-update._udp
        // _dns-update-tls._udp
        // We deny the presence of support for LLQ, because we only support DNS Push
        dnssd_hardwired_add(ifc, "_dns-llq._udp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        dnssd_hardwired_add(ifc, "_dns-llq-tls._tcp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        
        // We deny the presence of support for DNS Update, because a Discovery Proxy zone is stateless.
        dnssd_hardwired_add(ifc, "_dns-update._udp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        dnssd_hardwired_add(ifc, "_dns-update-tls._tcp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
    
        if (ifc->no_push) {
            dnssd_hardwired_add(ifc, "_dns-push-tls._tcp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        } else {
            // SRV
            // _dns-push._tcp
            RESET;
            dns_u16_to_wire(&towire, 0); // priority
            dns_u16_to_wire(&towire, 0); // weight
            dns_u16_to_wire(&towire, 53); // port
            // Define MY_NAME to reference a name for this server in a different zone.
            if (my_name == NULL) {
                dns_name_to_wire(NULL, &towire, "ns");
                dns_full_name_to_wire(NULL, &towire, ifc->domain);
            } else {
                dns_full_name_to_wire(NULL, &towire, my_name);
            }
            dnssd_hardwired_add(ifc, "_dns-push._tcp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);

            // SRV
            // _dns-push-tls._tcp
            RESET;
            dns_u16_to_wire(&towire, 0); // priority
            dns_u16_to_wire(&towire, 0); // weight
            dns_u16_to_wire(&towire, 853); // port
            // Define MY_NAME to reference a name for this server in a different zone.
            if (my_name == NULL) {
                dns_name_to_wire(NULL, &towire, "ns");
                dns_full_name_to_wire(NULL, &towire, ifc->domain);
            } else {
                dns_full_name_to_wire(NULL, &towire, my_name);
            }
            dnssd_hardwired_add(ifc, "_dns-push-tls._tcp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
            // This will probably never be used, but existing open source mDNSResponder code can be
            // configured to do DNS queries over TLS for specific domains, so we might as well support it,
            // since we do have TLS support.
            dnssd_hardwired_add(ifc, "_dns-query-tls._udp", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        }
    
        if (my_name == NULL) {
            // A
            // ns
            if (my_ipv4_addr != NULL) {
                RESET;
                dns_rdata_a_to_wire(&towire, my_ipv4_addr);
                dnssd_hardwired_add(ifc, "ns", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_a);
            }

            if (my_ipv4_addr != NULL) {
                // AAAA
                RESET;
                dns_rdata_aaaa_to_wire(&towire, my_ipv6_addr);
                dnssd_hardwired_add(ifc, "ns", ifc->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_aaaa);
            }
        }

        // NS
        RESET;
        if (my_name != NULL) {
            dns_full_name_to_wire(NULL, &towire, my_name);
        } else {
            dns_name_to_wire(NULL, &towire, "ns");
            dns_full_name_to_wire(NULL, &towire, ifc->domain);
        }
        dnssd_hardwired_add(ifc, "", ifc->domain, towire.p - wire.data, wire.data, dns_rrtype_ns);

        // SOA (piggybacking on what we already did for NS, which starts the same.
        dns_name_to_wire(NULL, &towire, "postmaster");
        dns_full_name_to_wire(NULL, &towire, ifc->domain);
        dns_u32_to_wire(&towire, 0);     // serial 
        dns_ttl_to_wire(&towire, 7200);  // refresh
        dns_ttl_to_wire(&towire, 3600);  // retry
        dns_ttl_to_wire(&towire, 86400); // expire
        dns_ttl_to_wire(&towire, 120);    // minimum
        dnssd_hardwired_add(ifc, "", ifc->domain, towire.p - wire.data, wire.data, dns_rrtype_soa);
    }
}

bool
embiggen(dnssd_query_t *query)
{
    dns_wire_t *nr = malloc(query->data_size + sizeof *nr); // increments wire size by DNS_DATA_SIZE
    if (nr == NULL) {
        return false;
    }
    memcpy(nr, query->response, DNS_HEADER_SIZE + query->data_size);
    query->data_size += DNS_DATA_SIZE;
#define RELOCATE(x) (x) = &nr->data[0] + ((x) - &query->response->data[0])
    RELOCATE(query->towire.p);
    query->towire.lim = &nr->data[0] + query->data_size;
    query->towire.p_rdlength = NULL;
    query->towire.p_opt = NULL;
    query->towire.message = nr;
    free(query->response);
    query->response = nr;
    return true;
}

void
dp_query_send_dns_response(dnssd_query_t *query)
{
    struct iovec iov;
    dns_towire_state_t *towire = &query->towire;
    const char *failnote = NULL;
    uint8_t *revert = towire->p;
    uint16_t tc = towire->truncated ? dns_flags_tc : 0;
    uint16_t bitfield = ntohs(query->response->bitfield);
    uint16_t mask = 0;

    // Send an SOA record if it's a .local query.
    if (query->iface != NULL && !towire->truncated) {
    redo:
        // DNSSD Hybrid, Section 6.1.
        TOWIRE_CHECK("&query->enclosing_domain_pointer 1", towire,
                     dns_pointer_to_wire(NULL, towire, &query->enclosing_domain_pointer));
        TOWIRE_CHECK("dns_rrtype_soa", towire,
                     dns_u16_to_wire(towire, dns_rrtype_soa));
        TOWIRE_CHECK("dns_qclass_in", towire,
                     dns_u16_to_wire(towire, dns_qclass_in));
        TOWIRE_CHECK("ttl", towire, dns_ttl_to_wire(towire, 3600));
        TOWIRE_CHECK("rdlength_begin ", towire, dns_rdlength_begin(towire));
#ifdef MY_NAME
        TOWIRE_CHECK(MY_NAME, towire, dns_full_name_to_wire(NULL, towire, MY_NAME));
#else
        TOWIRE_CHECK("\"ns\"", towire, dns_name_to_wire(NULL, towire, "ns"));
        TOWIRE_CHECK("&query->enclosing_domain_pointer 2", towire,
                     dns_pointer_to_wire(NULL, towire, &query->enclosing_domain_pointer));
#endif
        TOWIRE_CHECK("\"postmaster\"", towire,
                     dns_name_to_wire(NULL, towire, "postmaster"));
        TOWIRE_CHECK("&query->enclosing_domain_pointer 3", towire,
                     dns_pointer_to_wire(NULL, towire, &query->enclosing_domain_pointer));
        TOWIRE_CHECK("serial", towire,dns_u32_to_wire(towire, 0));     // serial 
        TOWIRE_CHECK("refresh", towire, dns_ttl_to_wire(towire, 7200));  // refresh
        TOWIRE_CHECK("retry", towire, dns_ttl_to_wire(towire, 3600));  // retry
        TOWIRE_CHECK("expire", towire, dns_ttl_to_wire(towire, 86400)); // expire
        TOWIRE_CHECK("minimum", towire, dns_ttl_to_wire(towire, 120));    // minimum
        dns_rdlength_end(towire);
        if (towire->truncated) {
            query->towire.p = revert;
            if (query->connection->tcp_stream) {
                if (embiggen(query)) {
                    query->towire.error = 0;
                    towire->truncated = false;
                    goto redo;
                }
            } else {
                tc = dns_flags_tc;
            }                
        } else {
            query->response->nscount = htons(1);
        }

        // Response is authoritative and not recursive.
        mask = ~dns_flags_ra;
        bitfield = bitfield | dns_flags_aa | tc;
        bitfield = bitfield & mask;
    } else {
        // Response is recursive and not authoritative.
	mask = ~dns_flags_aa;
        bitfield = bitfield | dns_flags_ra | tc;
        bitfield = bitfield & mask;
    }
    // Not authentic, checking not disabled.
    mask = ~(dns_flags_rd | dns_flags_ad | dns_flags_cd);
    bitfield = bitfield & mask;
    query->response->bitfield = htons(bitfield);

    // This is a response
    dns_qr_set(query->response, dns_qr_response);
    
    // Send an OPT RR if we got one
    // XXX reserve space so we can always send an OPT RR?
    if (query->is_edns0) {
    redo_edns0:
        TOWIRE_CHECK("Root label", towire, dns_u8_to_wire(towire, 0));     // Root label
        TOWIRE_CHECK("dns_rrtype_opt", towire, dns_u16_to_wire(towire, dns_rrtype_opt));
        TOWIRE_CHECK("UDP Payload size", towire, dns_u16_to_wire(towire, 4096)); // UDP Payload size
        TOWIRE_CHECK("extended-rcode", towire, dns_u8_to_wire(towire, 0));     // extended-rcode
        TOWIRE_CHECK("EDNS version 0", towire, dns_u8_to_wire(towire, 0));     // EDNS version 0
        TOWIRE_CHECK("No extended flags", towire, dns_u16_to_wire(towire, 0));    // No extended flags
        TOWIRE_CHECK("No payload", towire, dns_u16_to_wire(towire, 0));    // No payload
        if (towire->truncated) {
            query->towire.p = revert;
            if (query->connection->tcp_stream) {
                if (embiggen(query)) {
                    query->towire.error = false;
                    query->towire.truncated = false;
                    goto redo_edns0;
                }
            }
        } else {
            query->response->arcount = htons(1);
        }
    }

    if (towire->error) {
        ERROR("dp_query_send_dns_response failed on %s", failnote);
        if (tc == dns_flags_tc) {
            dns_rcode_set(query->response, dns_rcode_noerror);
        } else {
            dns_rcode_set(query->response, dns_rcode_servfail);
        }
    } else {
        // No error.
        dns_rcode_set(query->response, dns_rcode_noerror);
    }

    iov.iov_len = (query->towire.p - (uint8_t *)query->response);
    iov.iov_base = query->response;
    INFO("dp_query_send_dns_response: %s (len %zd)", query->name, iov.iov_len);

    if (query->connection != NULL) {
        query->connection->send_response(query->connection, query->question, &iov, 1);
    }

    // Free up state
    // Query will be freed automatically next time through the io loop.
    dnssd_query_cancel(&query->io);
}

void
dp_query_towire_reset(dnssd_query_t *query)
{
    query->towire.p = &query->response->data[0];  // We start storing RR data here.
    query->towire.lim = &query->response->data[0] + query->data_size; // This is the limit to how much we can store.
    query->towire.message = query->response;
    query->towire.p_rdlength = NULL;
    query->towire.p_opt = NULL;
    query->p_dso_length = NULL;
}

void
dns_push_start(dnssd_query_t *query)
{
    const char *failnote = NULL;
    
    // If we don't have a dso header yet, start one.
    if (query->p_dso_length == NULL) {
        memset(query->response, 0, (sizeof *query->response) - DNS_DATA_SIZE);
        dns_opcode_set(query->response, dns_opcode_dso);
        // This is a unidirectional DSO message, which is marked as a query
        dns_qr_set(query->response, dns_qr_query);
        // No error cuz not a response.
        dns_rcode_set(query->response, dns_rcode_noerror);

        TOWIRE_CHECK("kDSOType_DNSPushUpdate", &query->towire,
                     dns_u16_to_wire(&query->towire, kDSOType_DNSPushUpdate));
        if (query->towire.p + 2 > query->towire.lim) {
            ERROR("No room for dso length in DNS Push notification message.");
            dp_query_towire_reset(query);
            return;
        }
        query->p_dso_length = query->towire.p;
        query->towire.p += 2;
    }
    if (failnote != NULL) {
        ERROR("dns_push_start: couldn't start update: %s", failnote);
    }
}

void
dp_push_response(dnssd_query_t *query)
{
    struct iovec iov;

    if (query->p_dso_length != NULL) {
        int16_t dso_length = query->towire.p - query->p_dso_length - 2;
        iov.iov_len = (query->towire.p - (uint8_t *)query->response);
        iov.iov_base = query->response;
        INFO("dp_push_response: %s (len %zd)", query->name, iov.iov_len);

        query->towire.p = query->p_dso_length;
        dns_u16_to_wire(&query->towire, dso_length);
        if (query->connection != NULL) {
            query->connection->send_response(query->connection, query->question, &iov, 1);
        }
        dp_query_towire_reset(query);
    }
}

bool
dnssd_hardwired_response(dnssd_query_t *query, DNSServiceQueryRecordReply callback)
{
    hardwired_t *hp;
    bool got_response = false;

    for (hp = query->iface->hardwired_responses; hp; hp = hp->next) {
        if ((query->type == hp->type || query->type == dns_rrtype_any) &&
            query->qclass == dns_qclass_in && !strcasecmp(hp->name, query->name)) {
            if (query->is_dns_push) {
                dns_push_start(query);
                dp_query_add_data_to_response(query, hp->fullname, hp->type, dns_qclass_in, hp->rdlen, hp->rdata, 3600);
            } else {
                // Store the response
                if (!query->towire.truncated) {
                    dp_query_add_data_to_response(query, hp->fullname, hp->type, dns_qclass_in, hp->rdlen, hp->rdata, 3600);
                    if (!query->towire.truncated) {
                        query->response->ancount = htons(ntohs(query->response->ancount) + 1);
                    }
                }
            }
            got_response = true;
        }
    }
    if (got_response) {
        if (query->is_dns_push) {
            dp_push_response(query);
        } else {
            // Steal the question
            query->question = query->connection->message;
            query->connection->message = NULL;
            // Send the answer(s).
            dp_query_send_dns_response(query);
        }
        return true;
    }
    return false;
}

// This is the callback for dns query results.
void
dns_query_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                   const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata,
                   uint32_t ttl, void *context)
{
    dnssd_query_t *query = context;
    
    INFO("%s %d %d %x %d", fullname, rrtype, rrclass, rdlen, errorCode);

    if (errorCode == kDNSServiceErr_NoError) {
    re_add:
        dp_query_add_data_to_response(query, fullname, rrtype, rrclass, rdlen, rdata,
                                      ttl > 10 ? 10 : ttl); // Per dnssd-hybrid 5.5.1, limit ttl to 10 seconds
        if (query->towire.truncated) {
            if (query->connection->tcp_stream) {
                if (embiggen(query)) {
                    query->towire.truncated = false;
                    query->towire.error = false;
                    goto re_add;
                } else {
                    dns_rcode_set(query->response, dns_rcode_servfail);
                    dp_query_send_dns_response(query);
		    return;
	        }
            }
        } else {
            query->response->ancount = htons(ntohs(query->response->ancount) + 1);
        }
        // If there isn't more coming, send the response now
        if (!(flags & kDNSServiceFlagsMoreComing) || query->towire.truncated) {
            dp_query_send_dns_response(query);
        }
    } else if (errorCode == kDNSServiceErr_NoSuchRecord) {
        // If we get "no such record," we can't really do much except return the answer.
        dp_query_send_dns_response(query);
    } else {
        dns_rcode_set(query->response, dns_rcode_servfail);
        dp_query_send_dns_response(query);
    }
}

void
dp_query_wakeup(io_t *io)
{
    dnssd_query_t *query = (dnssd_query_t *)io;
    char name[DNS_MAX_NAME_SIZE + 1];
    int namelen = strlen(query->name);

    // Should never happen.
    if ((namelen + query->iface != NULL ? sizeof local_suffix : 0) > sizeof name) {
        ERROR("db_query_wakeup: no space to construct name.");
        dnssd_query_cancel(&query->io);
    }

    strcpy(name, query->name);
    if (query->iface != NULL) {
        strcpy(name + namelen, local_suffix);
    }
    dp_query_send_dns_response(query);
}

bool
dp_query_start(comm_t *comm, dnssd_query_t *query, int *rcode, DNSServiceQueryRecordReply callback)
{
    char name[DNS_MAX_NAME_SIZE + 1];
    char *np;

    if (query->iface != NULL) {
        if (dnssd_hardwired_response(query, callback)) {
            *rcode = dns_rcode_noerror;
            return true;
        }

        int len = strlen(query->name);
        if (len + sizeof local_suffix > sizeof name) {
            *rcode = dns_rcode_servfail;
            free(query->name);
            free(query);
            ERROR("question name %s is too long for .local.", name);
            return false;
        }
        memcpy(name, query->name, len);
        memcpy(&name[len], local_suffix, sizeof local_suffix);
        np = name;
    } else {
        np = query->name;
    }
        
    // If we get an SOA query for record that's under a zone cut we're authoritative, which
    // is the case of query->iface != NULL, then answer with a negative response that includes
    // our authority records, rather than waiting for the query to time out.
    if (query->iface != NULL && (query->type == dns_rrtype_soa ||
                                 query->type == dns_rrtype_ns ||
                                 query->type == dns_rrtype_ds) &&
        query->qclass == dns_qclass_in && query->is_dns_push == false) {
        query->question = comm->message;
        comm->message = NULL;
        dp_query_send_dns_response(query);
        return true;
    }

    // Issue a DNSServiceQueryRecord call
    int err = DNSServiceQueryRecord(&query->ref, query->serviceFlags,
                                    kDNSServiceInterfaceIndexAny, np, query->type,
                                    query->qclass, callback, query);
    if (err != kDNSServiceErr_NoError) {
        ERROR("dp_query_start: DNSServiceQueryRecord failed for '%s': %d", np, err);
        *rcode = dns_rcode_servfail;
        return false;
    } else {
        INFO("dp_query_start: DNSServiceQueryRecord started for '%s': %d", np, err);
    }
    
    // If this isn't a DNS Push subscription, we need to respond quickly with as much data as we have.  It
    // turns out that dig gives us a second, but also that responses seem to come back in on the order of a
    // millisecond, so we'll wait 100ms.
    if (!query->is_dns_push && query->iface) {
        query->io.wakeup_time = ioloop_now + IOLOOP_SECOND * 6; // [mDNSDP 5.6 p. 25]
        query->io.wakeup = dp_query_wakeup;
    }

    add_dnssd_query(query);
    return true;
}

dnssd_query_t *
dp_query_generate(comm_t *comm, dns_rr_t *question, bool dns_push, int *rcode)
{
    char name[DNS_MAX_NAME_SIZE + 1];
    interface_config_t *ifc = dp_served(question->name, name, sizeof name);

    // If it's a query for a name served by the local discovery proxy, do an mDNS lookup.
    if (ifc) {
        INFO("%s question: type %d class %d %s.%s -> %s.local", dns_push ? "push" : " dns",
             question->type, question->qclass, name, ifc->domain, name);
    } else {
        dns_name_print(question->name, name, sizeof name);
        INFO("%s question: type %d class %d %s",
             dns_push ? "push" : " dns", question->type, question->qclass, name);
    }

    dnssd_query_t *query = calloc(1,sizeof *query);
    if (query == NULL) {
    nomem:
        ERROR("Unable to allocate memory for query on %s", name);
        *rcode = dns_rcode_servfail;
        return NULL;
    }
    query->response = malloc(sizeof *query->response);
    if (query->response == NULL) {
        goto nomem;
    }
    query->data_size = DNS_DATA_SIZE;

    // Zero out the DNS header, but not the data.
    memset(query->response, 0, DNS_HEADER_SIZE);

    // Steal the data from the question.   If subdomain is not null, this is a local mDNS query; otherwise
    // we are recursing.
    INFO("name = %s", name);
    query->name = strdup(name);
    if (!query->name) {
        *rcode = dns_rcode_servfail;
        free(query);
        ERROR("unable to allocate memory for question name on %s", name);
        return NULL;
    }
    // It is safe to assume that enclosing domain will not be freed out from under us.
    query->iface = ifc;
    query->serviceFlags = 0;

    // If this is a local query, add ".local" to the end of the name and require multicast.
    if (ifc != NULL) {
        query->serviceFlags |= kDNSServiceFlagsForceMulticast;
    } else {
        query->serviceFlags |= kDNSServiceFlagsReturnIntermediates;
    }
    // Name now contains the name we want mDNSResponder to look up.

    // XXX make sure finalize does the right thing.
    query->connection = comm;

    // Remember whether this is a long-lived query.
    query->is_dns_push = dns_push;

    // Start writing the response
    dp_query_towire_reset(query);

    query->type = question->type;
    query->qclass = question->qclass;

    // Just in case we don't need to do a DNSServiceQueryRecord query to satisfy it.
    query->io.sock = -1;

    *rcode = dns_rcode_noerror;
    return query;
}

// This is the callback for DNS push query results, as opposed to push updates.
void
dns_push_query_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                        const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata,
                        uint32_t ttl, void *context)
{
    dnssd_query_t *query = context;
    uint8_t *revert = query->towire.p;
    
    // From DNSSD-Hybrid, for mDNS queries:
    // If we have cached answers, respond immediately, because we probably have all the answers.
    // If we don't have cached answers, respond as soon as we get an answer (presumably more-coming will be false).

    // The spec says to not query if we have cached answers.   We trust the DNSServiceQueryRecord call to handle this.

    // If we switch to using a single connection to mDNSResponder, we could have !more-coming trigger a flush of
    // all outstanding queries that aren't waiting on a time trigger.   This is because more-coming isn't
    // query-specific

    INFO("PUSH %s %d %d %x %d", fullname, rrtype, rrclass, rdlen, errorCode);

    // query_state_waiting means that we're answering a regular DNS question
    if (errorCode == kDNSServiceErr_NoError) {
        dns_push_start(query);

        // If kDNSServiceFlagsAdd is set, it's an add, otherwise a delete.
        re_add:
        if (flags & kDNSServiceFlagsAdd) {
            dp_query_add_data_to_response(query, fullname, rrtype, rrclass, rdlen, rdata, ttl);
        } else {
	    // There was a verion of the code that used different semantics, we use those semantics on non-tls
	    // connections for now, but should delete this soon.
	    if (query->connection->tls_context != NULL) {
                // I think if this happens it means delete all RRs of this type.
                if (rdlen == 0) {
                    dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_any, rdlen, rdata, -2);
                } else {
                    if (rdlen == 0) {
			dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_none, rdlen, rdata, -2);
		    } else {
                        dp_query_add_data_to_response(query, fullname, rrtype, rrclass, rdlen, rdata, -1);
		    }
                }
            } else {
                if (rdlen == 0) {
                    dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_any, rdlen, rdata, 0);
                } else {
                    dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_none, rdlen, rdata, 0);
                }
            }
        }
        if (query->towire.truncated) {
            query->towire.truncated = false;
            query->towire.p = revert;
            query->towire.error = 0;
            dp_push_response(query);
            dns_push_start(query);
            goto re_add;
        }

        // If there isn't more coming, send a DNS Push notification now.
        // XXX If enough comes to fill the response, send the message.
        if (!(flags & kDNSServiceFlagsMoreComing)) {
            dp_push_response(query);
        }
    } else {
        ERROR("dns_push_query_callback: unexpected error code %d", errorCode);
        if (query->connection != NULL) {
            dso_drop_activity(query->connection->dso, query->activity);
        }
    }
}

void
dns_push_subscribe(comm_t *comm, const dns_wire_t *header, dso_state_t *dso, dns_rr_t *question,
                   const char *activity_name, const char *opcode_name)
{
    int rcode;
    dnssd_query_t *query = dp_query_generate(comm, question, true, &rcode);
    
    if (!query) {
        dp_simple_response(comm, rcode);
        return;
    }

    dso_activity_t *activity = dso_add_activity(dso, activity_name, push_subscription_activity_type, query, dns_push_finalize);
    query->activity = activity;
    if (!dp_query_start(comm, query, &rcode, dns_push_query_callback)) {
        dso_drop_activity(dso, activity);
        dp_simple_response(comm, rcode);
        return;
    }
    dp_simple_response(comm, dns_rcode_noerror);
}

void
dns_push_reconfirm(comm_t *comm, const dns_wire_t *header, dso_state_t *dso)
{
    dns_rr_t question;
    char name[DNS_MAX_NAME_SIZE + 1];
    uint16_t rdlen;

    // The TLV offset should always be pointing into the message.
    unsigned offp = dso->primary.payload - &header->data[0];
    int len = offp + dso->primary.length;
    
    // Parse the name, rrtype and class.   We say there's no rdata even though there is
    // because there's no ttl and also we want the raw rdata, not parsed rdata.
    if (!dns_rr_parse(&question, header->data, len, &offp, false) ||
        !dns_u16_parse(header->data, len, &offp, &rdlen)) {
        dp_simple_response(comm, dns_rcode_formerr);
        ERROR("dns_push_reconfirm: RR parse from %s failed", dso->remote_name);
        return;
    }
    if (rdlen + offp != len) {
        dp_simple_response(comm, dns_rcode_formerr);
        ERROR("dns_push_reconfirm: RRdata parse from %s failed: length mismatch (%d != %d)",
              dso->remote_name, rdlen + offp, len);
        return;
    }

    if ((dp_served(question.name, name, sizeof name))) {
        int len = strlen(name);
        if (len + sizeof local_suffix > sizeof name) {
            dp_simple_response(comm, dns_rcode_formerr);
            ERROR("dns_push_reconfirm: name is too long for .local suffix: %s", name);
            return;
        }
        memcpy(&name[len], local_suffix, sizeof local_suffix);
    } else {
        dns_name_print(question.name, &name[8], sizeof name - 8);
    }
    // transmogrify name.
    DNSServiceReconfirmRecord(0, kDNSServiceInterfaceIndexAny, name,
                              question.type, question.qclass, rdlen, &header->data[offp]);
    dp_simple_response(comm, dns_rcode_noerror);
}

void
dns_push_unsubscribe(comm_t *comm, const dns_wire_t *header, dso_state_t *dso, dns_rr_t *question,
                   dso_activity_t *activity, const char *opcode_name)
{
    dso_drop_activity(dso, activity);
    // No response, unsubscribe is unidirectional.
}

void
dns_push_subscription_change(const char *opcode_name, comm_t *comm, const dns_wire_t *header, dso_state_t *dso)
{
    // type-in-hex/class-in-hex/name-to-subscribe
    char activity_name[DNS_MAX_NAME_SIZE_ESCAPED + 3 + 4 + 4];
    dso_activity_t *activity;
    
    // The TLV offset should always be pointing into the message.
    unsigned offp = dso->primary.payload - &header->data[0];
    // Get the question
    dns_rr_t question;

    if (!dns_rr_parse(&question, header->data, offp + dso->primary.length, &offp, false)) {
        // Unsubscribes are unidirectional, so no response can be sent
        if (dso->primary.opcode != kDSOType_DNSPushUnsubscribe) {
            dp_simple_response(comm, dns_rcode_formerr);
        }
        ERROR("RR parse for %s from %s failed", dso->remote_name, opcode_name);
        return;
    }

    // Concoct an activity name.
    snprintf(activity_name, sizeof activity_name, "%04x%04x", question.type, question.qclass);
    if ((dp_served(question.name, &activity_name[8], (sizeof activity_name) - 8))) {
        int len = strlen(activity_name);
        if (len + sizeof local_suffix + 8 > sizeof (activity_name)) {
            ERROR("activity name overflow for %s", activity_name);
            return;
        }
        const int lslen = sizeof local_suffix;
        strncpy(&activity_name[len], local_suffix, lslen);
    } else {
        dns_name_print(question.name, &activity_name[8], (sizeof activity_name) - 8);
    }
    
    activity = dso_find_activity(dso, activity_name, push_subscription_activity_type, NULL);
    if (activity == NULL) {
        // Unsubscribe with no activity means no work to do; just return noerror.
        if (dso->primary.opcode != kDSOType_DNSPushSubscribe) {
            ERROR("dso_message: %s for %s when no subscription exists.", opcode_name, activity_name);
            if (dso->primary.opcode == kDSOType_DNSPushReconfirm) {
                dp_simple_response(comm, dns_rcode_noerror);
            }
        } else {
            // In this case we have a push subscribe for which no subscription exists, which means we can do it.
            dns_push_subscribe(comm, header, dso, &question, activity_name, opcode_name);
        }
    } else {
        // Subscribe with a matching activity means no work to do; just return noerror.
        if (dso->primary.opcode == kDSOType_DNSPushSubscribe) {
            dp_simple_response(comm, dns_rcode_noerror);
        }            
        // Otherwise cancel the subscription.
        else {
            dns_push_unsubscribe(comm, header, dso, &question, activity, opcode_name);
        }
    }
}

static void dso_message(comm_t *comm, const dns_wire_t *header, dso_state_t *dso)
{
    switch(dso->primary.opcode) {
    case kDSOType_DNSPushSubscribe:
        dns_push_subscription_change("DNS Push Subscribe", comm, header, dso);
        break;
    case kDSOType_DNSPushUnsubscribe:
        dns_push_subscription_change("DNS Push Unsubscribe", comm, header, dso);
        break;

    case kDSOType_DNSPushReconfirm:
        dns_push_reconfirm(comm, header, dso);
        break;
        
    case kDSOType_DNSPushUpdate:
        INFO("dso_message: bogus push update message %d", dso->primary.opcode);
        dso_drop(dso);
        break;

    default:
        INFO("dso_message: unexpected primary TLV %d", dso->primary.opcode);
        dp_simple_response(comm, dns_rcode_dsotypeni);
        break;
    }
    // XXX free the message if we didn't consume it.
}

static void dns_push_callback(void *context, const void *event_context,
                              dso_state_t *dso, dso_event_type_t eventType)
{
    const dns_wire_t *message;
    switch(eventType)
    {
    case kDSOEventType_DNSMessage:
        // We shouldn't get here because we already handled any DNS messages
        message = event_context;
        INFO("dns_push_callback: DNS Message (opcode=%d) received from %s", dns_opcode_get(message), dso->remote_name);
        break;
    case kDSOEventType_DNSResponse:
        // We shouldn't get here because we already handled any DNS messages
        message = event_context;
        INFO("dns_push_callback: DNS Response (opcode=%d) received from %s", dns_opcode_get(message), dso->remote_name);
        break;
    case kDSOEventType_DSOMessage:
        INFO("dns_push_callback: DSO Message (Primary TLV=%d) received from %s",
               dso->primary.opcode, dso->remote_name);
        message = event_context;
        dso_message((comm_t *)context, message, dso);
        break;
    case kDSOEventType_DSOResponse:
        INFO("dns_push_callback: DSO Response (Primary TLV=%d) received from %s",
               dso->primary.opcode, dso->remote_name);
        break;

    case kDSOEventType_Finalize:
        INFO("dns_push_callback: Finalize");
        break;

    case kDSOEventType_Connected:
        INFO("dns_push_callback: Connected to %s", dso->remote_name);
        break;

    case kDSOEventType_ConnectFailed:
        INFO("dns_push_callback: Connection to %s failed", dso->remote_name);
        break;

    case kDSOEventType_Disconnected:
        INFO("dns_push_callback: Connection to %s disconnected", dso->remote_name);
        break;
    case kDSOEventType_ShouldReconnect:
        INFO("dns_push_callback: Connection to %s should reconnect (not for a server)", dso->remote_name);
        break;
    case kDSOEventType_Inactive:
        INFO("dns_push_callback: Inactivity timer went off, closing connection.");
        // XXX
        break;
    case kDSOEventType_Keepalive:
        INFO("dns_push_callback: should send a keepalive now.");
        break;
    case kDSOEventType_KeepaliveRcvd:
        INFO("dns_push_callback: keepalive received.");
        break;
    case kDSOEventType_RetryDelay:
        INFO("dns_push_callback: keepalive received.");
        break;
    }
}

void
dp_dns_query(comm_t *comm, dns_rr_t *question)
{
    int rcode;
    dnssd_query_t *query = dp_query_generate(comm, question, false, &rcode);
    const char *failnote = NULL;
    if (!query) {
        dp_simple_response(comm, rcode);
        return;
    }

    // For regular DNS queries, copy the ID, etc.
    query->response->id = comm->message->wire.id;
    query->response->bitfield = comm->message->wire.bitfield;
    dns_rcode_set(query->response, dns_rcode_noerror);

    // For DNS queries, we need to return the question.
    query->response->qdcount = htons(1);
    if (query->iface != NULL) {
        TOWIRE_CHECK("name", &query->towire, dns_name_to_wire(NULL, &query->towire, query->name));
        TOWIRE_CHECK("enclosing_domain", &query->towire,
                     dns_full_name_to_wire(&query->enclosing_domain_pointer,
                                           &query->towire, query->iface->domain));
    } else {
        TOWIRE_CHECK("full name", &query->towire, dns_full_name_to_wire(NULL, &query->towire, query->name));
    }        
    TOWIRE_CHECK("TYPE", &query->towire, dns_u16_to_wire(&query->towire, question->type));    // TYPE
    TOWIRE_CHECK("CLASS", &query->towire, dns_u16_to_wire(&query->towire, question->qclass));  // CLASS
    if (failnote != NULL) {
        ERROR("dp_dns_query: failure encoding question: %s", failnote);
        goto fail;
    }
    
    // We should check for OPT RR, but for now assume it's there.
    query->is_edns0 = true;

    if (!dp_query_start(comm, query, &rcode, dns_query_callback)) {
    fail:
        dp_simple_response(comm, rcode);
        free(query->name);
        free(query);
        return;
    }
    
    // XXX make sure that finalize frees this.
    if (comm->message) {
        query->question = comm->message;
        comm->message = NULL;
    }
}

void dso_transport_finalize(comm_t *comm)
{
    dso_state_t *dso = comm->dso;
    INFO("dso_transport_finalize: %s", dso->remote_name);
    if (comm) {
        ioloop_close(&comm->io);
    }
    free(dso);
    comm->dso = NULL;
}

void dns_evaluate(comm_t *comm)
{
    dns_rr_t question;
    unsigned offset = 0;

    // Drop incoming responses--we're a server, so we only accept queries.
    if (dns_qr_get(&comm->message->wire) == dns_qr_response) {
        return;
    }

    // If this is a DSO message, see if we have a session yet.
    switch(dns_opcode_get(&comm->message->wire)) {
    case dns_opcode_dso:
        if (!comm->tcp_stream) {
            ERROR("DSO message received on non-tcp socket %s", comm->name);
            dp_simple_response(comm, dns_rcode_notimp);
            return;
        }
        
        if (!comm->dso) {
            comm->dso = dso_create(true, 0, comm->name, dns_push_callback, comm, comm);
            if (!comm->dso) {
                ERROR("Unable to create a dso context for %s", comm->name);
                dp_simple_response(comm, dns_rcode_servfail);
                ioloop_close(&comm->io);
                return;
            }
            comm->dso->transport_finalize = dso_transport_finalize;
        }
        dso_message_received(comm->dso, (uint8_t *)&comm->message->wire, comm->message->length);
        break;

    case dns_opcode_query:
        // In theory this is permitted but it can't really be implemented because there's no way
        // to say "here's the answer for this, and here's why that failed.
        if (ntohs(comm->message->wire.qdcount) != 1) {
            dp_simple_response(comm, dns_rcode_formerr);
            return;
        }
        if (!dns_rr_parse(&question, comm->message->wire.data, comm->message->length, &offset, 0)) {
            dp_simple_response(comm, dns_rcode_formerr);
            return;
        }
        dp_dns_query(comm, &question);
        dns_rrdata_free(&question);
        break;

        // No support for other opcodes yet.
    default:
        dp_simple_response(comm, dns_rcode_notimp);
        break;
    }
}

void dns_input(comm_t *comm)
{
    dns_evaluate(comm);
    if (comm->message != NULL) {
        message_free(comm->message);
        comm->message = NULL;
    }
}

static int
usage(const char *progname)
{
    ERROR("usage: %s", progname);
    ERROR("ex: dnssd-proxy");
    return 1;
}

// Called whenever we get a connection.
void
connected(comm_t *comm)
{
    INFO("connection from %s", comm->name);
    return;
}

static bool config_string_handler(char **ret, const char *filename, const char *string, int lineno, bool tdot, bool ldot)
{
    char *s;
    int add_trailing_dot = 0;
    int add_leading_dot = ldot ? 1 : 0;
    int len = strlen(string);

    // Space for NUL and leading dot.
    if (len > 0 && string[len - 1] != '.') {
        add_trailing_dot = 1;
    }
    s = malloc(strlen(string) + add_leading_dot + add_trailing_dot + 1);
    if (s == NULL) {
        ERROR("Unable to allocate domain name %s", string);
        return false;
    }
    *ret = s;
    if (ldot) {
        *s++ = '.';
    }
    strcpy(s, string);
    if (add_trailing_dot) {
        s[len] = '.';
        s[len + 1] = 0;
    }
    return true;
}

// Config file parsing...
static bool interface_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    interface_config_t *ifc = calloc(1, sizeof *ifc);
    if (ifc == NULL) {
        ERROR("Unable to allocate interface %s", hunks[1]);
        return false;
    }
    ifc->name = strdup(hunks[1]);
    if (ifc->name == NULL) {
        ERROR("Unable to allocate interface name %s", hunks[1]);
    }
    if (!config_string_handler(&ifc->domain_ld, filename, hunks[2], lineno, true, true)) {
        return false;
    }
    ifc->domain = ifc->domain_ld + 1;
    ifc->domain_name = dns_pres_name_parse(ifc->domain);
    if (ifc->domain_name == NULL) {
        ERROR("invalid domain name for interface %s: %s", hunks[1], hunks[2]);
    }
    ifc->next = interfaces;
    interfaces = ifc;
    if (!strcmp(hunks[0], "nopush")) {
        ifc->no_push = true;
    }
    return true;
}

static bool port_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    char *ep = NULL;
    long port = strtol(hunks[1], &ep, 10);
    if (port < 0 || port > 65535 || *ep != 0) {
        ERROR("Invalid port number: %s", hunks[1]);
        return false;
    }
    if (!strcmp(hunks[0], "udp-port")) {
        udp_port = port;
    } else if (!strcmp(hunks[0], "tcp-port")) {
        tcp_port = port;
    } else if (!strcmp(hunks[0], "tls-port")) {
        tls_port = port;
    }
    return true;
}

static bool my_name_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&my_name, filename, hunks[1], lineno, true, false);
}

static bool my_ipv4_addr_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&my_ipv4_addr, filename, hunks[1], lineno, false, false);
}

static bool my_ipv6_addr_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&my_ipv6_addr, filename, hunks[1], lineno, false, false);
}

config_file_verb_t dp_verbs[] = {
    { "interface",    3, 3, interface_handler },    // interface <name> <domain>
    { "nopush",       3, 3, interface_handler },    // nopush <name> <domain>
    { "udp-port",     2, 2, port_handler },         // udp-port <number>
    { "tcp-port",     2, 2, port_handler },         // tcp-port <number>
    { "tls-port",     2, 2, port_handler },         // tls-port <number>
    { "my-name",      2, 2, my_name_handler },      // my-name <domain name>
    { "my-ipv4-addr", 2, 2, my_ipv4_addr_handler }, // my-ipv4-addr <IPv4 address>
    { "my-ipv6-addr", 2, 2, my_ipv6_addr_handler }  // my-ipv6-addr <IPv6 address>
};
#define NUMCFVERBS ((sizeof dp_verbs) / sizeof (config_file_verb_t))

int
main(int argc, char **argv)
{
    int i;
    comm_t *tls4_listener;
    comm_t *tcp4_listener;
    comm_t *udp4_listener;

    udp_port = tcp_port = htons(53);
    tls_port = htons(853);

    // Read the configuration from the command line.
    for (i = 1; i < argc; i++) {
        return usage(argv[0]);
    }

    // Read the config file
    if (!config_parse(NULL, "/etc/dnssd-proxy.cf", dp_verbs, NUMCFVERBS)) {
        return 1;
    }
    
    if (!srp_tls_init()) {
        return 1;
    }

    if (!ioloop_init()) {
        return 1;
    }

    // Set up hardwired answers
    dnssd_hardwired_setup();

    // XXX Support IPv6!
    tcp4_listener = setup_listener_socket(AF_INET, IPPROTO_TCP, false, tcp_port, "IPv4 DNS Push Listener", dns_input, connected, 0);
    if (tcp4_listener == NULL) {
        ERROR("TCPv4 listener: fail.");
        return 1;
    }
    
    udp4_listener = setup_listener_socket(AF_INET, IPPROTO_UDP, false, udp_port, "IPv4 DNS UDP Listener", dns_input, 0, 0);
    if (udp4_listener == NULL) {
        ERROR("UDP4 listener: fail.");
        return 1;
    }
    
    tls4_listener = setup_listener_socket(AF_INET, IPPROTO_TCP, true, tls_port, "IPv4 DNS TLS Listener", dns_input, connected, 0);
    if (udp4_listener == NULL) {
        ERROR("TLS4 listener: fail.");
        return 1;
    }
    
    (void)tcp4_listener;
    (void)udp4_listener;
    (void)tls4_listener;

    do {
        int something = 0;
        something = ioloop_events(0);
        INFO("dispatched %d events.", something);
    } while (1);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
