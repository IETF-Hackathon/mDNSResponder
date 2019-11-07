/* srp-mproxy.c
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
 * This file contains support routines for the DNSSD SRP update and mDNS proxies.
 */

#define __APPLE_USE_RFC_3542

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/time.h>

#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"
#include "dnssd-proxy.h"
#include "srp-gw.h"
#include "config-parse.h"

typedef struct srp_mdns_registration_item srp_mdns_registration_item_t;
struct srp_mdns_registration_item {
    DNSRegisterRef ref;     // The registration
    void *item;             // The item being updated (which may have multiple RRs)
    dns_rr_t *NONNULL rr;   // The RR from the SRP update.
    enum { item_type_host, item_type_service, item_type_instance } item_type;
};

// This is a completed registration.  We have DNSUpdateRefs for each "update" in the registration, and a
// DNSServiceRef that covers all of the updates in the registration.
struct srp_mdns_registration {
    // Registrations are kept in a linked list.
    srp_mdns_registration_t *next;

    // This is the steady state of the registration
    DNSServiceRef *ref;
    dns_host_description_t *NONNULL host;        // The host for which this registration exists.
    service_instance_t *NONNULL instances;       // The service instances offered by this host
    service_t *NONNULL service;                  // The full set of services offered by this host
    srp_mdns_registration_item_t *registrations; // Registrations that have succeeded and are active.

    // If we have received an update for the host for which this registration exists, and that update
    // is in progress, the transaction ID will be other than -1, and the pointers below will be non-null;
    // the transaction is done when we've gotten a successful callback on every record registration.
    // A failure on any registration means that the update failed.   We keep the update state here
    // because there can never be more than one update in progress (at present) and we need to be
    // able to start the update over if we lose our connection to mDNSResponder.
    srp_mdns_registration_item_t *registrations; // All of the registrations in this update, complete or not.
    service_instance_t *new_instances;           // New service instances being added
    service_t *new_services;                     // New services
    host_addr_t *new_addresses;                  // Addresses being added
    host_addr_t *remove_addresses;               // Addresses being removed
    int outstanding_registrations;               // Number of registrations that haven't completed
    int xid;                                     // A DNS xid (16 bits) or else -1 if no update is happening
} *registrations;

void
advertise_finished(comm_t *connection, message_t *message, int rcode)
{
    struct iovec iov;
    dns_wire_t response;
    INFO("Update Finished, rcode = %s", dns_rcode_name(rcode));
    
    memset(&response, 0, DNS_HEADER_SIZE);
    response.id = message->wire.id;
    response.bitfield = message->wire.bitfield;
    dns_rcode_set(&response, rcode);
    
    iov.iov_base = &response;
    iov.iov_len = DNS_HEADER_SIZE;

    connection->send_response(connection, message, &iov, 1);
}

// Given a list of existing entries and a list of new entries, take all the entries that are on the new entry
// list but not the existing entry list and move them to the missing entry list, which is returned.

static void *
extract_missing_entries(void *vnew, void *vexisting, bool (*isequal)(void *a, void *b))
{
    typedef struct list list_t;
    struct list {
        list_t *next;
    };
    list_t *existing_entries, *entry, **new_entry_pointer, **missing_entry_pointer, *missing_entries;

    missing_entry_pointer = &missing_entries;
    new_entry_pointer = vnew;
    existing_entries = vexisting;

    // For each entry on the new entry list, see if it's already on the existing entry list.
    while (*new_entry_pointer) {
        list_t *new_entry = *new_entry_pointer;
        for (entry = existing_entries; entry; entry = entry->next) {
            if (isequal(entry, new_entry)) {
                break;
            }
        }
        // If it's not on the existing entry list, move it from the new entry list to the
        // missing entry list.
        if (entry == NULL) {
            *missing_entry_pointer = new_entry;
            *new_entry_pointer = new_entry->next;
            missing_entry_pointer = &new_entry->next;
            *missing_entry_pointer = NULL;
        } else {
            new_entry_pointer = *new_entry->next;
        }
    }
    return missing_entry_pointer;
}

// Compare function for finding missing service instances
bool
compare_instances(void *a, void *b)
{
    service_instance_t *s1, *s2;
    s1 = a;
    s2 = b;
    return dns_names_equal(s1->name, s2->name)
}

// Compare function for finding missing addresses
bool compare_host_addresses(void *a, void *b)
{
    host_addr_t *a1, *a2;
    a1 = a;
    a2 = b;
    if (a->rr.type == b->rr.type && a->rr.qclass == b->rr.qclass) {
        if (a->rr.type == dns_rrtype_a) {
            return !memcmp(&a->rr.data.a, &b->rr.data.a, sizeof a->rr.data.a);
        } else if (a->rr.type == dns_rrtype_aaaa) {
            return !memcmp(&a->rr.data.aaaa, &b->rr.data.aaaa, sizeof a->rr.data.aaaa);
        }
    }
    return false;
}

bool
srp_update_start(comm_t *connection, dns_message_t *parsed_message, dns_host_description_t *host,
                 service_instance_t *instances, service_t *services, dns_name_t *update_zone)
{
    dns_addr_reg_t *areg;
    int len;
    const char local_suffix[] = ".local";
    static int ifindex = -1;
    DNSServiceErrorType err;
    srp_mdns_registration_t **regs, *reg;
    char host_name[DNS_MAX_NAME_SIZE + 1];
    int i;
    service_instance_t **new_instance_pointer, **instance_pointer, *instance, *new_instance;
    
    if (ifindex == -1) {
        ifindex = if_nametoindex("en0");
    }

    // Is there a matching host entry?
    // If no, are there any matching service instances pointing to different hosts?
    // If yes, we have to reject the update.
    // If no, then we have to:
    // - Update the host entry
    // - Update any service instance entries
    // - Add or remove any missing service pointers
    // Does SRP currently support removal?
    // SRP doesn't currently support removal.   I think it needs to, but I'm going to leave that out of
    // this code for now.


#define GEN_NAME(name, buffer, description)                                 \
    dns_name_print(name, buffer, sizeof buffer);                            \
    len = strlen(buffer);                                                   \
    if (len + (sizeof local_suffix) + 1 >= sizeof buffer) {                 \
        ERROR(description " is too long for .local (how'd that happen?)."); \
        return false;                                                       \
    }                                                                       \
    strcpy(buffer + len, local_suffix);

    GEN_NAME(host->name, host_name, "Hostname");

    // Look for matching service instance names.   A service instance name that matches, but has a different
    // hostname, means that there is a conflict.   We have to look through all the entries; the presence of
    // a matching hostname doesn't mean we are done UNLESS there's a matching service instance name pointing
    // to that hostname.
    for (regs = &registrations; *regs; regs = &reg->next) {
        reg = *regs;
        // We need to look for matches both in the registered instances for this registration, and also in
        // the list of new instances, in case we get a duplicate update while a previous update is in progress.
        for (i = 0; i < 2; i++) {
            // This is O(n^2), but n is usually 1, and can't get very big.
            for (reg_instance = i ? reg->instances : reg->new_instances;
                 reg_instance; reg_instance = reg_instance->next) {
                for (new_instance = instances; new_instance; new_instance = new_instance->next) {
                    if (dns_names_equal(reg_instance->name, new_instance->name)) {
                        if (!dns_names_equal(reg->host->name, host->name)) {
                            char instance_name[DNS_MAX_NAME_SIZE + 1];
                            char reg_host_name[DNS_MAX_NAME_SIZE + 1];
                            char new_host_name[DNS_MAX_NAME_SIZE + 1];
                            dns_name_print(reg_instance->name, instance_name, sizeof instance_name)
                                dns_name_print(reg->host->name, reg_host_name, sizeof reg_host_name);
                            dns_name_print(host->name, new_host_name, sizeof new_host_name);
                            ERROR("Service instance name %s already pointing to host %s, not host %s",
                                  instance_name, reg_host_name, new_host_name);
                            advertise_finished(connection, connection->message, dns_rcode_yxdomain);
                            goto fail;
                        }
                        goto present;
                    } 
               }
            }
        }
    }

    // If we fall off the end looking for a matching service instance, there isn't a matching
    // service instance, but there may be a matching host, so look for that.
    for (regs = &registrations; *regs; regs = &reg->next) {
        reg = *regs;
        if (dns_names_equal(reg->host->name, host->name)) {
            if (dns_keys_equal(reg->host->key, host->key)) {
                goto present;
            }
            ERROR("Update for host %s doesn't have the right key.", host_name);
            advertise_finished(connection, connection->message, dns_rcode_yxdomain);
            goto fail;
        }
    }

    // If we fall out the bottom of this loop, it means that there is no matching host entry
    // and no conflicting service instance, so we need to just make one.  At this point, regs
    // is pointing to the end of the list.
    reg = calloc(1, sizeof *reg);
    reg->host = host;
    reg->new_instances = instances;
    instances = NULL;
    reg->new_addrs = host->addrs;
    host->addrs = NULL;
    reg->new_services = services;
    services = NULL;

    // Tack this on to the end of the list.
    *regs = reg;
    regs = NULL;

    // If we jump to present, it means that there is a matching host entry in reg, with the right key.
    if (false) {
    present:
        // If we already have an update in progress, we can't do this one.
        if (reg->xid != -1) {
            // If it's a retransmission, that's okay--we can just ignore it because when the current update
            // finished we'll respond to that xid (or, if it's a spoofed message with the same xid, then the
            // attacker just won't get a reply, which is also fine).
            if (reg->xid == parsed_message->wire->xid) {
                INFO("dropping retranmission of in-progress update for host %s",
                     dns_name_print(reg->host->name, host_name, sizeof host_name));
            fail:
                srp_update_free_parts(service_instances, NULL, services, host);
                dns_message_free(parsed_message);
                return true;
            }

            // If it's an update right at the back of another update for the same host, we're going to
            // treat it as an error for now.  It's conceivable that an implementation might try to register
            // multiple services for the same host sequentially without waiting for acknowledgment of the
            // previous update.   In theory if these updates don't conflict we could handle it, but that
            // would be a lot more complicated, so for now we don't handle this case.
            ERROR("Dropping update for host %s because another update is still in progress.",
                     dns_name_print(reg->host->name, host_name, sizeof host_name));
            advertise_finished(connection, connection->message, dns_rcode_refused);
            goto fail;
        }
        
        reg->new_instances = extract_missing_entries(instances, &reg->instances, compare_instances)
    }

    // If this isn't a new registration, we may need to update the A and/or AAAA records.
    if (reg->host != host) {
        // Find address records to add
        reg->new_addresses = extract_missing_entries(host->addrs, &reg->host->addrs, compare_host_addresses);
        // Find address records to remove
        reg->remove_addresses = extract_missing_entries(reg->host->addrs, host->addrs, compare_host_addresses);
    }
    
    // Go through all the addresses to add and add them
    // Go through all the addresses to remove and remove them

    // Now go through the new service instances and add their records.   We've already figured out which
    // instances are new.

    // Now go through the services; for each service that's new, add it; services that aren't new require
    // no action.

}

int
main(int argc, char **argv)
{
    int i;
    uint16_t port;

    if (!ioloop_init()) {
        return 1;
    }

    if (!srp_proxy_listen()) {
        return 1;
    }

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
