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

typedef struct srp_mdns_registration srp_mdns_registration_t;
struct srp_mdns_registration {
    srp_mdns_update_t *next;
    DNSServiceRef *ref;
    dns_host_description_t *NONNULL host;
    service_instance_t *NONNULL instances;
} *registrations;

typedef struct srp_mdns_registration_item srp_mdns_registration_item_t;
struct srp_mdns_registration_item {
    DNSRegisterRef ref;
    void *item;
    dns_rr_t *NULLABLE rr;
    enum { item_type_host, item_type_service, item_type_instance } item_type;
};

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
        // This is O(n^2), but n is usually 1, and can't get very big.
        for (reg_instance = reg->instances; reg_instance; reg_instance = reg_instance->next) {
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
                        return false;
                    }
                    goto present;
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
            return false;
        }
    }

    // If we fall out the bottom of this loop, it means that there is no matching host entry
    // and no conflicting service instance, so we need to just make one.  At this point, regs
    // is pointing to the end of the list.
    reg = calloc(1, sizeof *reg);
    reg->host = host;

    // Tack this on to the end of the list.
    *regs = reg;
    regs = NULL;

    // If this is a host we haven't seen before, claim its name.
    add_host(reg);

    // If we jump to present, it means that there is a matching host entry in reg, with the right key.
    if (false) {
    present:
        // Go through the list of records in the new host; for each record that exists in the old and not in
        // the new, stop advertising that record.   For each that exists in the new and not in the old, start
        // advertising it.   Anything that's unchanged requires no action.
    }
    
    // Now go through the service instances; for each service instance that's new, add it.   Service instances
    // that are not present in the update, and instances that are present both in the update and the current
    // published set for this host (if any) require no action.

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
