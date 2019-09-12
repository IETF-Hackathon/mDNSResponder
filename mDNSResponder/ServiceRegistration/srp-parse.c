/* srp-parse.c
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

static dns_name_t *service_update_zone; // The zone to update when we receive an update for default.service.arpa.

// Free the data structures into which the SRP update was parsed.   The pointers to the various DNS objects that these
// structures point to are owned by the parsed DNS message, and so these do not need to be freed here.
void
srp_update_free_parts(service_instance_t *service_instances, service_instance_t *added_instances,
                      service_t *services, dns_host_description_t *host_description)
{
    service_instance_t *sip;
    service_t *sp;

    for (sip = service_instances; sip; ) {
        service_instance_t *next = sip->next;
        free(sip);
        sip = next;
    }
    for (sip = added_instances; sip; ) {
        service_instance_t *next = sip->next;
        free(sip);
        sip = next;
    }
    for (sp = services; sp; ) {
        service_t *next = sp->next;
        free(sp);
        sp = next;
    }
    if (host_description != NULL) {
        dns_addr_reg_t *reg, *next;
        for (reg = host_description->a; reg; reg = next) {
            next = reg->next;
            free(reg);
        }
        for (reg = host_description->aaaa; reg; reg = next) {
            next = reg->next;
            free(reg);
        }
        free(host_description);
    }
}

// Free all the stuff that we accumulated while processing the SRP update.
void
srp_update_free(update_t *update)
{
    // Free all of the structures we collated RRs into:
    srp_update_free_parts(update->instances, update->added_instances, update->services, update->host);
    // We don't need to free the zone name: it's either borrowed from the message,
    // or it's service_update_zone, which is static.
    message_free(update->message);
    dns_message_free(update->parsed_message);
    free(update);
}

bool add_addr_reg(dns_addr_reg_t **dest, dns_rr_t *rr)
{
    dns_addr_reg_t *reg = calloc(1, sizeof *reg);
    if (reg == NULL) {
        ERROR("add_addr_reg: no memory for record");
        return false;
    }

    while (*dest) {
        dest = &(*dest)->next;
    }
    *dest = reg;
    reg->rr = rr;
    return true;
}

bool
replace_zone_name(dns_name_t **nzp_in, dns_name_t *uzp, dns_name_t *replacement_zone)
{
    dns_name_t **nzp = nzp_in;
    while (*nzp != NULL && *nzp != uzp) {
        nzp = &((*nzp)->next);
    }
    if (*nzp == NULL) {
        ERROR("replace_zone: dns_name_subdomain_of returned bogus pointer.");
        return false;
    }

    // Free the suffix we're replacing
    dns_name_free(*nzp);

    // Replace it.
    *nzp = dns_name_copy(replacement_zone);
    if (*nzp == NULL) {
        ERROR("replace_zone_name: no memory for replacement zone");
        return false;
    }
    return true;
}


bool
srp_evaluate(comm_t *comm, dns_message_t *message)
{
    int i;
    dns_host_description_t *host_description = NULL;
    delete_t *deletes = NULL, *dp, **dpp = &deletes;
    service_instance_t *service_instances = NULL, *sip, **sipp = &service_instances;
    service_t *services = NULL, *sp, **spp = &services;
    dns_rr_t *signature;
    dns_rr_t *key;
    char namebuf[DNS_MAX_NAME_SIZE + 1], namebuf1[DNS_MAX_NAME_SIZE + 1];
    bool ret = false;
    struct timeval now;
    dns_name_t *update_zone, *replacement_zone;
    dns_name_t *uzp;
    dns_rr_t *key = NULL;
    dns_rr_t **keys = NULL;
    int num_keys = 0;
    int max_keys = 1;
    bool found_key = false;

    // Update requires a single SOA record as the question
    if (message->qdcount != 1) {
        ERROR("srp_evaluate: update received with qdcount > 1");
        return false;
    }
 
    // Update should contain zero answers.
    if (message->ancount != 0) {
        ERROR("srp_evaluate: update received with ancount > 0");
        return false;
    }

    if (message->questions[0].type != dns_rrtype_soa) {
        ERROR("srp_evaluate: update received with rrtype %d instead of SOA in question section.",
              message->questions[0].type);
        return false;
    }

    update_zone = message->questions[0].name;
    if (service_update_zone != NULL && dns_names_equal_text(update_zone, "default.service.arpa.")) {
        replacement_zone = service_update_zone;
    } else {
        replacement_zone = NULL;
    }

    // Scan over the authority RRs; do the delete consistency check.  We can't do other consistency checks
    // because we can't assume a particular order to the records other than that deletes have to come before
    // adds.
    for (i = 0; i < message->nscount; i++) {
        dns_rr_t *rr = &message->authority[i];

        // If this is a delete for all the RRs on a name, record it in the list of deletes.
        if (rr->type == dns_rrtype_any && rr->qclass == dns_qclass_any && rr->ttl == 0) {
            for (dp = deletes; dp; dp = dp->next) {
                if (dns_names_equal(dp->name, rr->name)) {
                    ERROR("srp_evaluate: two deletes for the same name: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
            }
            dp = calloc(sizeof *dp, 1);
            if (!dp) {
                ERROR("srp_evaluate: no memory.");
                goto out;
            }
            *dpp = dp;
            dpp = &dp->next;

            // Make sure the name is a subdomain of the zone being updated.
            dp->zone = dns_name_subdomain_of(rr->name, update_zone);
            if (dp->zone == NULL) {
                ERROR("srp_evaluate: delete for record not in update zone %s: %s",
                      dns_name_print(update_zone, namebuf1, sizeof namebuf),
                      dns_name_print(rr->name, namebuf, sizeof namebuf));
                goto out;
            }
            dp->name = rr->name;
        }

        // The update should really only contain one key, but it's allowed for keys to appear on
        // service instance names as well, since that's what will be stored in the zone.   So if
        // we get one key, we'll assume it's a host key until we're done scanning, and then check.
        // If we get more than one, we allocate a buffer and store all the keys so that we can
        // check them all later.
        else if (rr->type == dns_rrtype_key) {
            if (num_keys == 1) {
                key = rr;
            } else {
                if (num_keys == 1) {
                    // We can't have more keys than there are authority records left, plus
                    // one for the key we already have, so allocate a buffer that large.
                    max_keys = message->nscount - i + 1;
                    keys = calloc(max_keys, sizeof *keys);
                    if (keys == NULL) {
                        ERROR("srp_evaluate: no memory");
                        goto out;
                    }
                    keys[0] = key;
                }
                if (num_keys >= max_keys) {
                    ERROR("srp_evaluate: coding error in key allocation");
                    goto out;
                }
                keys[num_keys++] = rr;
            }
        }
                    
        // Otherwise if it's an A or AAAA record, it's part of a hostname entry.
        else if (rr->type == dns_rrtype_a || rr->type == dns_rrtype_aaaa) {
            // Allocate the hostname record
            if (!host_description) {
                host_description = calloc(sizeof *host_description, 1);
                if (!host_description) {
                    ERROR("srp_evaluate: no memory");
                    goto out;
                }
            }

            // Make sure it's preceded by a deletion of all the RRs on the name.
            if (!host_description->delete) {
                for (dp = deletes; dp; dp = dp->next) {
                    if (dns_names_equal(dp->name, rr->name)) {
                        break;
                    }
                }
                if (dp == NULL) {
                    ERROR("srp_evaluate: ADD for hostname %s without a preceding delete.",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                host_description->delete = dp;
                host_description->name = dp->name;
                dp->consumed = true; // This delete is accounted for.

                // In principle, we should be checking this name to see that it's a subdomain of the update
                // zone.  However, it turns out we don't need to, because the /delete/ has to be a subdomain
                // of the update zone, and we won't find that delete if it's not present.
            }
                          
            if (rr->type == dns_rrtype_a) {
                if (!add_addr_reg(&host_description->a, rr)) {
                    goto out;
                }
            } else if (rr->type == dns_rrtype_aaaa) {
                if (!add_addr_reg(&host_description->aaaa, rr)) {
                    goto out;
                }
            }
        }

        // Otherwise if it's an SRV entry, that should be a service instance name.
        else if (rr->type == dns_rrtype_srv || rr->type == dns_rrtype_txt) {
            // Should be a delete that precedes this service instance.
            for (dp = deletes; dp; dp = dp->next) {
                if (dns_names_equal(dp->name, rr->name)) {
                    break;
                }
            }
            if (dp == NULL) {
                ERROR("srp_evaluate: ADD for service instance not preceded by delete: %s",
                      dns_name_print(rr->name, namebuf, sizeof namebuf));
                goto out;
            }
            for (sip = service_instances; sip; sip = sip->next) {
                if (dns_names_equal(sip->name, rr->name)) {
                    break;
                }
            }
            if (!sip) {
                sip = calloc(sizeof *sip, 1);
                if (sip == NULL) {
                    ERROR("srp_evaluate: no memory");
                    goto out;
                }
                sip->delete = dp;
                dp->consumed = true;
                sip->name = dp->name;
                *sipp = sip;
                sipp = &sip->next;
            }
            if (rr->type == dns_rrtype_srv) {
                if (sip->srv != NULL) {
                    ERROR("srp_evaluate: more than one SRV rr received for service instance: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                sip->srv = rr;
            } else if (rr->type == dns_rrtype_txt) {
                if (sip->txt != NULL) {
                    ERROR("srp_evaluate: more than one SRV rr received for service instance: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                }
                sip->txt = rr;
            }
        }

        // Otherwise if it's a PTR entry, that should be a service name
        else if (rr->type == dns_rrtype_ptr) {
            sp = calloc(sizeof *sp, 1);
            if (sp == NULL) {
                ERROR("srp_evaluate: no memory");
                goto out;
            }
            *spp = sp;
            spp = &sp->next;
            sp->rr = rr;

            // Make sure the service name is in the update zone.
            sp->zone = dns_name_subdomain_of(sp->rr->name, update_zone);
            if (sp->zone == NULL) {
                ERROR("srp_evaluate: service name %s for %s is not in the update zone",
                      dns_name_print(rr->name, namebuf, sizeof namebuf),
                      dns_name_print(rr->data.ptr.name, namebuf1, sizeof namebuf1));
                goto out;
            }
        }            

        // Otherwise it's not a valid update
        else {
            ERROR("srp_evaluate: unexpected rrtype %d on %s in update.", rr->type,
                      dns_name_print(rr->name, namebuf, sizeof namebuf));
            goto out;
        }
    }

    // Now that we've scanned the whole update, do the consistency checks for updates that might
    // not have come in order.
    
    // First, make sure there's a host description.
    if (host_description == NULL) {
        ERROR("srp_evaluate: SRP update does not include a host description.");
        goto out;
    }

    // Make sure that each service add references a service instance that's in the same update.
    for (sp = services; sp; sp = sp->next) {
        for (sip = service_instances; sip; sip = sip->next) {
            if (dns_names_equal(sip->name, sp->rr->data.ptr.name)) {
                // Note that we have already verified that there is only one service instance
                // with this name, so this could only ever happen once in this loop even without
                // the break statement.
                sip->service = sp;
                sip->num_instances++;
                break;
            }
        }
        // If this service doesn't point to a service instance that's in the update, then the
        // update fails validation.
        if (sip == NULL) {
            ERROR("srp_evaluate: service %s points to an instance that's not included: %s",
                  dns_name_print(sp->rr->name, namebuf, sizeof namebuf),
                  dns_name_print(sip->name, namebuf1, sizeof namebuf1));
            goto out;
        }
    }

    for (sip = service_instances; sip; sip = sip->next) {
        // For each service instance, make sure that at least one service references it
        if (sip->num_instances == 0) {
            ERROR("srp_evaluate: service instance update for %s is not referenced by a service update.",
                  dns_name_print(sip->name, namebuf, sizeof namebuf));
            goto out;
        }

        // For each service instance, make sure that it references the host description
        if (dns_names_equal(host_description->name, sip->srv->data.srv.name)) {
            sip->host = host_description;
            host_description->num_instances++;
        }
    }

    // Make sure that at least one service instance references the host description
    if (host_description->num_instances == 0) {
        ERROR("srp_evaluate: host description %s is not referenced by any service instances.",
              dns_name_print(host_description->name, namebuf, sizeof namebuf));
        goto out;
    }

    // Make sure the host description has at least one address record.
    if (host_description->a == NULL && host_description->aaaa == NULL) {
        ERROR("srp_evaluate: host description %s doesn't contain any IP addresses.",
              dns_name_print(host_description->name, namebuf, sizeof namebuf));
        goto out;
    }

    for (i = 0; i < num_keys; i++) {
        // If this isn't the only key, make sure it's got the same contents as the other keys.
        if (i > 0) {
            if (!dns_keys_equal(key, keys[i])) {
                ERROR("srp_evaluate: more than one key presented");
                goto out;
            }
            // This is a hack so that if num_keys == 1, we don't have to allocate keys[].
            // At the bottom of this if statement, key is always the key we are looking at.
            key = keys[i];
        }
        // If there is a key, and the host description doesn't currently have a key, check
        // there first since that's the default.
        if (host_description->key == NULL && dns_names_equal(key->rr, host_description->name)) {
            host_description->key =  rr;
            found_key = true;
        } else {
            for (sip = service_instances; sip != NULL; sip = sip->next) {
                if (dns_names_equal(service_instance->name, key->name)) {
                    found_key = true;
                    break;
                }
            }
        }
        if (!found_key) {
            ERROR("srp_evaluate: key present for name %s which is neither a host nor an instance name.",
                  dns_name_print(key->name, namebuf, sizeof namebuf));
            goto out;
        }
    }
    free(keys);
    keys = NULL;
        
    // And make sure it has a key record
    if (host_description->key == NULL) {
        ERROR("srp_evaluate: host description %s doesn't contain a key.",
              dns_name_print(host_description->name, namebuf, sizeof namebuf));
        goto out;
    }

    // Make sure that all the deletes are for things that are then added.
    for (dp = deletes; dp; dp = dp->next) {
        if (!dp->consumed) {
            ERROR("srp_evaluate: delete for which there is no subsequent add: %s",
                  dns_name_print(host_description->name, namebuf, sizeof namebuf));
            goto out;
        }
    }

    // The signature should be the last thing in the additional section.   Even if the signature
    // is valid, if it's not at the end we reject it.   Note that we are just checking for SIG(0)
    // so if we don't find what we're looking for, we forward it to the DNS auth server which
    // will either accept or reject it.
    if (message->arcount < 1) {
        ERROR("srp_evaluate: signature not present");
        goto out;
    }
    signature = &message->additional[message->arcount -1];
    if (signature->type != dns_rrtype_sig) {
        ERROR("srp_evaluate: signature is not at the end or is not present");
        goto out;
    }

    // Make sure that the signer name is the hostname.   If it's not, it could be a legitimate
    // update with a different key, but it's not an SRP update, so we pass it on.
    if (!dns_names_equal(signature->data.sig.signer, host_description->name)) {
        ERROR("srp_evaluate: signer %s doesn't match host %s", 
              dns_name_print(signature->data.sig.signer, namebuf, sizeof namebuf),
              dns_name_print(host_description->name, namebuf1, sizeof namebuf1));
        goto out;
    }
    
    // Make sure we're in the time limit for the signature.   Zeroes for the inception and expiry times
    // mean the host that send this doesn't have a working clock.   One being zero and the other not isn't
    // valid unless it's 1970.
    if (signature->data.sig.inception != 0 || signature->data.sig.expiry != 0) {
        gettimeofday(&now, NULL);
        // The sender does the bracketing, so we can just do a simple comparison.
        if (now.tv_sec > signature->data.sig.expiry || now.tv_sec < signature->data.sig.inception) {
            ERROR("signature is not timely: %lu < %lu < %lu does not hold",
                  (unsigned long)signature->data.sig.inception, (unsigned long)now.tv_sec,
                  (unsigned long)signature->data.sig.expiry);
            goto badsig;
        }
    }

    // Now that we have the key, we can validate the signature.   If the signature doesn't validate,
    // there is no need to pass the message on.
    if (!srp_sig0_verify(message->wire, host_description->key, signature)) {
        ERROR("signature is not valid");
        goto badsig;
    }

    // Now that we have validated the SRP message, go through and fix up all instances of
    // *default.service.arpa to use the replacement zone, if this update is for
    // default.services.arpa and there is a replacement zone.
    if (replacement_zone != NULL) {
        // All of the service instances and the host use the name from the delete, so if
        // we update these, the names for those are taken care of.   We already found the
        // zone for which the delete is a subdomain, so we can just replace it without
        // finding it again.
        for (dp = deletes; dp; dp = dp->next) {
            replace_zone_name(&dp->name, dp->zone, replacement_zone);
        }

        // All services have PTR records, which point to names.   Both the service name and the
        // PTR name have to be fixed up.
        for (sp = services; sp; sp = sp->next) {
            replace_zone_name(&sp->rr->name, sp->zone, replacement_zone);
            uzp = dns_name_subdomain_of(sp->rr->data.ptr.name, update_zone);
            // We already validated that the PTR record points to something in the zone, so this
            // if condition should always be false.
            if (uzp == NULL) {
                ERROR("srp_evaluate: service PTR record zone match fail!!");
                goto out;
            }
            replace_zone_name(&sp->rr->data.ptr.name, uzp, replacement_zone);
        }

        // All service instances have SRV records, which point to names.  The service instance
        // name is already fixed up, because it's the same as the delete, but the name in the
        // SRV record must also be fixed.
        for (sip = service_instances; sip; sip = sip->next) {
            uzp = dns_name_subdomain_of(sip->srv->data.srv.name, update_zone);
            // We already validated that the SRV record points to something in the zone, so this
            // if condition should always be false.
            if (uzp == NULL) {
                ERROR("srp_evaluate: service instance SRV record zone match fail!!");
                goto out;
            }
            replace_zone_name(&sip->srv->data.srv.name, uzp, replacement_zone);
        }
    }

    // Start the update.
    ret = srp_update_start(comm, message, host_description, service_instances, services,
                           replacement_zone == NULL ? update_zone : replacement_zone);
    if (ret == true) {
        comm->message = NULL; // This is retained for the length of the dns update process.
        ret = true;
        goto success;
    }
    ERROR("update start failed");

badsig:
    // True means it was intended for us, and shouldn't be forwarded.
    ret = true;

out:
    // free everything we allocated but (it turns out) aren't going to use
    srp_update_free_parts(service_instances, NULL, services, host_description);

    // If we indicate that the message was an srp update, which we do by returning true, then we
    // are expected to retain the message.   Since the update didn't validate, we need to free it
    // here.
    if (ret == true) {
        dns_message_free(message);
    }
success:
    // No matter how we get out of this, we free the delete structures, because they are not
    // used to do the update.
    for (dp = deletes; dp; ) {
        delete_t *next = dp->next;
        free(dp);
        dp = next;
    }
    return ret;
}

void
dns_evaluate(comm_t *comm)
{
    dns_message_t *message;

    // Drop incoming responses--we're a server, so we only accept queries.
    if (dns_qr_get(&comm->message->wire) == dns_qr_response) {
        return;
    }

    // Forward incoming messages that are queries but not updates.
    // XXX do this later--for now we operate only as a translator, not a proxy.
    if (dns_opcode_get(&comm->message->wire) != dns_opcode_update) {
        return;
    }
    
    // Parse the UPDATE message.
    if (!dns_wire_parse(&message, &comm->message->wire, comm->message->length)) {
        ERROR("dns_wire_parse failed.");
        return;
    }
    
    // We need the wire message to validate the signature...
    message->wire = &comm->message->wire;
    if (!srp_evaluate(comm, message)) {
        // The message wasn't invalid, but wasn't an SRP message.
        dns_message_free(message);
        // dns_forward(comm)
        // dns_forward can steal the wire message off of comm if needed.
    }
}

void dns_input(comm_t *comm)
{
    dns_evaluate(comm);
    // We're responsible for freeing the message buffer.   dns_evaluate might have
    // already consumed it.
    if (comm->message) {
        message_free(comm->message);
        comm->message = NULL;
    }
}

bool
srp_proxy_listen(void)
{
    uint16_t listen_port;

    listen_port = htons(53);

    // Set up listeners
    // XXX UDP listeners should bind to interface addresses, not INADDR_ANY.
    if (!setup_listener_socket(AF_INET, IPPROTO_UDP, false, listen_port, NULL, NULL, "UDPv4 listener", dns_input, 0, 0)) {
        ERROR("UDPv4 listener: fail.");
        return false;
    }
    if (!setup_listener_socket(AF_INET6, IPPROTO_UDP, false, listen_port, NULL, NULL, "UDPv6 listener", dns_input, 0, 0)) {
        ERROR("UDPv6 listener: fail.");
        return false;
    }
    if (!setup_listener_socket(AF_INET, IPPROTO_TCP, false, listen_port, NULL, NULL, "TCPv4 listener", dns_input, 0, 0)) {
        ERROR("TCPv4 listener: fail.");
        return false;
    }
    if (!setup_listener_socket(AF_INET6, IPPROTO_TCP, false, listen_port, NULL, NULL, "TCPv6 listener", dns_input, 0, 0)) {
        ERROR("TCPv6 listener: fail.");
        return false;
    }
    if (!setup_listener_socket(AF_INET, IPPROTO_TCP, true, listen_port, NULL, NULL, "TLSv4 listener", dns_input, 0, 0)) {
        ERROR("TLSv4 listener: fail.");
        return false;
    }
    if (!setup_listener_socket(AF_INET6, IPPROTO_TCP, true, listen_port, NULL, NULL, "TLSv6 listener", dns_input, 0, 0)) {
        ERROR("TLSv6 listener: fail.");
        return false;
    }
    
    // For now, hardcoded, should be configurable
    service_update_zone = dns_pres_name_parse("home.arpa");

    return true;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
