/* srp-proxy.h
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
 * Service Registration Protocol common definitions
 */

#ifndef __SRP_PROXY_H
#define __SRP_PROXY_H

bool srp_proxy_listen(void);
bool srp_evaluate(comm_t *comm, dns_message_t *message);
bool srp_update_start(comm_t *connection, dns_message_t *parsed_message, dns_host_description_t *host,
                      service_instance_t *instance, service_t *service, dns_name_t *update_zone)

#endif // __SRP_PROXY_H

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
