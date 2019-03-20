/*
 * Copyright (c) 2016-2017 Apple Inc. All rights reserved.
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
 */

#ifndef __Metrics_h
#define __Metrics_h

#include "mDNSEmbeddedAPI.h"
#include <TargetConditionals.h>

#ifdef  __cplusplus
extern "C" {
#endif

#if AWD_METRICS
mStatus MetricsInit(void);
void    MetricsUpdateDNSQueryStats(const domainname *inQueryName, mDNSu16 inType, const ResourceRecord *inRR, mDNSu32 inSendCount, ExpiredAnswerMetric inExpiredAnswerState, mDNSu32 inLatencyMs, mDNSBool inForCell);
void    MetricsUpdateDNSResolveStats(const domainname *inQueryName, const ResourceRecord *inRR, mDNSBool inForCell);
void    MetricsUpdateDNSQuerySize(mDNSu32 inSize);
void    MetricsUpdateDNSResponseSize(mDNSu32 inSize);
void    LogMetrics(void);
#endif

#ifdef  __cplusplus
}
#endif

#endif // __Metrics_h
