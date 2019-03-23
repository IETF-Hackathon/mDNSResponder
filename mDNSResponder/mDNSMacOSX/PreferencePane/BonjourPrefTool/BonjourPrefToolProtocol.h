/*
 *
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

// The protocol that this service will vend as its API. This header file will
// also need to be visible to the process hosting the service.
@protocol BonjourPrefToolProtocol

- (void) setKeychainEntry:(NSDictionary *_Nonnull)secretDictionary withStatus:(void (^ _Nonnull)(OSStatus))status;

@end

