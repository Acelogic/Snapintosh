/* SPDX-License-Identifier: MIT */
// Deferred native resource descriptors: BeginSegment resets IOGPU's list.
#pragma once
#import "AdrenoMetalSPI.h"

NS_ASSUME_NONNULL_BEGIN
@interface AdrenoResourceUsage : NSObject
- (instancetype)initWithDevice:(id)device retainedList:(nullable id)retainedList;
- (void)recordResource:(id)resource usage:(MTLResourceUsage)usage;
// Call only after native BeginSegment and before EndSegment. A failed or
// successful publication seals the records; neither can be retried.
- (void)encodeIntoIOGPUList:(void *)list;
#if ADRENO_PIPELINE
// agents/gpu-pipeline U2: the recorded resources' IOGPU resource IDs (uint32_t each, in record order).
- (NSData *)adrenoResourceIDs;
#endif
@end
NS_ASSUME_NONNULL_END
