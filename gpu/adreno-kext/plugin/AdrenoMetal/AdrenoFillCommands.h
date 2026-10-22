/* SPDX-License-Identifier: MIT */
#import "AdrenoResourceUsage.h"

NS_ASSUME_NONNULL_BEGIN
/* Metadata-only encoder. Destination bytes are never mapped or accessed here.
 * Resources use the command buffer's ordinary retained/unretained lifetime. */
@interface AdrenoFillCommands : NSObject
- (instancetype)initWithResources:(AdrenoResourceUsage *)resources;
- (void)recordBuffer:(id<MTLBuffer>)buffer range:(NSRange)range value:(uint8_t)value;
- (void)recordClearPass:(MTLRenderPassDescriptor *)pass;
- (void)recordClearPass:(MTLRenderPassDescriptor *)pass refusal:(nullable NSString *)refusal;
- (NSUInteger)commandBytes;
- (void)encodeInto:(void *)destination capacity:(NSUInteger)capacity;
@end
NS_ASSUME_NONNULL_END
