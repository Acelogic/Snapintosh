/* SPDX-License-Identifier: MIT */
#import <Foundation/Foundation.h>

// One unambiguous stage from the native compiler callback, still untranslated.
@interface AdrenoCompilerInput : NSObject
@property (nonatomic, readonly, strong) NSData *airModule;
@property (nonatomic, readonly, strong) NSString *entry;
@property (nonatomic, readonly, strong) NSString *airSHA256;
@property (nonatomic, readonly) NSUInteger stage; // 0 vertex, 1 fragment, 2 kernel
+ (instancetype)inputWithCompilerOutput:(id)output stage:(NSUInteger)stage
                                 entry:(NSString *)entry error:(NSString **)error;
// The built-in fragment stage for render pipelines without a fragment function (AdrenoEmptyFragment.metal).
+ (instancetype)emptyFragmentInput:(NSString **)error;
@end
