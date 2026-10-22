/* SPDX-License-Identifier: MIT */
#pragma once
#import "AdrenoMetalSPI.h"
// <MTLDeviceSPI> MUST be declared on the concrete class: _MTLDevice/IOGPUMetalDevice do not carry it at runtime,
// and both -[IOGPUMetalDevice initWithAcceleratorPort:options:] (IOGPUMetalDevice.m:333) and MTLAddDevice assert
// [self conformsToProtocol:@protocol(MTLDeviceSPI)]. The protocol is matched by name, so a local re-declaration works.
@interface AdrenoMTLDevice : IOGPUMetalDevice <MTLDeviceSPI>
- (id)compiler;
@end
