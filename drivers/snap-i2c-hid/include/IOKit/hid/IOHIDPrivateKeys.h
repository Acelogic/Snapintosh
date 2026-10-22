/* SPDX-License-Identifier: MIT */
/*
 * The macOS 27 SDK's Kernel.framework IOKit/hid/IOHIDDevice.h includes
 * <IOKit/hid/IOHIDPrivateKeys.h>, which the SDK does not ship. Nothing that
 * SnapI2CHID.cpp uses is declared there (an empty header compiles the whole
 * driver), so this stands in for it on the build's include path only.
 */
#pragma once
