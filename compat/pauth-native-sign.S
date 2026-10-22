// SPDX-License-Identifier: MIT
// Same scoped controls/restoration as the canonical round-trip helper. Native
// PAC receives all operand bits; no AUT is executed on the resulting value.
#define PAUTH_NATIVE_NAME pauth_native_sign_user
#define PAUTH_NATIVE_RAW_SIGN 1
#include "pauth-native.S"
