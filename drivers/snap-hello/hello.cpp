/* SPDX-License-Identifier: MIT */
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
class SnapHello : public IOService {
    OSDeclareDefaultStructors(SnapHello)
public:
    bool start(IOService *provider) override {
        if (!IOService::start(provider)) return false;
        IOLog("SnapHello: AuxKC kext started\n");
        registerService();
        return true;
    }
};
OSDefineMetaClassAndStructors(SnapHello, IOService)
