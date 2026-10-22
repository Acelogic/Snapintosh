/* SPDX-License-Identifier: MIT */
#ifndef SNAPINTOSH_VIRTUAL_ETHERNET_H
#define SNAPINTOSH_VIRTUAL_ETHERNET_H

// 26A428 TimeSync consumes the kernel IOEthernetInterface path. Keep use of
// these intentionally selected legacy KPIs local to this bring-up controller.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOOutputQueue.h>

// A deliberately disconnected virtual interface for the guest's stable network
// identity. Native TimeSync consumes the ordinary IOEthernetInterface/MAC path.
// This controller never reports carrier or successful packet transmission.
//
// It also names its own interface (en0) from a kernel thread, with the request
// configd's InterfaceNamer would send. IOTimeSyncClockManager publishes the clock
// WindowServer waits for only after an interface has a BSD name. In generation71
// configd named this interface 5.9 min after it was published: InterfaceNamer's
// 240 s IOKit-quiesce timer had expired 0.4 min before this AuxKC loaded, and in
// every earlier boot with intact configd logs naming waited for the busy-registry
// walk that follows that timeout.
class SnapintoshVirtualEthernet : public IOEthernetController {
    OSDeclareDefaultStructors(SnapintoshVirtualEthernet)

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    IOReturn getHardwareAddress(IOEthernetAddress *address) override;
    IOReturn enable(IONetworkInterface *interface) override;
    IOReturn disable(IONetworkInterface *interface) override;
    IOReturn selectMedium(const IONetworkMedium *medium) override;
    UInt32 outputPacket(mbuf_t packet, void *parameter) override;
    const OSString *newVendorString() const override;
    const OSString *newModelString() const override;

private:
    static void namingThread(void *parameter, wait_result_t);
    void nameInKernel(IONetworkInterface *interface);

    IONetworkInterface *fInterface = nullptr;
    IONetworkMedium *fMedium = nullptr;
    IONetworkInterface *fNamingInterface = nullptr; // retained for the naming thread only
    uint8_t fStopping = 0;                          // stop() ends the naming thread's retries
    IOEthernetAddress fAddress = {{0x02, 0x53, 0x4e, 0x50, 0x00, 0x01}};
};

#pragma clang diagnostic pop

#endif
