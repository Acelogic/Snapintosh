/* SPDX-License-Identifier: MIT */
#include "SnapintoshVirtualEthernet.h"

#include <IOKit/IOKitKeys.h>
#include <IOKit/IOLib.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IONetworkMedium.h>
#include <kern/thread.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>

#define super IOEthernetController
OSDefineMetaClassAndStructors(SnapintoshVirtualEthernet, IOEthernetController)

// The naming request configd's InterfaceNamer sends to IONetworkStack
// (IONetworkingFamily IONetworkStack.h, not in the SDK). 26A428's
// IONetworkStack::setProperties takes it from kernel_task without the user-client
// entitlement; command 0 names the interface with exactly the given unit.
static const char *const kStackCommandKey = "IONetworkStackUserCommand";
static const uint32_t kStackRegisterWithUnit = 0;
// The guest's NetworkInterfaces.plist already maps this MAC to en0 (generation61:
// "Assigned unit 0 (from database)"). If en0 is taken, the request fails and
// configd names the interface as before.
static const uint32_t kVirtualUnit = 0;
static const unsigned kNamingTries = 30;          // one per second after the interface has matched
static const uint64_t kStackWait = 60ULL * kSecondScale;
static const uint64_t kMatchWait = 30ULL * kSecondScale;

bool SnapintoshVirtualEthernet::start(IOService *provider)
{
    if (!provider || !provider->metaCast("AdrenoAcceleratorX2"))
        return false;

    // The default is reserved for this single A16 guest. An additional guest
    // must supply its own locally administered unicast address in its plist.
    if (OSObject *property = getProperty("SnapintoshVirtualMAC")) {
        OSData *address = OSDynamicCast(OSData, property);
        if (!address || address->getLength() != sizeof(fAddress.bytes))
            return false;
        memcpy(fAddress.bytes, address->getBytesNoCopy(), sizeof(fAddress.bytes));
    }
    if ((fAddress.bytes[0] & 3u) != 2u)
        return false;
    if (!super::start(provider))
        return false;

    setProperty("SnapintoshVirtualInterface", true);
    setProperty("NetworkConnectivityImplemented", false);
    setProperty("IOBuiltin", false);
    OSDictionary *media = OSDictionary::withCapacity(1);
    fMedium = IONetworkMedium::medium(kIOMediumEthernetNone, 0);
    const bool ready = media && fMedium &&
        IONetworkMedium::addMedium(media, fMedium) &&
        publishMediumDictionary(media) && setCurrentMedium(fMedium) &&
        setLinkStatus(kIONetworkLinkValid, fMedium, 0);
    OSSafeReleaseNULL(media);
    if (!ready || !attachInterface(&fInterface, false)) {
        OSSafeReleaseNULL(fMedium);
        super::stop(provider);
        return false;
    }
    fInterface->setProperty("SnapintoshVirtualInterface", true);
    fInterface->setProperty("NetworkConnectivityImplemented", false);
    fInterface->setProperty("IOBuiltin", false);
    // Address, media and inactive link state are established before matching.
    fInterface->registerService();
    registerService();
    IOLog("SnapintoshVirtualEthernet: virtual interface published, carrier absent\n");

    // The thread owns one reference to this controller and one to the interface.
    thread_t thread = nullptr;
    retain();
    fInterface->retain();
    fNamingInterface = fInterface;
    if (kernel_thread_start(&SnapintoshVirtualEthernet::namingThread, this, &thread) == KERN_SUCCESS) {
        thread_deallocate(thread);
    } else {
        OSSafeReleaseNULL(fNamingInterface);
        release();
        IOLog("SnapintoshVirtualEthernet: no naming thread; configd names the interface\n");
    }
    return true;
}

void SnapintoshVirtualEthernet::namingThread(void *parameter, wait_result_t)
{
    SnapintoshVirtualEthernet *self = static_cast<SnapintoshVirtualEthernet *>(parameter);
    self->nameInKernel(self->fNamingInterface);
    OSSafeReleaseNULL(self->fNamingInterface);
    self->release();
    // Returning from a kernel_thread_start continuation terminates the thread.
}

void SnapintoshVirtualEthernet::nameInKernel(IONetworkInterface *interface)
{
    OSDictionary *matching = IOService::serviceMatching("IONetworkStack");
    IOService *stack = matching ? IOService::waitForMatchingService(matching, kStackWait) : nullptr;
    OSSafeReleaseNULL(matching);
    const uint64_t entryID = interface->getRegistryEntryID();
    OSDictionary *request = OSDictionary::withCapacity(3);
    OSNumber *command = OSNumber::withNumber(kStackRegisterWithUnit, 32);
    OSNumber *unit = OSNumber::withNumber(kVirtualUnit, 32);
    OSData *entry = OSData::withBytes(&entryID, sizeof(entryID));
    IOReturn status = kIOReturnNoMemory;
    unsigned tries = 0;
    if (stack && request && command && unit && entry && request->setObject(kStackCommandKey, command) &&
        request->setObject(kIOInterfaceUnit, unit) && request->setObject(kIORegistryEntryIDKey, entry)) {
        // IONetworkStack accepts the interface once its publish notification has run, which is part
        // of the interface's own matching. Configd may still name it first; then there is nothing to do.
        interface->waitQuiet(kMatchWait);
        for (status = kIOReturnNotReady; tries < kNamingTries; tries++) {
            if (__atomic_load_n(&fStopping, __ATOMIC_ACQUIRE) || interface->isInactive() ||
                interface->getProperty(kIOInterfaceUnit))
                break;
            status = stack->setProperties(request);
            if (status == kIOReturnSuccess)
                break;
            IOSleep(1000);
        }
    } else if (!stack) {
        status = kIOReturnNotFound;
    }
    if (status == kIOReturnSuccess)
        IOLog("SnapintoshVirtualEthernet: %s%u attached from the kernel (try %u)\n", interface->getNamePrefix(),
              kVirtualUnit, tries + 1);
    else if (interface->getProperty(kIOInterfaceUnit))
        IOLog("SnapintoshVirtualEthernet: interface was already named (after %u kernel tries)\n", tries);
    else
        IOLog("SnapintoshVirtualEthernet: kernel naming stopped (0x%x after %u tries); configd names the "
              "interface\n", status, tries);
    OSSafeReleaseNULL(entry);
    OSSafeReleaseNULL(unit);
    OSSafeReleaseNULL(command);
    OSSafeReleaseNULL(request);
    OSSafeReleaseNULL(stack);
}

void SnapintoshVirtualEthernet::stop(IOService *provider)
{
    __atomic_store_n(&fStopping, 1, __ATOMIC_RELEASE);
    setLinkStatus(kIONetworkLinkValid, fMedium, 0);
    if (fInterface) {
        detachInterface(fInterface);
        OSSafeReleaseNULL(fInterface);
    }
    super::stop(provider);
}

void SnapintoshVirtualEthernet::free()
{
    OSSafeReleaseNULL(fMedium);
    super::free();
}

IOReturn SnapintoshVirtualEthernet::getHardwareAddress(IOEthernetAddress *address)
{
    if (!address)
        return kIOReturnBadArgument;
    *address = fAddress;
    return kIOReturnSuccess;
}

IOReturn SnapintoshVirtualEthernet::enable(IONetworkInterface *interface)
{
    if (interface != fInterface)
        return kIOReturnBadArgument;
    setLinkStatus(kIONetworkLinkValid, fMedium, 0);
    return kIOReturnSuccess;
}

IOReturn SnapintoshVirtualEthernet::disable(IONetworkInterface *interface)
{
    return enable(interface); // Administrative state cannot create carrier.
}

IOReturn SnapintoshVirtualEthernet::selectMedium(const IONetworkMedium *medium)
{
    if (!medium || medium->getType() != kIOMediumEthernetNone)
        return kIOReturnUnsupported;
    return setCurrentMedium(medium) ? kIOReturnSuccess : kIOReturnError;
}

UInt32 SnapintoshVirtualEthernet::outputPacket(mbuf_t packet, void *)
{
    if (packet)
        freePacket(packet);
    return kIOReturnOutputDropped;
}

const OSString *SnapintoshVirtualEthernet::newVendorString() const
{
    return OSString::withCString("Snapintosh");
}

const OSString *SnapintoshVirtualEthernet::newModelString() const
{
    return OSString::withCString("Virtual Ethernet (no carrier)");
}
