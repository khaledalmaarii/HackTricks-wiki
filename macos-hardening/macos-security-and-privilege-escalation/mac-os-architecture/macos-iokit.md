# macOS IOKit

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

**IOKit** jIH is an open-source, object-oriented **device-driver framework** in the XNU kernel, handles **dynamically loaded device drivers**. It allows modular code to be added to the kernel on-the-fly, supporting diverse hardware.

**IOKit drivers** will basically **export functions from the kernel**. These function parameter **types** are **predefined** and are verified. Moreover, similar to XPC, IOKit is just another layer on **top of Mach messages**.

**IOKit XNU kernel code** is opensourced by Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Moreover, the user space IOKit components are also opensource [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

However, **no IOKit drivers** are opensource. Anyway, from time to time a release of a driver might come with symbols that makes it easier to debug it. Check how to [**get the driver extensions from the firmware here**](./#ipsw)**.**

It's written in **C++**. You can get demangled C++ symbols with:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **exposed functions** could perform **additional security checks** when a client tries to call a function but note that the apps are usually **limited** by the **sandbox** to which IOKit functions they can interact with.
{% endhint %}

## Drivers

In macOS they are located in:

* **`/System/Library/Extensions`**
* KEXT files built into the OS X operating system.
* **`/Library/Extensions`**
* KEXT files installed by 3rd party software

In iOS they are located in:

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
**9** pIqaD 0 **ghItlh** **drivers** **list** **vItlhutlh**. **cha'logh** **drivers** **real** **ghItlh** **'ej** **unloaded** **ghItlh** **not** **'e'**.

**extensions** **specific** **find** **to** **order** **In** **use** **can**:

```bash
kextfind -case-insensitive -bundle-id com.example.driver
```

**com.example.driver** **bundle-id** **example** **an** **with** **ID** **bundle** **the** **replace** **to** **need** **You**.
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
To load and unload kernel extensions do:

```
To'wI' 'ej 'oH 'e' vItlhutlh
```

```
<code>To'wI' 'ej 'oH 'e' vItlhutlh</code>
```
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** jatlh IOKit framework Daq macOS je iOS vaj, 'ej Hoch 'ej **hardware configuration vaj state** system representation database vaj. 'Iv 'ej **hierarchical collection of objects** Hoch 'ej hardware vaj drivers vaj, 'ej Hoch 'ej 'oH Hoch.&#x20;

**`ioreg`** cli 'oH inspect 'ej console (iOS laH) vaj.
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`** **Xcode Additional Tools**-lI' **download**. [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) **'e'** **'e'** **macOS IORegistry** **inspect** **'e'** **'e'** **interface**.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer, "planes" **IORegistry** **objects** **relationship** **organize** **'e'** **display** **'e'.** **plane** **specific** **type** **relationship** **'e'** **system's** **hardware** **driver** **configuration** **'e'.** **IORegistryExplorer** **common** **planes** **'e'** **encounter** **'e':

1. **IOService Plane**: **'e'** **general** **plane**, **service objects** **driver** **nubs** (communication channels between drivers) **represent** **'e'.** **provider-client relationships** **objects** **show** **'e'.
2. **IODeviceTree Plane**: **'e'** **plane**, **physical connections** **devices** **attach** **system** **represent** **'e'.** **often** **visualize** **hierarchy** **devices** **connect** **buses** **USB** **PCI** **'e'.
3. **IOPower Plane**: **'e'** **objects** **relationships** **power management** **terms** **display** **'e'.** **show** **objects** **affect** **power state** **others**, **useful** **debugging** **power-related issues** **'e'.
4. **IOUSB Plane**: **'e'** **USB devices** **relationships** **focus** **'e',** **hierarchy** **USB hubs** **connect** **devices** **show** **'e'.
5. **IOAudio Plane**: **'e'** **plane**, **audio devices** **relationships** **system** **'e'.
6. ...

## Driver Comm Code Example

**code** **connect** **IOKit service** `"YourServiceNameHere"` **call** **function** **selector 0** **'e'.**:

* **first** **call** **`IOServiceMatching`** **`IOServiceGetMatchingServices`** **service** **'e'.
* **then** **establish** **connection** **call** **`IOServiceOpen`** **'e'.**
* **finally** **call** **function** **`IOConnectCallScalarMethod`** **indicate** **selector 0** **(selector** **function** **call** **assigned)** **'e'.**
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
**Qapla'!**

**'ej** **`IOConnectCallScalarMethod`** **laH** **IOKit** **ghItlh** **ghItlh** **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** **...** **vaj** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH** **ghItlh** **'oH
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Qapla'! jatlh **`self`** param vItlhutlh. vItlhutlh definition vItlhutlhlaHbe'chugh:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% code %}

Qapla', vaj vItlhutlh [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) 'e' vItlhutlh:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
With this info you can rewrite Ctrl+Right -> `Edit function signature` and set the known types:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

The new decompiled code will look like:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

For the next step we need to have defined the **`IOExternalMethodDispatch2022`** struct. It's opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), you could define it:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Now, following the `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` you can see a lot of data:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Change the Data Type to **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

after the change:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

And as we now in there we have an **array of 7 elements** (check the final decompiled code), click to create an array of 7 elements:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

After the array is created you can see all the exported functions:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
If you remember, to **call** an **exported** function from user space we don't need to call the name of the function, but the **selector number**. Here you can see that the selector **0** is the function **`initializeDecoder`**, the selector **1** is **`startDecoder`**, the selector **2** **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
