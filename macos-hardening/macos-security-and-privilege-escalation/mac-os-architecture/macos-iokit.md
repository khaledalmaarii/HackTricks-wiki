# macOS IOKit

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

Die I/O Kit is 'n oopbron, objek-georiënteerde **toestuurder-raamwerk** in die XNU-kern, wat **dynamies gelaaide toestel bestuurders** hanteer. Dit laat modulaire kode toe om aan die kern bygevoeg te word terwyl dit loop, wat verskillende hardeware ondersteun.

IOKit bestuurders sal basies **funksies van die kern** **uitvoer**. Hierdie funksieparameter **tipes** is **vooraf gedefinieer** en word geverifieer. Boonop, soortgelyk aan XPC, is IOKit net nog 'n laag op **top van Mach boodskappe**.

**IOKit XNU kernkode** is oopgesluit deur Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Boonop is die gebruikersruimte IOKit-komponente ook oopbron [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Echter, **geen IOKit bestuurders** is oopbron. In elk geval, van tyd tot tyd kan 'n vrystelling van 'n bestuurder kom met simbole wat dit makliker maak om dit te debug. Kyk hoe om [**die bestuurder uitbreidings van die firmware hier te kry**](./#ipsw)**.**

Dit is geskryf in **C++**. Jy kan demangled C++ simbole kry met:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **blootgestelde funksies** kan **addisionele sekuriteitskontroles** uitvoer wanneer 'n kliënt probeer om 'n funksie aan te roep, maar let daarop dat die programme gewoonlik **beperk** is deur die **sandbox** waartoe IOKit-funksies hulle kan interaksie hê.
{% endhint %}

## Bestuurders

In macOS is hulle geleë in:

* **`/System/Library/Extensions`**
* KEXT-lêers ingebou in die OS X-bedryfstelsel.
* **`/Library/Extensions`**
* KEXT-lêers geïnstalleer deur 3de party sagteware

In iOS is hulle geleë in:

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
Tot nommer 9 is die gelysde bestuurders **gelaai in die adres 0**. Dit beteken dat dit nie werklike bestuurders is nie, maar **deel van die kern en hulle kan nie ontlaai word nie**.

Om spesifieke uitbreidings te vind, kan jy gebruik maak van:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Om kernuitbreidings te laai en te ontlaai, doen:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** is 'n belangrike deel van die IOKit-raamwerk in macOS en iOS wat dien as 'n databasis vir die voorstelling van die stelsel se hardewarekonfigurasie en -toestand. Dit is 'n **hiërargiese versameling van objekke wat al die hardeware en bestuurders** wat op die stelsel gelaai is, verteenwoordig, en hul verhoudings tot mekaar.

Jy kan die IORegistry verkry met die cli **`ioreg`** om dit vanaf die konsole te inspekteer (spesiaal nuttig vir iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **grafiese** interface.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "planes" are used to organize and display the relationships between different objects in the IORegistry. Each plane represents a specific type of relationship or a particular view of the system's hardware and driver configuration. Here are some of the common planes you might encounter in IORegistryExplorer:

1. **IOService Plane**: This is the most general plane, displaying the service objects that represent drivers and nubs (communication channels between drivers). It shows the provider-client relationships between these objects.
2. **IODeviceTree Plane**: This plane represents the physical connections between devices as they are attached to the system. It is often used to visualize the hierarchy of devices connected via buses like USB or PCI.
3. **IOPower Plane**: Displays objects and their relationships in terms of power management. It can show which objects are affecting the power state of others, useful for debugging power-related issues.
4. **IOUSB Plane**: Specifically focused on USB devices and their relationships, showing the hierarchy of USB hubs and connected devices.
5. **IOAudio Plane**: This plane is for representing audio devices and their relationships within the system.
6. ...

## Driver Comm Code Example

The following code connects to the IOKit service `"YourServiceNameHere"` and calls the function inside the selector 0. For it:

* it first calls **`IOServiceMatching`** and **`IOServiceGetMatchingServices`** to get the service.
* It then establish a connection calling **`IOServiceOpen`**.
* And it finally calls a function with **`IOConnectCallScalarMethod`** indicating the selector 0 (the selector is the number the function you want to call has assigned).
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
There are **ander** functions that can be used to call IOKit functions apart of **`IOConnectCallScalarMethod`** like **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

You could obtain these for example from a [**firmware image (ipsw)**](./#ipsw). Then, load it into your favourite decompiler.

You could start decompiling the **`externalMethod`** function as this is the driver function that will be receiving the call and calling the correct function:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

That awful call demagled means:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Let op hoe die **`self`** parameter in die vorige definisie ontbreek, die goeie definisie sou wees:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Werklik, jy kan die werklike definisie vind in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Met hierdie inligting kan jy Ctrl+Right -> `Edit function signature` herskryf en die bekende tipes stel:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Die nuwe dekompilde kode sal soos volg lyk:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Vir die volgende stap moet ons die **`IOExternalMethodDispatch2022`** struktuur gedefinieer hê. Dit is oopbron in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), jy kan dit definieer:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Nou, volg die `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` kan jy 'n baie data sien:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Verander die Data Type na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

na die verandering:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

En soos ons nou daar is, het ons 'n **array van 7 elemente** (kyk die finale dekompilde kode), klik om 'n array van 7 elemente te skep:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nadat die array geskep is, kan jy al die geexporteerde funksies sien:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
As jy onthou, om 'n **geexporteerde** funksie vanuit gebruikersruimte te **roep**, hoef ons nie die naam van die funksie te noem nie, maar die **selector nommer**. Hier kan jy sien dat die selector **0** die funksie **`initializeDecoder`** is, die selector **1** is **`startDecoder`**, die selector **2** **`initializeEncoder`**...
{% endhint %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
