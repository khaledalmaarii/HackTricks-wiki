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

I/O Kit ni mfumo wa **madereva wa vifaa** wa chanzo wazi, unaoelekezwa kwenye vitu katika kernel ya XNU, unashughulikia **madereva wa vifaa wanaopakiwa kwa nguvu**. Inaruhusu msimbo wa moduli kuongezwa kwenye kernel mara moja, ikisaidia vifaa mbalimbali.

Madereva ya IOKit kwa msingi **yanatoa kazi kutoka kwenye kernel**. Aina za **vigezo** vya kazi hizi ni **zilizowekwa awali** na zinathibitishwa. Zaidi ya hayo, kama ilivyo kwa XPC, IOKit ni safu nyingine juu ya **ujumbe wa Mach**.

**Msimbo wa IOKit XNU kernel** umefunguliwa na Apple katika [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Zaidi ya hayo, vipengele vya IOKit katika nafasi ya mtumiaji pia ni chanzo wazi [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Hata hivyo, **hakuna madereva ya IOKit** yanayofunguliwa. Hata hivyo, mara kwa mara kutolewa kwa dereva kunaweza kuja na alama zinazofanya iwe rahisi kuirekebisha. Angalia jinsi ya [**kupata nyongeza za dereva kutoka kwenye firmware hapa**](./#ipsw)**.**

Imeandikwa kwa **C++**. Unaweza kupata alama za C++ zisizokuwa na mchanganyiko kwa:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **imefunzwa kazi** inaweza kufanya **ukaguzi wa ziada wa usalama** wakati mteja anajaribu kuita kazi lakini kumbuka kwamba programu kawaida **zina mipaka** na **sandbox** ambayo IOKit kazi wanaweza kuingiliana nayo.
{% endhint %}

## Madereva

Katika macOS zinapatikana katika:

* **`/System/Library/Extensions`**
* Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
* **`/Library/Extensions`**
* Faili za KEXT zilizowekwa na programu za upande wa tatu

Katika iOS zinapatikana katika:

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
Hadi nambari 9, madereva yaliyoorodheshwa yana **pakizwa katika anwani 0**. Hii ina maana kwamba si madereva halisi bali **sehemu ya kernel na hayawezi kuondolewa**.

Ili kupata nyongeza maalum unaweza kutumia:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Ili kupakia na kupakua nyongeza za kernel fanya:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** ni sehemu muhimu ya mfumo wa IOKit katika macOS na iOS ambayo inatumika kama hifadhidata ya kuwakilisha usanidi wa vifaa vya mfumo na hali. Ni **mkusanyiko wa kihierarkia wa vitu vinavyowakilisha vifaa vyote na madereva** yaliyojumuishwa kwenye mfumo, na uhusiano wao kwa kila mmoja.

Unaweza kupata IORegistry kwa kutumia cli **`ioreg`** kuikagua kutoka kwenye console (hasa inafaida kwa iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
You could download **`IORegistryExplorer`** from **Xcode Additional Tools** from [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) and inspect the **macOS IORegistry** through a **graphical** interface.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "planes" are used to organize and display the relationships between different objects in the IORegistry. Each plane represents a specific type of relationship or a particular view of the system's hardware and driver configuration. Here are some of the common planes you might encounter in IORegistryExplorer:

1. **IOService Plane**: Hii ni ndege ya jumla zaidi, inayoonyesha vitu vya huduma vinavyowakilisha madereva na nubs (michannel ya mawasiliano kati ya madereva). Inaonyesha uhusiano wa mtoa huduma-mteja kati ya vitu hivi.
2. **IODeviceTree Plane**: Ndege hii inawakilisha muunganisho wa kimwili kati ya vifaa kadri vinavyounganishwa kwenye mfumo. Mara nyingi hutumika kuonyesha hierarchi ya vifaa vilivyounganishwa kupitia mabasi kama USB au PCI.
3. **IOPower Plane**: Inaonyesha vitu na uhusiano wao kwa upande wa usimamizi wa nguvu. Inaweza kuonyesha ni vitu gani vinavyoathiri hali ya nguvu ya vingine, muhimu kwa kutatua matatizo yanayohusiana na nguvu.
4. **IOUSB Plane**: Imejikita hasa kwenye vifaa vya USB na uhusiano wao, ikionyesha hierarchi ya vituo vya USB na vifaa vilivyounganishwa.
5. **IOAudio Plane**: Ndege hii inawakilisha vifaa vya sauti na uhusiano wao ndani ya mfumo.
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
There are **other** functions that can be used to call IOKit functions apart of **`IOConnectCallScalarMethod`** like **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

You could obtain these for example from a [**firmware image (ipsw)**](./#ipsw). Then, load it into your favourite decompiler.

You could start decompiling the **`externalMethod`** function as this is the driver function that will be receiving the call and calling the correct function:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

That awful call demagled means:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Kumbuka jinsi katika ufafanuzi wa awali param **`self`** ilikosekana, ufafanuzi mzuri ungekuwa:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Kwa kweli, unaweza kupata ufafanuzi halisi katika [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Kwa habari hii unaweza kuandika upya Ctrl+Right -> `Edit function signature` na kuweka aina zinazojulikana:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Msimbo mpya uliofanywa upya utaonekana kama:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Kwa hatua inayofuata tunahitaji kuwa na muundo wa **`IOExternalMethodDispatch2022`** umefafanuliwa. Ni wa chanzo wazi katika [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), unaweza kuufafanua:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Sasa, kufuatia `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` unaweza kuona data nyingi:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Badilisha Aina ya Data kuwa **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

baada ya mabadiliko:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Na kama tunavyojua huko tuna **array ya vipengele 7** (angalia msimbo wa mwisho uliofanywa upya), bonyeza kuunda array ya vipengele 7:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Baada ya array kuundwa unaweza kuona kazi zote zilizotolewa:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Kama unavyokumbuka, ili **kuita** kazi **iliyotolewa** kutoka kwa nafasi ya mtumiaji hatuhitaji kuita jina la kazi, bali **nambari ya mteule**. Hapa unaweza kuona kwamba mteule **0** ni kazi **`initializeDecoder`**, mteule **1** ni **`startDecoder`**, mteule **2** **`initializeEncoder`**...
{% endhint %}

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
