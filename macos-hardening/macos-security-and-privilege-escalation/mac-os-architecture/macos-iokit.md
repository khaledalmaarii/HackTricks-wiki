# macOS IOKit

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionyeshwa kwenye HackTricks**? Au ungependa kupata ufikiaji wa **toleo la hivi karibuni la PEASS au kupakua HackTricks kwa muundo wa PDF**? Tazama [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu maalum wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi wa PEASS na HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord** au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Shiriki mbinu zako za kudukua kwa kutuma PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Taarifa Msingi

IOKit ni mfumo wa **madereva ya kifaa** ulio wazi, wenye mwelekeo wa vitu katika kernel ya XNU, unashughulikia **madereva ya kifaa yaliyopakia kwa kudumu**. Inaruhusu nambari za moduli kuongezwa kwenye kernel wakati wa mchakato, ikisaidia vifaa mbalimbali.

Madereva ya IOKit kimsingi yatakuwa yanatoa **kazi kutoka kwenye kernel**. Aina za **parameta za kazi hizi** zimeainishwa mapema na kuthibitishwa. Zaidi ya hayo, kama ilivyo XPC, IOKit ni safu nyingine tu juu ya **ujumbe wa Mach**.

Msimbo wa **IOKit XNU kernel** umefunguliwa na Apple katika [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Zaidi ya hayo, sehemu za IOKit za nafasi ya mtumiaji pia zimefunguliwa [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Hata hivyo, **madereva ya IOKit** hayafunguliwi. Hata hivyo, mara kwa mara toleo la dereva linaweza kuja na alama ambazo hufanya iwe rahisi kuidhibiti. Angalia jinsi ya [**kupata nyongeza za dereva kutoka kwenye firmware hapa**](./#ipsw)**.**

Imeandikwa kwa kutumia **C++**. Unaweza kupata alama za C++ zilizopanguliwa na:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **kazi zilizofichuliwa** zinaweza kufanya **ukaguzi wa ziada wa usalama** wakati mteja anajaribu kuita kazi lakini kumbuka kuwa programu kawaida **imezuiliwa** na **sandbox** ambayo IOKit inaweza kuingiliana nayo.
{% endhint %}

## Madereva

Katika macOS, madereva yako yamehifadhiwa katika:

* **`/System/Library/Extensions`**
* Faili za KEXT zilizojengwa katika mfumo wa uendeshaji wa OS X.
* **`/Library/Extensions`**
* Faili za KEXT zilizosanikishwa na programu ya tatu.

Katika iOS, madereva yako yamehifadhiwa katika:

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
Mpaka nambari 9 madereva yaliyoorodheshwa yanapakia katika anwani 0. Hii inamaanisha kwamba hayo sio madereva halisi bali ni sehemu ya kernel na hawawezi kuondolewa.

Ili kupata nyongeza maalum unaweza kutumia:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Kuwezesha na kuzima nyongeza za kernel fanya:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** ni sehemu muhimu ya mfumo wa IOKit katika macOS na iOS ambayo inatumika kama database ya kuonyesha usanidi na hali ya vifaa vya mfumo. Ni **mkusanyiko wa hiyerariki wa vitu vinavyowakilisha vifaa vyote na madereva** vilivyopakia kwenye mfumo, na uhusiano wao kati yao.&#x20;

Unaweza kupata IORegistry kwa kutumia amri ya **`ioreg`** kuichunguza kutoka kwenye konsoli (hasa inafaa kwa iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Unaweza kupakua **`IORegistryExplorer`** kutoka **Xcode Additional Tools** kutoka [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) na ukague **macOS IORegistry** kupitia kiolesura **cha picha**.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

Katika IORegistryExplorer, "planes" hutumiwa kuandaa na kuonyesha uhusiano kati ya vitu tofauti katika IORegistry ya macOS. Kila ndege inawakilisha aina maalum ya uhusiano au mtazamo maalum wa vifaa na usanidi wa dereva wa mfumo. Hapa kuna baadhi ya ndege za kawaida unazoweza kukutana nazo katika IORegistryExplorer:

1. **IOService Plane**: Hii ni ndege ya kawaida zaidi, inaonyesha vitu vya huduma vinavyowakilisha dereva na nubs (njia za mawasiliano kati ya madereva). Inaonyesha uhusiano wa mtoa huduma-mteja kati ya vitu hivi.
2. **IODeviceTree Plane**: Ndege hii inawakilisha uhusiano wa kimwili kati ya vifaa wanapounganishwa kwenye mfumo. Mara nyingi hutumiwa kuonyesha muundo wa vifaa vilivyounganishwa kupitia mabasi kama USB au PCI.
3. **IOPower Plane**: Inaonyesha vitu na uhusiano wao kwa kuzingatia usimamizi wa nguvu. Inaweza kuonyesha vitu vipi vinavyoathiri hali ya nguvu ya vingine, ni muhimu kwa ajili ya kutatua matatizo yanayohusiana na nguvu.
4. **IOUSB Plane**: Inazingatia hasa vifaa vya USB na uhusiano wao, ikionyesha muundo wa vichupo vya USB na vifaa vilivyounganishwa.
5. **IOAudio Plane**: Ndege hii inawakilisha vifaa vya sauti na uhusiano wao ndani ya mfumo.
6. ...

## Mfano wa Kanuni ya Mawasiliano ya Dereva

Msimbo ufuatao unahusisha huduma ya IOKit `"JinaLakoLaHudumaHapa"` na kuita kazi ndani ya kuchagua 0. Kwa hilo:

* kwanza inaita **`IOServiceMatching`** na **`IOServiceGetMatchingServices`** kupata huduma.
* Kisha inaanzisha uhusiano kwa kuita **`IOServiceOpen`**.
* Na hatimaye inaita kazi na **`IOConnectCallScalarMethod`** ikionyesha kuchagua 0 (kuchagua ni nambari ambayo kazi unayotaka kuita imepewa).
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
Kuna **kazi nyingine** ambazo zinaweza kutumika kuita kazi za IOKit mbali na **`IOConnectCallScalarMethod`** kama vile **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Kurejesha kuingia kwa dereva

Unaweza kupata hizi kwa mfano kutoka kwa [**picha ya firmware (ipsw)**](./#ipsw). Kisha, ingiza kwenye decompiler yako pendwa.

Unaweza kuanza kudecompile kazi ya **`externalMethod`** kwani hii ndio kazi ya dereva ambayo itapokea wito na kuita kazi sahihi:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Wito mbaya huo una maana:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Tazama jinsi katika ufafanuzi uliopita paramu ya **`self`** imekosekana, ufafanuzi mzuri ungekuwa:

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
Kwa habari hii unaweza kuandika upya Ctrl+Right -> `Hariri saini ya kazi` na weka aina zilizojulikana:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Msimbo uliopanguliwa mpya utaonekana kama hivi:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Kwa hatua inayofuata tunahitaji kuwa na **`IOExternalMethodDispatch2022`** muundo uliowekwa. Ni wazi katika [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), unaweza kuweka:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Sasa, ukiendelea na `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` unaweza kuona data nyingi:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Badilisha Aina ya Data kuwa **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

baada ya mabadiliko:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

Na sasa tunayo **safu ya vipengele 7** (angalia msimbo uliopanguliwa mwisho), bonyeza kuunda safu ya vipengele 7:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Baada ya safu kuundwa unaweza kuona kazi zote zilizosafirishwa:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Ukikumbuka, kwa **kuita** kazi **iliyosafirishwa** kutoka nafasi ya mtumiaji hatuhitaji kuita jina la kazi, bali **namba ya kuchagua**. Hapa unaweza kuona kuwa kuchagua **0** ni kazi ya **`initializeDecoder`**, kuchagua **1** ni **`startDecoder`**, kuchagua **2** ni **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? Au ungependa kupata ufikiaji wa **toleo la hivi karibuni la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJISAJILI**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu maalum wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi wa PEASS na HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord** au [**kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Shiriki mbinu zako za kudukua kwa kutuma PR kwa** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **na** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
