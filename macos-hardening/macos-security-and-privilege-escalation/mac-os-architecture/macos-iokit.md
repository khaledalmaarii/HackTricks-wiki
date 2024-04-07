# macOS IOKit

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? Au ungependa kupata upatikanaji wa **toleo la hivi karibuni la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu maalum wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS na HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord** au [**kikundi cha telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Shiriki mbinu zako za udukuzi kwa kutuma PR kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Taarifa Msingi

IO Kit ni **mfumo wa madereva ya kifaa** wa chanzo wazi katika kernel ya XNU, unashughulikia **madereva ya kifaa yaliyopakiwa kwa kudhibiti**. Inaruhusu msimbo wa modular kuongezwa kwenye kernel mara moja, ikisaidia vifaa mbalimbali.

Madereva ya IOKit kimsingi **hutoa kazi kutoka kwa kernel**. Aina za **parameta** za kazi hizi ni **zilizopangwa mapema** na kudhibitishwa. Zaidi ya hayo, kama XPC, IOKit ni safu nyingine tu juu ya **ujumbe wa Mach**.

**Msimbo wa kernel wa IOKit XNU** umefunguliwa na Apple katika [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Zaidi ya hayo, vipengele vya IOKit vya nafasi ya mtumiaji pia ni vya chanzo wazi [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Hata hivyo, **madereva ya IOKit** hayana chanzo wazi. Hata hivyo, mara kwa mara kutolewa kwa dereva kunaweza kuja na alama ambazo hufanya iwe rahisi kuidhibiti. Angalia jinsi ya [**kupata nyongeza za dereva kutoka kwa firmware hapa**](./#ipsw)**.**

Imeandikwa katika **C++**. Unaweza kupata alama za C++ zilizopanguliwa na:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Kazi zilizofunuliwa za IOKit zingeweza kufanya ukaguzi wa usalama wa ziada wakati mteja anajaribu kuita kazi lakini kumbuka kuwa programu kawaida zinazuiliwa na sanduku la IOKit wanaweza kuingiliana nayo.
{% endhint %}

## Madereva

Katika macOS zinapatikana katika:

- **`/System/Library/Extensions`**
- Faili za KEXT zilizojengwa katika mfumo wa uendeshaji wa OS X.
- **`/Library/Extensions`**
- Faili za KEXT zilizowekwa na programu ya tatu

Katika iOS zinapatikana katika:

- **`/System/Library/Extensions`**
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
Mpaka nambari 9 madereva yaliyoorodheshwa yanapakia **katika anwani 0**. Hii inamaanisha kuwa hayo si madereva halisi bali ni **sehemu ya kernel na haziwezi kuondolewa**.

Ili kupata nyongeza maalum unaweza kutumia:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Kuweka na kutoa upanuzi wa kernel fanya:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## Usajili wa IO

**Usajili wa IO** ni sehemu muhimu ya mfumo wa IOKit katika macOS na iOS ambayo hutumika kama database kwa kuiwakilisha usanidi na hali ya vifaa vya mfumo. Ni **mkusanyiko wa hiari wa vitu vinavyowakilisha vifaa vyote na madereva** vilivyopakiwa kwenye mfumo, na mahusiano yao kati yao.

Unaweza kupata Usajili wa IO kwa kutumia cli **`ioreg`** kuiangalia kutoka kwenye koni (hasa inayofaa kwa iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Unaweza kupakua **`IORegistryExplorer`** kutoka **Zana za Ziada za Xcode** kutoka [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) na ukague **macOS IORegistry** kupitia kiolesura **cha picha**.

<figure><img src="../../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Katika IORegistryExplorer, "planes" hutumika kuandaa na kuonyesha uhusiano kati ya vitu tofauti katika IORegistry. Kila ndege inawakilisha aina maalum ya uhusiano au mtazamo fulani wa vifaa vya mfumo na usanidi wa dereva. Hapa kuna baadhi ya ndege za kawaida unazoweza kukutana nazo katika IORegistryExplorer:

1. **IOService Plane**: Hii ni ndege ya kawaida zaidi, inayoonyesha vitu vya huduma vinavyowakilisha dereva na nubs (vituo vya mawasiliano kati ya madereva). Inaonyesha uhusiano wa mtoa huduma-mteja kati ya vitu hivi.
2. **IODeviceTree Plane**: Ndege hii inawakilisha uhusiano wa kimwili kati ya vifaa wanavyounganishwa kwenye mfumo. Mara nyingi hutumiwa kuona muundo wa vifaa vilivyounganishwa kupitia mabasi kama vile USB au PCI.
3. **IOPower Plane**: Inaonyesha vitu na uhusiano wao kwa upande wa usimamizi wa nguvu. Inaweza kuonyesha ni vitu vipi vinavyoathiri hali ya nguvu ya vingine, inayoweza kutumika kwa kutatua matatizo yanayohusiana na nguvu.
4. **IOUSB Plane**: Kuzingatia hasa vifaa vya USB na uhusiano wao, ikiwaonyesha muundo wa vituo vya USB na vifaa vilivyounganishwa.
5. **IOAudio Plane**: Ndege hii ni kwa ajili ya kuwakilisha vifaa vya sauti na uhusiano wao ndani ya mfumo.
6. ...

## Mfano wa Kanuni ya Mawasiliano ya Dereva

Msimbo ufuatao unahusiana na huduma ya IOKit `"JinaLakoLaHudumaHapa"` na kuita kazi ndani ya chaguzi 0. Kwa hilo:

* kwanza inaita **`IOServiceMatching`** na **`IOServiceGetMatchingServices`** kupata huduma.
* Kisha inaanzisha uhusiano kwa kuita **`IOServiceOpen`**.
* Na hatimaye inaita kazi na **`IOConnectCallScalarMethod`** ikionyesha chaguo 0 (chaguo ni nambari ambayo kazi unayotaka kuita imepewa).
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
Kuna **kazi nyingine** ambazo zinaweza kutumika kuita kazi za IOKit isipokuwa **`IOConnectCallScalarMethod`** kama vile **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Kugeuza mshale wa dereva

Unaweza kupata hizi kwa mfano kutoka kwa [**picha ya firmware (ipsw)**](./#ipsw). Kisha, iweke katika decompiler yako pendwa.

Unaweza kuanza kugeuza mshale wa kazi ya **`externalMethod`** kwani hii ni kazi ya dereva ambayo itapokea simu na kuita kazi sahihi:

<figure><img src="../../../.gitbook/assets/image (1165).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1166).png" alt=""><figcaption></figcaption></figure>

Simu hiyo mbaya iliyopangiliwa inamaanisha:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Tazama jinsi paramu ya **`self`** ilivyokosekana katika ufafanuzi uliopita, ufafanuzi mzuri ungekuwa:

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
Na habari hii unaweza kuandika upya Ctrl+Right -> `Hariri saini ya kazi` na kuweka aina zilizojulikana:

<figure><img src="../../../.gitbook/assets/image (1171).png" alt=""><figcaption></figcaption></figure>

Msimbo mpya uliokwisha kudecompile utaonekana kama:

<figure><img src="../../../.gitbook/assets/image (1172).png" alt=""><figcaption></figcaption></figure>

Kwa hatua inayofuata tunahitaji kuwa tumefafanua **`IOExternalMethodDispatch2022`** muundo. Ni wazi chanzo katika [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), unaweza kufafanua hivyo:

<figure><img src="../../../.gitbook/assets/image (1167).png" alt=""><figcaption></figcaption></figure>

Sasa, kufuatia `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` unaweza kuona data nyingi:

<figure><img src="../../../.gitbook/assets/image (1173).png" alt="" width="563"><figcaption></figcaption></figure>

Badilisha Aina ya Data kuwa **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1174).png" alt="" width="375"><figcaption></figcaption></figure>

baada ya mabadiliko:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Na sasa tunajua kuwa kuna **array ya vipengele 7** (angalia msimbo uliokwisha kudecompile), bonyeza kuunda array ya vipengele 7:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="563"><figcaption></figcaption></figure>

Baada ya array kuundwa unaweza kuona kazi zote zilizosafirishwa:

<figure><img src="../../../.gitbook/assets/image (1178).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Ukikumbuka, kwa **kupiga** kazi **iliyosafirishwa** kutoka nafasi ya mtumiaji hatuhitaji kuita jina la kazi, bali **namba ya kuchagua**. Hapa unaweza kuona kuwa chaguo **0** ni kazi **`initializeDecoder`**, chaguo **1** ni **`startDecoder`**, chaguo **2** **`initializeEncoder`**...
{% endhint %}
