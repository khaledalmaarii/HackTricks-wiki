# macOS IOKit

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **sakeman in siber-sekuriteit**? Wil jy hê dat jou **sakeman geadverteer word op HackTricks**? Of wil jy toegang hê tot die **laaste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS en HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegram-groep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou haktruuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basiese Inligting

Die I/O Kit is 'n oopbron, objekgeoriënteerde **toestelbestuurder-raamwerk** in die XNU-kernel, hanteer **dinamies gelaaide toestelbestuurders**. Dit maak dit moontlik om modulêre kode vinnig by die kernel te voeg, wat uiteenlopende hardeware ondersteun.

IOKit-bestuurders sal basies **funksies uit die kernel uitvoer**. Hierdie funksieparameter **tipes** is **vooraf gedefinieer** en word geverifieer. Verder, soortgelyk aan XPC, is IOKit net nog 'n laag bo-op **Mach-boodskappe**.

**IOKit XNU kernel-kode** is deur Apple oopbron in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Verder is die gebruikerspas IOKit-komponente ook oopbron [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Tog is **geen IOKit-bestuurders** oopbron nie. Hoe dan ook, van tyd tot tyd kan 'n vrystelling van 'n bestuurder met simbole kom wat dit makliker maak om dit te ontleed. Kyk hoe om [**die bestuurder-uitbreidings van die firmware hier te kry**](./#ipsw)**.**

Dit is geskryf in **C++**. Jy kan ontwarde C++ simbole kry met:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **blootgestelde funksies** kan **addisionele sekuriteitskontroles** uitvoer wanneer 'n klient probeer om 'n funksie aan te roep, maar let daarop dat programme gewoonlik **beperk** word deur die **sandbox** tot watter IOKit funksies hulle kan interaksie mee hê.
{% endhint %}

## Bestuurders

In macOS is hulle geleë in:

* **`/System/Library/Extensions`**
* KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
* **`/Library/Extensions`**
* KEXT-lêers wat deur derdeparty sagteware geïnstalleer is

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
Tot by nommer 9 word die gelysde bestuurders **gelaai in die adres 0**. Dit beteken dat dit nie werklike bestuurders is nie, maar **deel van die kernel en hulle kan nie gelaai word nie**.

Om spesifieke uitbreidings te vind, kan jy gebruik:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Om kernel-uitbreidings te laai en te ontlas, doen die volgende:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** is 'n noodsaaklike deel van die IOKit-raamwerk in macOS en iOS wat dien as 'n databasis om die stelsel se hardewarekonfigurasie en -toestand voor te stel. Dit is 'n **hiërargiese versameling van voorwerpe wat al die hardeware en drywers** wat op die stelsel gelaai is, en hul verhoudings met mekaar, voorstel.

Jy kan die IORegistry kry deur die cli **`ioreg`** te gebruik om dit van die konsole te inspekteer (veral nuttig vir iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Jy kan **`IORegistryExplorer`** aflaai van **Xcode Aanvullende Gereedskap** vanaf [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) en die **macOS IORegistry** deur 'n **grafiese** koppelvlak inspekteer.

<figure><img src="../../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer word "vlakke" gebruik om die verhoudings tussen verskillende voorwerpe in die IORegistry te organiseer en te vertoon. Elke vlak verteenwoordig 'n spesifieke tipe verhouding of 'n spesifieke aansig van die stelsel se hardeware en drywerkonfigurasie. Hier is van die algemene vlakke wat jy in IORegistryExplorer mag teëkom:

1. **IOService Vlak**: Dit is die mees algemene vlak wat die diensvoorwerpe vertoon wat drywers en nubs (kommunikasiekanaal tussen drywers) verteenwoordig. Dit toon die verskaffer-kliëntverhoudings tussen hierdie voorwerpe.
2. **IODeviceTree Vlak**: Hierdie vlak verteenwoordig die fisiese verbindings tussen toestelle soos hulle aan die stelsel geheg is. Dit word dikwels gebruik om die hiërargie van toestelle wat via busse soos USB of PCI gekoppel is, te visualiseer.
3. **IOPower Vlak**: Vertoon voorwerpe en hul verhoudings in terme van kragbestuur. Dit kan wys watter voorwerpe die kragtoestand van ander beïnvloed, nuttig vir die foutopsporing van kragverwante probleme.
4. **IOUSB Vlak**: Spesifiek gefokus op USB-toestelle en hul verhoudings, wat die hiërargie van USB-hubs en gekoppelde toestelle vertoon.
5. **IOAudio Vlak**: Hierdie vlak is vir die verteenwoordiging van klanktoestelle en hul verhoudings binne die stelsel.
6. ...

## Drywer Komm Kode Voorbeeld

Die volgende kode verbind met die IOKit-diens `"JouDiensNaamHier"` en roep die funksie binne die kieser 0 aan. Vir dit:

* roep dit eers **`IOServiceMatching`** en **`IOServiceGetMatchingServices`** aan om die diens te kry.
* Dit vestig dan 'n verbinding deur **`IOServiceOpen`** aan te roep.
* En dit roep uiteindelik 'n funksie aan met **`IOConnectCallScalarMethod`** wat die kieser 0 aandui (die kieser is die nommer wat die funksie wat jy wil aanroep, toegewys het).
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
Daar is **ander** funksies wat gebruik kan word om IOKit funksies aan te roep, behalwe **`IOConnectCallScalarMethod`** soos **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Omkeer van bestuurder ingangspunt

Jy kan hierdie byvoorbeeld verkry vanaf 'n [**firmware beeld (ipsw)**](./#ipsw). Laai dit dan in jou gunsteling decompiler.

Jy kan begin met die dekompilering van die **`externalMethod`** funksie aangesien dit die bestuurder funksie is wat die oproep sal ontvang en die korrekte funksie sal aanroep:

<figure><img src="../../../.gitbook/assets/image (1165).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1166).png" alt=""><figcaption></figcaption></figure>

Daardie afgryslike oproep beteken:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Merk op hoe in die vorige definisie die **`self`** param gemis word, die goeie definisie sou wees:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Eintlik, jy kan die werklike definisie vind by [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Met hierdie inligting kan jy Ctrl+Right herskryf -> `Wysig funksie handtekening` en die bekende tipes instel:

<figure><img src="../../../.gitbook/assets/image (1171).png" alt=""><figcaption></figcaption></figure>

Die nuwe gedekompilde kode sal lyk soos:

<figure><img src="../../../.gitbook/assets/image (1172).png" alt=""><figcaption></figcaption></figure>

Vir die volgende stap moet ons die **`IOExternalMethodDispatch2022`** struktuur gedefinieer hê. Dit is oopbron in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), jy kan dit definieer:

<figure><img src="../../../.gitbook/assets/image (1167).png" alt=""><figcaption></figcaption></figure>

Nou, deur die `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` te volg, kan jy baie data sien:

<figure><img src="../../../.gitbook/assets/image (1173).png" alt="" width="563"><figcaption></figcaption></figure>

Verander die Datatipe na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1174).png" alt="" width="375"><figcaption></figcaption></figure>

na die verandering:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

En aangesien ons nou daar is, het ons 'n **array van 7 elemente** (kontroleer die finale gedekompilde kode), klik om 'n array van 7 elemente te skep:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="563"><figcaption></figcaption></figure>

Nadat die array geskep is, kan jy al die uitgevoerde funksies sien:

<figure><img src="../../../.gitbook/assets/image (1178).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
As jy onthou, om 'n **uitgevoerde** funksie vanuit gebruikerspas te **roep**, hoef ons nie die naam van die funksie te roep nie, maar die **selekteernommer**. Hier kan jy sien dat die selekteerder **0** die funksie **`initializeDecoder`** is, die selekteerder **1** is **`startDecoder`**, die selekteerder **2** **`initializeEncoder`**...
{% endhint %}
