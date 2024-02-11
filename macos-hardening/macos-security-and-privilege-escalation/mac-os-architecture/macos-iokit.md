# macOS IOKit

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer op HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS en HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegram-groep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou hacking-truuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basiese Inligting

Die I/O Kit is 'n oopbron, objek-georiënteerde **toestuurder-raamwerk** in die XNU-kernel, wat **dinamies gelaai word toestuurders** hanteer. Dit maak dit moontlik om modulêre kode op die vlieg by die kernel te voeg, wat diverse hardeware ondersteun.

IOKit-bestuurders sal basies **funksies uit die kernel uitvoer**. Hierdie funksieparameter **tipes** is **voorgedefinieer** en word geverifieer. Verder, soos XPC, is IOKit net nog 'n laag **bo-op Mach-boodskappe**.

Die **IOKit XNU-kernelkode** is deur Apple oopbron in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Verder is die IOKit-komponente vir gebruikersruimte ook oopbron [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Nietemin, **geen IOKit-bestuurders** is oopbron nie. In elk geval kan 'n vrystelling van 'n bestuurder van tyd tot tyd met simbole kom wat dit makliker maak om dit te foutopspoor. Kyk hoe om [**die bestuurderuitbreidings uit die firmware te kry hier**](./#ipsw)**.**

Dit is in **C++** geskryf. Jy kan gedemangelde C++-simbole kry met:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **blootgestelde funksies** kan **addisionele sekuriteitskontroles** uitvoer wanneer 'n kliënt probeer om 'n funksie aan te roep, maar let daarop dat die programme gewoonlik **beperk** word deur die **sandbox** waarmee IOKit funksies kan interaksie hê.
{% endhint %}

## Bestuurders

In macOS is hulle geleë in:

* **`/System/Library/Extensions`**
* KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
* **`/Library/Extensions`**
* KEXT-lêers wat deur derdeparty sagteware geïnstalleer is.

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
Tot by nommer 9 word die gelysde drywers **gelaai in die adres 0**. Dit beteken dat dit nie werklike drywers is nie, maar **deel van die kernel en hulle kan nie gelaai word nie**.

Om spesifieke uitbreidings te vind, kan jy gebruik maak van:
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

Die **IORegistry** is 'n belangrike deel van die IOKit-raamwerk in macOS en iOS wat dien as 'n databasis vir die voorstelling van die stelsel se hardewarekonfigurasie en -toestand. Dit is 'n **hiërargiese versameling van voorwerpe wat al die hardeware en drywers verteenwoordig** wat op die stelsel gelaai is, en hul verhoudings met mekaar.&#x20;

Jy kan die IORegistry kry deur die opdrag **`ioreg`** te gebruik om dit vanaf die konsole te ondersoek (veral nuttig vir iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Jy kan **`IORegistryExplorer`** aflaai vanaf **Xcode Additional Tools** by [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) en die **macOS IORegistry** deur middel van 'n **grafiese** koppelvlak ondersoek.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer word "vlakke" gebruik om die verhoudings tussen verskillende voorwerpe in die IORegistry te organiseer en te vertoon. Elke vlak verteenwoordig 'n spesifieke tipe verhouding of 'n spesifieke aansig van die stelsel se hardeware- en drywerkonfigurasie. Hier is 'n paar van die algemene vlakke wat jy in IORegistryExplorer mag teëkom:

1. **IOService-vlak**: Dit is die algemeenste vlak wat diensvoorwerpe vertoon wat drywers en nubs (kommunikasiekanale tussen drywers) voorstel. Dit toon die verskaffer-kliëntverhoudings tussen hierdie voorwerpe.
2. **IODeviceTree-vlak**: Hierdie vlak verteenwoordig die fisiese verbindings tussen toestelle soos hulle aan die stelsel gekoppel is. Dit word dikwels gebruik om die hiërargie van toestelle wat via busse soos USB of PCI gekoppel is, te visualiseer.
3. **IOPower-vlak**: Vertoon voorwerpe en hul verhoudings in terme van kragbestuur. Dit kan wys watter voorwerpe die kragtoestand van ander beïnvloed, wat nuttig is vir die opspoor van kragverwante probleme.
4. **IOUSB-vlak**: Spesifiek gefokus op USB-toestelle en hul verhoudings, wat die hiërargie van USB-hubs en gekoppelde toestelle vertoon.
5. **IOAudio-vlak**: Hierdie vlak is vir die verteenwoordiging van klanktoestelle en hul verhoudings binne die stelsel.
6. ...

## Voorbeeld van drywerkommunikasiekode

Die volgende kode maak verbinding met die IOKit-diens `"YourServiceNameHere"` en roep die funksie binne die selektor 0 aan. Hiervoor:

* roep dit eers **`IOServiceMatching`** en **`IOServiceGetMatchingServices`** aan om die diens te kry.
* Dit vestig dan 'n verbinding deur **`IOServiceOpen`** te roep.
* En dit roep uiteindelik 'n funksie aan met **`IOConnectCallScalarMethod`** wat die selektor 0 aandui (die selektor is die nommer wat aan die funksie wat jy wil oproep, toegeken is).
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
Daar is **ander** funksies wat gebruik kan word om IOKit funksies aan te roep, afgesien van **`IOConnectCallScalarMethod`** soos **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Omkeer van bestuurder se intreepunt

Jy kan dit byvoorbeeld verkry vanaf 'n [**firmware-beeld (ipsw)**](./#ipsw). Laai dit dan in jou gunsteling dekompiler.

Jy kan begin dekompilering van die **`externalMethod`** funksie aangesien dit die bestuursfunksie is wat die oproep sal ontvang en die korrekte funksie sal aanroep:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Daardie afgryslike oproep beteken: 

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Let op hoe in die vorige definisie die **`self`** parameter weggelaat is, die goeie definisie sou wees:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Eintlik kan jy die werklike definisie vind by [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Met hierdie inligting kan jy Ctrl+Right herskryf -> `Wysig funksie handtekening` en stel die bekende tipes in:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Die nuwe gedekomponeerde kode sal lyk soos:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Vir die volgende stap moet ons die **`IOExternalMethodDispatch2022`** struktuur gedefinieer hê. Dit is oopbron in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), jy kan dit definieer:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Nou, volgens die `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` kan jy baie data sien:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Verander die Data Tipe na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

na die verandering:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

En soos ons nou weet, het ons 'n **array van 7 elemente** (kontroleer die finale gedekomponeerde kode), klik om 'n array van 7 elemente te skep:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Nadat die array geskep is, kan jy al die uitgevoerde funksies sien:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
As jy onthou, om 'n uitgevoerde funksie vanuit gebruikersruimte te **roep**, hoef ons nie die naam van die funksie te noem nie, maar die **selekteernommer**. Hier kan jy sien dat die selekteerder **0** die funksie **`initializeDecoder`** is, die selekteerder **1** is **`startDecoder`**, die selekteerder **2** is **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer op HackTricks**? Of wil jy toegang hê tot die **laaste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS- en HackTricks-swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegramgroep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou hacking-truuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
