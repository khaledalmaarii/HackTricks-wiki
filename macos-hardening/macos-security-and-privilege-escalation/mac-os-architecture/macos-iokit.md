# macOS IOKit

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za sajber bezbednost**? Želite da vidite svoju **kompaniju reklamiranu na HackTricks-u**? Ili želite pristup **poslednjoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF formatu**? Pogledajte [**PLANOVE ZA ČLANSTVO**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu ekskluzivnu kolekciju [**NFT-a**](https://opensea.io/collection/the-peass-family)
* Nabavite **zvanični PEASS i HackTricks** [**swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi** ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podelite svoje hakovanje trikova slanjem PR-a na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Osnovne informacije

IO Kit je open-source, objektno orijentisani **framework za drajvere uređaja** u XNU kernelu, koji upravlja **dinamički učitanim drajverima uređaja**. Omogućava dodavanje modularnog koda u kernel "on-the-fly", podržavajući različit hardver.

IOKit drajveri će uglavnom **izvoziti funkcije iz kernela**. Tipovi parametara ovih funkcija su **unapred definisani** i provereni. Osim toga, slično kao XPC, IOKit je samo još jedan sloj na **vrhu Mach poruka**.

**IOKit XNU kernel kod** je otvoren od strane Apple-a na [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Takođe, IOKit komponente u korisničkom prostoru su takođe otvorene [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Međutim, **nijedan IOKit drajver** nije otvorenog koda. U svakom slučaju, povremeno se može desiti da izdanje drajvera dođe sa simbolima koji olakšavaju njegovo debugiranje. Proverite kako **dobiti proširenja drajvera iz firmware-a ovde**](./#ipsw)**.

Napisan je u **C++**. Možete dobiti demangle C++ simbole sa:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **izložene funkcije** mogu izvršiti **dodatne sigurnosne provere** kada klijent pokuša da pozove funkciju, ali imajte na umu da aplikacije obično su **ograničene** od strane **peska-boksa** sa kojim IOKit funkcijama mogu da interaguju.
{% endhint %}

## Drajveri

Na macOS-u se nalaze u:

* **`/System/Library/Extensions`**
* KEXT fajlovi ugrađeni u OS X operativni sistem.
* **`/Library/Extensions`**
* KEXT fajlovi instalirani od strane softvera trećih strana

Na iOS-u se nalaze u:

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
Do broja 9 navedeni drajveri su **učitani na adresi 0**. To znači da to nisu pravi drajveri već **deo jezgra i ne mogu se isključiti**.

Kako biste pronašli određene ekstenzije, možete koristiti:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Da biste učitali i isključili proširenja jezgra, uradite sledeće:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** je ključni deo IOKit okvira u macOS-u i iOS-u koji služi kao baza podataka za predstavljanje konfiguracije hardvera i stanja sistema. To je **hijerarhijska kolekcija objekata koja predstavlja sav hardver i drajvere** učitane na sistemu, kao i njihove međusobne odnose.

IORegistry možete dobiti koristeći CLI **`ioreg`** kako biste ga pregledali iz konzole (posebno korisno za iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Možete preuzeti **`IORegistryExplorer`** iz **Dodatnih alata za Xcode** sa [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i pregledati **macOS IORegistry** kroz **grafički** interfejs.

<figure><img src="../../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

U IORegistryExplorer-u, "ravni" se koriste za organizovanje i prikaz odnosa između različitih objekata u IORegistry-ju. Svaka ravan predstavlja određenu vrstu odnosa ili određeni prikaz hardvera i konfiguracije drajvera sistema. Evo nekih od uobičajenih ravni sa kojima možete naići u IORegistryExplorer-u:

1. **IOService Ravan**: Ovo je najopštija ravan, prikazuje servisne objekte koji predstavljaju drajvere i nubove (kanale komunikacije između drajvera). Prikazuje odnose između pružalaca i klijenata između ovih objekata.
2. **IODeviceTree Ravan**: Ova ravan predstavlja fizičke veze između uređaja kako su povezani sa sistemom. Često se koristi za vizualizaciju hijerarhije uređaja povezanih putem busova poput USB-a ili PCI-a.
3. **IOPower Ravan**: Prikazuje objekte i njihove odnose u smislu upravljanja snagom. Može pokazati koji objekti utiču na stanje snage drugih, korisno za otklanjanje problema povezanih sa snagom.
4. **IOUSB Ravan**: Specifično fokusirana na USB uređaje i njihove odnose, prikazujući hijerarhiju USB hubova i povezanih uređaja.
5. **IOAudio Ravan**: Ova ravan služi za predstavljanje audio uređaja i njihovih odnosa unutar sistema.
6. ...

## Primer koda za komunikaciju sa drajverom

Sledeći kod se povezuje sa IOKit servisom `"ImeVašegServisaOvde"` i poziva funkciju unutar selektora 0. Za to:

* prvo poziva **`IOServiceMatching`** i **`IOServiceGetMatchingServices`** da dobije servis.
* Zatim uspostavlja vezu pozivajući **`IOServiceOpen`**.
* I na kraju poziva funkciju sa **`IOConnectCallScalarMethod`** navodeći selektor 0 (selektor je broj koji je dodeljen funkciji koju želite da pozovete).
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
Postoje **druge** funkcije koje se mogu koristiti za pozivanje IOKit funkcija osim **`IOConnectCallScalarMethod`** kao što su **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

Možete ih dobiti, na primer, iz [**firmver slike (ipsw)**](./#ipsw). Zatim je učitajte u svoj omiljeni dekompajler.

Možete početi dekompajlirati funkciju **`externalMethod`** jer je ovo funkcija drajvera koja će primati poziv i pozivati odgovarajuću funkciju:

<figure><img src="../../../.gitbook/assets/image (1165).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1166).png" alt=""><figcaption></figcaption></figure>

Ovaj užasni poziv demangle znači:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Primetite kako u prethodnoj definiciji nedostaje parametar **`self`**, dobra definicija bi bila:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Zapravo, pravu definiciju možete pronaći na [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Sa ovim informacijama možete prepraviti Ctrl+Desno -> `Uredi potpis funkcije` i postaviti poznate tipove:

<figure><img src="../../../.gitbook/assets/image (1171).png" alt=""><figcaption></figcaption></figure>

Novi dekompajlirani kod će izgledati ovako:

<figure><img src="../../../.gitbook/assets/image (1172).png" alt=""><figcaption></figcaption></figure>

Za sledeći korak moramo imati definisanu strukturu **`IOExternalMethodDispatch2022`**. To je otvorenog koda na [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), možete je definisati:

<figure><img src="../../../.gitbook/assets/image (1167).png" alt=""><figcaption></figcaption></figure>

Sada, prateći `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` možete videti puno podataka:

<figure><img src="../../../.gitbook/assets/image (1173).png" alt="" width="563"><figcaption></figcaption></figure>

Promenite tip podataka u **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1174).png" alt="" width="375"><figcaption></figcaption></figure>

nakon promene:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

I sada, pošto znamo da imamo **niz od 7 elemenata** (proverite konačni dekompajlirani kod), kliknite da biste kreirali niz od 7 elemenata:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="563"><figcaption></figcaption></figure>

Nakon što je niz kreiran, možete videti sve izvezene funkcije:

<figure><img src="../../../.gitbook/assets/image (1178).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Ako se sećate, da biste **pozvali** izvezenu funkciju iz korisničkog prostora, ne morate nazvati funkciju, već **broj selektora**. Ovde možete videti da je selektor **0** funkcija **`initializeDecoder`**, selektor **1** je **`startDecoder`**, selektor **2** **`initializeEncoder`**...
{% endhint %}
