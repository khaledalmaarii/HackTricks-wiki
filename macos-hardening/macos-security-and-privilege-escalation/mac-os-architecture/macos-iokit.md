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

I/O Kit je open-source, objektno-orijentisani **okvir drajvera uređaja** u XNU kernelu, koji upravlja **dinamički učitanim drajverima uređaja**. Omogućava dodavanje modularnog koda u kernel u hodu, podržavajući raznovrsni hardver.

IOKit drajveri će u osnovi **izvoziti funkcije iz kernela**. Ovi parametri funkcija su **preddefinisani** i verifikovani. Štaviše, slično XPC-u, IOKit je samo još jedan sloj **iznad Mach poruka**.

**IOKit XNU kernel kod** je open-source od strane Apple-a na [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Takođe, komponente IOKit korisničkog prostora su takođe open-source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Međutim, **nema IOKit drajvera** koji su open-source. U svakom slučaju, s vremena na vreme, objavljivanje drajvera može doći sa simbolima koji olakšavaju njegovo debagovanje. Proverite kako da [**dobijete ekstenzije drajvera iz firmvera ovde**](./#ipsw)**.**

Napisan je u **C++**. Možete dobiti demanglovane C++ simbole sa:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **izložene funkcije** mogu izvršiti **dodatne provere bezbednosti** kada klijent pokuša da pozove funkciju, ali imajte na umu da su aplikacije obično **ograničene** od strane **sandbox-a** sa kojima IOKit funkcije mogu da komuniciraju.
{% endhint %}

## Drajveri

U macOS se nalaze u:

* **`/System/Library/Extensions`**
* KEXT datoteke ugrađene u OS X operativni sistem.
* **`/Library/Extensions`**
* KEXT datoteke instalirane od strane softvera trećih strana

U iOS se nalaze u:

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
Dok broj 9, navedeni drajveri su **učitani na adresi 0**. To znači da to nisu pravi drajveri već **deo kernela i ne mogu se ukloniti**.

Da biste pronašli specifične ekstenzije, možete koristiti:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Da biste učitali i ispraznili kernel ekstenzije, uradite:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** je ključni deo IOKit okvira u macOS-u i iOS-u koji služi kao baza podataka za predstavljanje hardverske konfiguracije i stanja sistema. To je **hijerarhijska kolekcija objekata koja predstavlja sav hardver i drajvere** učitane na sistemu, kao i njihove međusobne odnose.

Možete dobiti IORegistry koristeći cli **`ioreg`** da biste ga pregledali iz konzole (posebno korisno za iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Možete preuzeti **`IORegistryExplorer`** iz **Xcode Dodatnih Alata** sa [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i pregledati **macOS IORegistry** kroz **grafički** interfejs.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

U IORegistryExplorer-u, "planovi" se koriste za organizovanje i prikazivanje odnosa između različitih objekata u IORegistry-ju. Svaki plan predstavlja specifičnu vrstu odnosa ili poseban prikaz hardverske i drajverske konfiguracije sistema. Evo nekih od uobičajenih planova koje možete sresti u IORegistryExplorer-u:

1. **IOService Plane**: Ovo je najopštiji plan, koji prikazuje servisne objekte koji predstavljaju drajvere i nubs (kanale komunikacije između drajvera). Prikazuje odnose između provajdera i klijenata ovih objekata.
2. **IODeviceTree Plane**: Ovaj plan predstavlja fizičke veze između uređaja dok su priključeni na sistem. Često se koristi za vizualizaciju hijerarhije uređaja povezanih putem magistrala kao što su USB ili PCI.
3. **IOPower Plane**: Prikazuje objekte i njihove odnose u smislu upravljanja energijom. Može pokazati koji objekti utiču na stanje napajanja drugih, što je korisno za otklanjanje grešaka povezanih sa energijom.
4. **IOUSB Plane**: Specifično fokusiran na USB uređaje i njihove odnose, prikazuje hijerarhiju USB hub-ova i povezanih uređaja.
5. **IOAudio Plane**: Ovaj plan je za predstavljanje audio uređaja i njihovih odnosa unutar sistema.
6. ...

## Primer Koda za Komunikaciju sa Draiverom

Sledeći kod se povezuje na IOKit servis `"YourServiceNameHere"` i poziva funkciju unutar selektora 0. Za to:

* prvo poziva **`IOServiceMatching`** i **`IOServiceGetMatchingServices`** da dobije servis.
* Zatim uspostavlja vezu pozivajući **`IOServiceOpen`**.
* I konačno poziva funkciju sa **`IOConnectCallScalarMethod`** označavajući selektor 0 (selektor je broj koji je funkciji koju želite da pozovete dodeljen).
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
Postoje **druge** funkcije koje se mogu koristiti za pozivanje IOKit funkcija pored **`IOConnectCallScalarMethod`** kao što su **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reverzno inženjerstvo ulazne tačke drajvera

Možete ih dobiti, na primer, iz [**firmware slike (ipsw)**](./#ipsw). Zatim, učitajte je u svoj omiljeni dekompajler.

Možete početi dekompilaciju funkcije **`externalMethod`** jer je to funkcija drajvera koja će primati poziv i pozivati odgovarajuću funkciju:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

Ta strašna pozivna demanglovana znači:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Obratite pažnju na to kako u prethodnoj definiciji nedostaje **`self`** parametar, dobra definicija bi bila:

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
Sa ovom informacijom možete prepraviti Ctrl+Desno -> `Edit function signature` i postaviti poznate tipove:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Novi dekompilirani kod će izgledati ovako:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Za sledeći korak potrebno je da definišemo **`IOExternalMethodDispatch2022`** strukturu. Ona je otvorenog koda na [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), možete je definisati:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Sada, prateći `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` možete videti mnogo podataka:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Promenite Tip Podataka u **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

posle promene:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

I kao što sada znamo, ovde imamo **niz od 7 elemenata** (proverite konačni dekompilirani kod), kliknite da kreirate niz od 7 elemenata:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nakon što je niz kreiran, možete videti sve eksportovane funkcije:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Ako se sećate, da **pozovete** **eksportovanu** funkciju iz korisničkog prostora, ne treba da pozivate ime funkcije, već **broj selektora**. Ovde možete videti da je selektor **0** funkcija **`initializeDecoder`**, selektor **1** je **`startDecoder`**, selektor **2** **`initializeEncoder`**...
{% endhint %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
