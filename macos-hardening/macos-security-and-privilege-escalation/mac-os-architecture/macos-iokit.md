# macOS IOKit

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN ZASUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą ekskluzywną kolekcję [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS i HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) **grupy Discord** lub [**grupy telegramowej**](https://t.me/peass) lub **śledź mnie** na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podziel się swoimi sztuczkami hakerskimi, wysyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Podstawowe informacje

IOKit to otwarty, obiektowy **framework sterowników urządzeń** w jądrze XNU, obsługujący **dynamicznie ładowane sterowniki urządzeń**. Pozwala na dodawanie modułowego kodu do jądra w locie, obsługując różnorodny sprzęt.

Sterowniki IOKit w zasadzie **eksportują funkcje z jądra**. Typy parametrów tych funkcji są **predefiniowane** i weryfikowane. Ponadto, podobnie jak XPC, IOKit to kolejna warstwa na **szczycie komunikatów Mach**.

Kod jądra **IOKit XNU** jest udostępniony przez Apple na stronie [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Ponadto, komponenty IOKit w przestrzeni użytkownika są również udostępnione jako otwarte źródło [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Jednak **żadne sterowniki IOKit** nie są udostępnione jako otwarte źródło. Niemniej jednak, od czasu do czasu wydanie sterownika może zawierać symbole ułatwiające jego debugowanie. Sprawdź, jak [**uzyskać rozszerzenia sterownika z firmware tutaj**](./#ipsw)**.**

Jest napisany w **C++**. Możesz uzyskać zdemagnetyzowane symbole C++ za pomocą:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Funkcje **udostępnione przez IOKit** mogą wykonywać **dodatkowe kontrole bezpieczeństwa**, gdy klient próbuje wywołać funkcję, ale zauważ, że aplikacje są zazwyczaj **ograniczone** przez **sandbox**, z którym funkcje IOKit mogą współdziałać.
{% endhint %}

## Sterowniki

W systemie macOS znajdują się tutaj:

* **`/System/Library/Extensions`**
* Pliki KEXT wbudowane w system operacyjny OS X.
* **`/Library/Extensions`**
* Pliki KEXT zainstalowane przez oprogramowanie firm trzecich.

W systemie iOS znajdują się tutaj:

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
Do numeru 9 wymienione sterowniki są **załadowane pod adresem 0**. Oznacza to, że nie są to prawdziwe sterowniki, ale **część jądra i nie można ich odładować**.

Aby znaleźć konkretne rozszerzenia, można użyć:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Aby załadować i wyładować rozszerzenia jądra, wykonaj:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** jest kluczową częścią frameworka IOKit w systemach macOS i iOS, która służy jako baza danych do reprezentowania konfiguracji sprzętu i stanu systemu. Jest to **hierarchiczna kolekcja obiektów, które reprezentują cały sprzęt i sterowniki** załadowane w systemie oraz ich wzajemne relacje.&#x20;

Możesz uzyskać dostęp do IORegistry za pomocą polecenia **`ioreg`** w celu jego inspekcji z konsoli (szczególnie przydatne w przypadku iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Możesz pobrać **`IORegistryExplorer`** z **Dodatkowych narzędzi Xcode** ze strony [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i przeglądać **macOS IORegistry** za pomocą **graficznego** interfejsu.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

W IORegistryExplorer "płaszczyzny" są używane do organizowania i wyświetlania relacji między różnymi obiektami w IORegistry. Każda płaszczyzna reprezentuje określony typ relacji lub określony widok konfiguracji sprzętu i sterowników systemu. Oto kilka powszechnych płaszczyzn, z którymi możesz się spotkać w IORegistryExplorer:

1. **Płaszczyzna IOService**: To najbardziej ogólna płaszczyzna, wyświetlająca obiekty usług reprezentujące sterowniki i nuby (kanały komunikacyjne między sterownikami). Pokazuje relacje dostawca-klient między tymi obiektami.
2. **Płaszczyzna IODeviceTree**: Ta płaszczyzna reprezentuje fizyczne połączenia między urządzeniami, gdy są podłączone do systemu. Często jest używana do wizualizacji hierarchii urządzeń podłączonych za pomocą magistral takich jak USB lub PCI.
3. **Płaszczyzna IOPower**: Wyświetla obiekty i ich relacje w kontekście zarządzania energią. Może pokazywać, które obiekty wpływają na stan zasilania innych, co jest przydatne do debugowania problemów związanych z zasilaniem.
4. **Płaszczyzna IOUSB**: Skupia się szczególnie na urządzeniach USB i ich relacjach, pokazując hierarchię hubów USB i podłączonych urządzeń.
5. **Płaszczyzna IOAudio**: Ta płaszczyzna służy do reprezentowania urządzeń audio i ich relacji w systemie.
6. ...

## Przykład kodu komunikacji sterownika

Poniższy kod łączy się z usługą IOKit o nazwie `"YourServiceNameHere"` i wywołuje funkcję wewnątrz selektora 0. Aby to zrobić:

* najpierw wywołuje funkcje **`IOServiceMatching`** i **`IOServiceGetMatchingServices`** w celu znalezienia usługi.
* Następnie nawiązuje połączenie, wywołując **`IOServiceOpen`**.
* Na koniec wywołuje funkcję za pomocą **`IOConnectCallScalarMethod`**, wskazując selektor 0 (selektor to numer przypisany do funkcji, którą chcesz wywołać).
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
Istnieją **inne** funkcje, które można użyć do wywoływania funkcji IOKit oprócz **`IOConnectCallScalarMethod`**, takie jak **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Odwracanie punktu wejścia sterownika

Możesz je na przykład uzyskać z [**obrazu firmware (ipsw)**](./#ipsw). Następnie załaduj go do ulubionego dekompilatora.

Możesz rozpocząć dekompilację funkcji **`externalMethod`**, ponieważ jest to funkcja sterownika, która będzie odbierać wywołanie i wywoływać odpowiednią funkcję:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Ten okropny wywołanie oznacza:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Zauważ, że w poprzedniej definicji brakuje parametru **`self`**, poprawna definicja wyglądałaby tak:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

W rzeczywistości prawdziwą definicję można znaleźć pod adresem [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Z tą informacją możesz przepisać Ctrl+Right -> `Edytuj sygnaturę funkcji` i ustawić znane typy:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Nowy zdekompilowany kod będzie wyglądał tak:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

W kolejnym kroku musimy zdefiniować strukturę **`IOExternalMethodDispatch2022`**. Jest ona dostępna jako open source pod adresem [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), możesz ją zdefiniować:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Teraz, podążając za `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, możesz zobaczyć wiele danych:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Zmień typ danych na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

po zmianie:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

I teraz, gdy mamy **tablicę 7 elementów** (sprawdź końcowy zdekompilowany kod), kliknij, aby utworzyć tablicę 7 elementów:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Po utworzeniu tablicy możesz zobaczyć wszystkie wyeksportowane funkcje:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Jeśli pamiętasz, aby **wywołać** funkcję **wyeksportowaną** z przestrzeni użytkownika, nie musisz wywoływać nazwy funkcji, ale **numer selektora**. Tutaj możesz zobaczyć, że selektor **0** to funkcja **`initializeDecoder`**, selektor **1** to **`startDecoder`**, selektor **2** to **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz uzyskać dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą ekskluzywną kolekcję [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź oficjalne [**swag PEASS i HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) **grupy Discord** lub [**grupy telegram**](https://t.me/peass) lub **śledź mnie** na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Podziel się swoimi sztuczkami hakerskimi, wysyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
