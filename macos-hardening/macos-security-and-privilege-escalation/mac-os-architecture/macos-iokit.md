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

## Podstawowe informacje

IO Kit to otwartoźródłowy, obiektowy **framework sterowników urządzeń** w jądrze XNU, obsługujący **dynamicznie ładowane sterowniki urządzeń**. Umożliwia dodawanie modularnego kodu do jądra w locie, wspierając różnorodny sprzęt.

Sterowniki IOKit zasadniczo **eksportują funkcje z jądra**. Typy **parametrów** tych funkcji są **zdefiniowane z góry** i są weryfikowane. Ponadto, podobnie jak XPC, IOKit jest po prostu kolejną warstwą **na szczycie komunikatów Mach**.

**Kod jądra IOKit XNU** jest otwartoźródłowy i udostępniony przez Apple w [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Ponadto, komponenty IOKit w przestrzeni użytkownika są również otwartoźródłowe [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Jednakże, **żadne sterowniki IOKit** nie są otwartoźródłowe. Tak czy inaczej, od czasu do czasu wydanie sterownika może zawierać symbole, które ułatwiają jego debugowanie. Sprawdź, jak [**uzyskać rozszerzenia sterownika z oprogramowania układowego tutaj**](./#ipsw)**.**

Jest napisany w **C++**. Możesz uzyskać zdemanglowane symbole C++ za pomocą:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Funkcje **exponowane przez IOKit** mogą wykonywać **dodatkowe kontrole bezpieczeństwa**, gdy klient próbuje wywołać funkcję, ale należy zauważyć, że aplikacje są zazwyczaj **ograniczone** przez **piaskownicę**, z którymi funkcjami IOKit mogą wchodzić w interakcje.
{% endhint %}

## Sterowniki

W macOS znajdują się w:

* **`/System/Library/Extensions`**
* Pliki KEXT wbudowane w system operacyjny OS X.
* **`/Library/Extensions`**
* Pliki KEXT zainstalowane przez oprogramowanie firm trzecich

W iOS znajdują się w:

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
Do numeru 9 wymienione sterowniki są **załadowane pod adresem 0**. Oznacza to, że nie są to prawdziwe sterowniki, ale **część jądra i nie mogą być odładowane**.

Aby znaleźć konkretne rozszerzenia, możesz użyć:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Aby załadować i odładować rozszerzenia jądra, wykonaj:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** jest kluczową częścią frameworka IOKit w macOS i iOS, który służy jako baza danych do reprezentowania konfiguracji i stanu sprzętu systemu. To **hierarchiczna kolekcja obiektów, które reprezentują cały sprzęt i sterowniki** załadowane w systemie oraz ich wzajemne relacje.

Możesz uzyskać IORegistry za pomocą cli **`ioreg`**, aby go zbadać z konsoli (szczególnie przydatne dla iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Możesz pobrać **`IORegistryExplorer`** z **Xcode Additional Tools** z [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i zbadać **macOS IORegistry** za pomocą **interfejsu graficznego**.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

W IORegistryExplorer "płaszczyzny" są używane do organizowania i wyświetlania relacji między różnymi obiektami w IORegistry. Każda płaszczyzna reprezentuje określony typ relacji lub szczególny widok konfiguracji sprzętowej i sterowników systemu. Oto niektóre z powszechnych płaszczyzn, które możesz napotkać w IORegistryExplorer:

1. **IOService Plane**: To najbardziej ogólna płaszczyzna, wyświetlająca obiekty usług, które reprezentują sterowniki i nuby (kanały komunikacyjne między sterownikami). Pokazuje relacje dostawca-klient między tymi obiektami.
2. **IODeviceTree Plane**: Ta płaszczyzna reprezentuje fizyczne połączenia między urządzeniami, gdy są podłączone do systemu. Często jest używana do wizualizacji hierarchii urządzeń podłączonych przez magistrale, takie jak USB lub PCI.
3. **IOPower Plane**: Wyświetla obiekty i ich relacje w kontekście zarządzania energią. Może pokazać, które obiekty wpływają na stan zasilania innych, co jest przydatne do debugowania problemów związanych z zasilaniem.
4. **IOUSB Plane**: Skupia się na urządzeniach USB i ich relacjach, pokazując hierarchię hubów USB i podłączonych urządzeń.
5. **IOAudio Plane**: Ta płaszczyzna jest przeznaczona do reprezentowania urządzeń audio i ich relacji w systemie.
6. ...

## Przykład kodu komunikacji sterownika

Poniższy kod łączy się z usługą IOKit `"YourServiceNameHere"` i wywołuje funkcję wewnątrz selektora 0. W tym celu:

* najpierw wywołuje **`IOServiceMatching`** i **`IOServiceGetMatchingServices`**, aby uzyskać usługę.
* Następnie nawiązuje połączenie, wywołując **`IOServiceOpen`**.
* A na końcu wywołuje funkcję za pomocą **`IOConnectCallScalarMethod`**, wskazując selektor 0 (selektor to numer przypisany funkcji, którą chcesz wywołać).
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
There are **inne** functions that can be used to call IOKit functions apart of **`IOConnectCallScalarMethod`** like **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

You could obtain these for example from a [**obraz firmware (ipsw)**](./#ipsw). Then, load it into your favourite decompiler.

You could start decompiling the **`externalMethod`** function as this is the driver function that will be receiving the call and calling the correct function:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

That awful call demagled means:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Zauważ, że w poprzedniej definicji brakuje parametru **`self`**, dobra definicja to:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

W rzeczywistości możesz znaleźć prawdziwą definicję w [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Z tymi informacjami możesz przepisać Ctrl+Right -> `Edit function signature` i ustawić znane typy:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Nowy dekompilowany kod będzie wyglądać następująco:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Na następnym etapie musimy zdefiniować strukturę **`IOExternalMethodDispatch2022`**. Jest to open source w [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), możesz ją zdefiniować:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Teraz, po `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` możesz zobaczyć wiele danych:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Zmień typ danych na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

po zmianie:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Jak teraz widzimy, mamy **tablicę 7 elementów** (sprawdź końcowy dekompilowany kod), kliknij, aby utworzyć tablicę 7 elementów:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Po utworzeniu tablicy możesz zobaczyć wszystkie eksportowane funkcje:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Jeśli pamiętasz, aby **wywołać** funkcję **eksportowaną** z przestrzeni użytkownika, nie musimy wywoływać nazwy funkcji, ale **numer selektora**. Tutaj możesz zobaczyć, że selektor **0** to funkcja **`initializeDecoder`**, selektor **1** to **`startDecoder`**, selektor **2** **`initializeEncoder`**...
{% endhint %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
