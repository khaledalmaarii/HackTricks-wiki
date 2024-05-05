# macOS IOKit

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen auf HackTricks beworben sehen**? Oder möchten Sie Zugang zur **neuesten Version von PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS und HackTricks Merch**](https://peass.creator-spring.com)
* Treten Sie dem [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe** bei oder dem [**Telegram-Gruppe**](https://t.me/peass) oder **folgen Sie mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PR an** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

## Grundlegende Informationen

Das I/O Kit ist ein Open-Source, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel, das **dynamisch geladene Gerätetreiber** verarbeitet. Es ermöglicht die Hinzufügung von modularem Code zum Kernel im laufenden Betrieb und unterstützt vielfältige Hardware.

IOKit-Treiber **exportieren im Wesentlichen Funktionen aus dem Kernel**. Diese Funktionen haben **vordefinierte** Parameter und werden überprüft. Darüber hinaus ist IOKit ähnlich wie XPC nur eine weitere Schicht über **Mach-Nachrichten**.

Der **IOKit XNU-Kernelcode** wurde von Apple unter [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) veröffentlicht. Außerdem sind die IOKit-Komponenten im Benutzerbereich ebenfalls Open Source unter [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Jedoch sind **keine IOKit-Treiber** Open Source. Gelegentlich wird jedoch ein Treiber-Release mit Symbolen veröffentlicht, die das Debuggen erleichtern. Überprüfen Sie, wie Sie [**die Treibererweiterungen aus der Firmware hier erhalten können**](./#ipsw)**.**

Es ist in **C++** geschrieben. Sie können demangled C++-Symbole mit:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **exponierte Funktionen** könnten **zusätzliche Sicherheitsüberprüfungen** durchführen, wenn ein Client versucht, eine Funktion aufzurufen, aber beachten Sie, dass Apps in der Regel durch die **Sandbox** darauf beschränkt sind, mit welchen IOKit-Funktionen sie interagieren können.
{% endhint %}

## Treiber

In macOS befinden sie sich in:

* **`/System/Library/Extensions`**
* KEXT-Dateien, die in das Betriebssystem OS X integriert sind.
* **`/Library/Extensions`**
* KEXT-Dateien, die von Software von Drittanbietern installiert wurden

In iOS befinden sie sich in:

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
Bis zur Nummer 9 werden die aufgelisteten Treiber **in der Adresse 0 geladen**. Das bedeutet, dass es sich dabei nicht um echte Treiber handelt, sondern **Teil des Kernels sind und nicht entladen werden können**.

Um spezifische Erweiterungen zu finden, können Sie Folgendes verwenden:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Um Kernel-Erweiterungen zu laden und zu entladen, führen Sie Folgendes aus:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** ist ein entscheidender Bestandteil des IOKit-Frameworks in macOS und iOS, das als Datenbank zur Darstellung der Hardwarekonfiguration und des Zustands des Systems dient. Es handelt sich um eine **hierarchische Sammlung von Objekten, die die gesamte Hardware und Treiber** auf dem System sowie deren Beziehungen zueinander darstellen.

Sie können die IORegistry mithilfe des Befehlszeilentools **`ioreg`** abrufen, um sie von der Konsole aus zu inspizieren (besonders nützlich für iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Du könntest **`IORegistryExplorer`** von den **Zusätzlichen Tools von Xcode** von [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) herunterladen und das **macOS IORegistry** durch eine **grafische** Benutzeroberfläche inspizieren.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer werden "Ebenen" verwendet, um die Beziehungen zwischen verschiedenen Objekten im IORegistry zu organisieren und anzuzeigen. Jede Ebene repräsentiert einen spezifischen Beziehungstyp oder eine bestimmte Ansicht der Hardware- und Treiberkonfiguration des Systems. Hier sind einige der häufig vorkommenden Ebenen, auf die du in IORegistryExplorer stoßen könntest:

1. **IOService-Ebene**: Dies ist die allgemeinste Ebene, die die Serviceobjekte anzeigt, die Treiber und Nubs (Kommunikationskanäle zwischen Treibern) repräsentieren. Es zeigt die Anbieter-Client-Beziehungen zwischen diesen Objekten.
2. **IODeviceTree-Ebene**: Diese Ebene repräsentiert die physischen Verbindungen zwischen Geräten, wie sie mit dem System verbunden sind. Sie wird oft verwendet, um die Hierarchie der über Busse wie USB oder PCI verbundenen Geräte zu visualisieren.
3. **IOPower-Ebene**: Zeigt Objekte und ihre Beziehungen in Bezug auf das Energiemanagement an. Es kann zeigen, welche Objekte den Energiezustand anderer beeinflussen, was nützlich ist, um Probleme im Zusammenhang mit der Stromversorgung zu debuggen.
4. **IOUSB-Ebene**: Speziell auf USB-Geräte und deren Beziehungen fokussiert, zeigt die Hierarchie von USB-Hubs und angeschlossenen Geräten.
5. **IOAudio-Ebene**: Diese Ebene dient zur Darstellung von Audiogeräten und deren Beziehungen innerhalb des Systems.
6. ...

## Beispiel für Treiberkommunikationscode

Der folgende Code verbindet sich mit dem IOKit-Dienst `"DeinServiceNameHier"` und ruft die Funktion im Selektor 0 auf. Dafür:

* ruft es zuerst **`IOServiceMatching`** und **`IOServiceGetMatchingServices`** auf, um den Dienst zu erhalten.
* Es stellt dann eine Verbindung her, indem es **`IOServiceOpen`** aufruft.
* Und ruft schließlich eine Funktion mit **`IOConnectCallScalarMethod`** auf, wobei der Selektor 0 angegeben ist (der Selektor ist die Nummer, die der Funktion zugewiesen ist, die du aufrufen möchtest).
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
Es gibt **andere** Funktionen, die verwendet werden können, um IOKit-Funktionen aufzurufen, abgesehen von **`IOConnectCallScalarMethod`** wie **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Umkehrung des Treibereinstiegspunkts

Sie könnten diese beispielsweise aus einem [**Firmware-Image (ipsw)**](./#ipsw) erhalten. Laden Sie es dann in Ihren bevorzugten Decompiler.

Sie könnten mit dem Dekompilieren der **`externalMethod`**-Funktion beginnen, da dies die Treiberfunktion ist, die den Aufruf empfängt und die richtige Funktion aufruft:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

Dieser schreckliche Aufruf bedeutet:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Beachten Sie, wie in der vorherigen Definition der **`self`**-Parameter fehlt, die korrekte Definition wäre: 

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Tatsächlich finden Sie die genaue Definition unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mit diesen Informationen können Sie `Strg+Rechts -> `Funktions-Signatur bearbeiten` neu schreiben und die bekannten Typen festlegen:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Der neue dekompilierte Code wird wie folgt aussehen:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Für den nächsten Schritt müssen wir die **`IOExternalMethodDispatch2022`** Struktur definiert haben. Es ist Open Source unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) verfügbar, Sie könnten es definieren:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Nun, nach dem `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` können Sie viele Daten sehen:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Ändern Sie den Datentyp in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

nach der Änderung:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Und da wir jetzt wissen, dass wir ein **Array mit 7 Elementen** haben (überprüfen Sie den endgültigen dekompilierten Code), klicken Sie, um ein Array mit 7 Elementen zu erstellen:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nachdem das Array erstellt wurde, können Sie alle exportierten Funktionen sehen:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Wenn Sie sich erinnern, um eine **exportierte** Funktion aus dem Benutzerbereich aufzurufen, müssen Sie nicht den Namen der Funktion aufrufen, sondern die **Selektornummer**. Hier sehen Sie, dass der Selektor **0** die Funktion **`initializeDecoder`** ist, der Selektor **1** ist **`startDecoder`**, der Selektor **2** **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen auf HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS- und HackTricks-Merch**](https://peass.creator-spring.com)
* Treten Sie dem [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe** bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen Sie mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* Teilen Sie Ihre Hacking-Tricks, indem Sie PR an das [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) und das [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) senden.

</details>
