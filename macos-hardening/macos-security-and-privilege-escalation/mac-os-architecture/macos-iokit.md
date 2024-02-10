# macOS IOKit

<details>

<summary><strong>Lerne AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeitest du in einem **Cybersecurity-Unternehmen**? Möchtest du dein **Unternehmen auf HackTricks bewerben**? Oder möchtest du Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Schau dir die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Entdecke [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Hol dir das [**offizielle PEASS und HackTricks Merch**](https://peass.creator-spring.com)
* **Trete der** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe** oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folge mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Teile deine Hacking-Tricks, indem du einen PR an** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **sendest**.

</details>

## Grundlegende Informationen

Das I/O Kit ist ein Open-Source, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel, das **dynamisch geladene Gerätetreiber** verwaltet. Es ermöglicht das Hinzufügen von modularem Code zum Kernel im laufenden Betrieb und unterstützt verschiedene Hardware.

IOKit-Treiber **exportieren im Wesentlichen Funktionen aus dem Kernel**. Diese Funktionen haben **vordefinierte Parameter** und werden überprüft. Ähnlich wie XPC ist IOKit nur eine weitere Schicht **über Mach-Nachrichten**.

Der **IOKit XNU-Kernelcode** wird von Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) als Open Source veröffentlicht. Darüber hinaus sind auch die IOKit-Komponenten im Benutzerbereich Open Source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Allerdings sind **keine IOKit-Treiber** Open Source. Gelegentlich kann jedoch eine Veröffentlichung eines Treibers mit Symbolen erfolgen, die das Debuggen erleichtern. Erfahre hier, wie du **die Treibererweiterungen aus der Firmware erhältst**](./#ipsw)**.

Es ist in **C++** geschrieben. Du kannst demanglierte C++-Symbole mit folgendem Befehl erhalten:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **exposed functions** could perform **additional security checks** when a client tries to call a function but note that the apps are usually **limited** by the **sandbox** to which IOKit functions they can interact with.
{% endhint %}

## Treiber

In macOS befinden sie sich in:

* **`/System/Library/Extensions`**
* KEXT-Dateien, die in das OS X-Betriebssystem integriert sind.
* **`/Library/Extensions`**
* KEXT-Dateien, die von Drittanbieter-Software installiert wurden.

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
Bis zur Nummer 9 werden die aufgelisteten Treiber **an der Adresse 0 geladen**. Das bedeutet, dass es sich dabei nicht um echte Treiber handelt, sondern **Teil des Kernels sind und nicht entladen werden können**.

Um bestimmte Erweiterungen zu finden, können Sie Folgendes verwenden:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Um Kernel-Erweiterungen zu laden und zu entladen, führen Sie folgende Schritte aus:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** ist ein entscheidender Bestandteil des IOKit-Frameworks in macOS und iOS, das als Datenbank zur Darstellung der Hardwarekonfiguration und des Zustands des Systems dient. Es handelt sich um eine **hierarchische Sammlung von Objekten, die alle auf dem System geladenen Hardware und Treiber** sowie deren Beziehungen zueinander repräsentieren.

Sie können die IORegistry mithilfe der Befehlszeilenschnittstelle **`ioreg`** abrufen, um sie von der Konsole aus zu inspizieren (besonders nützlich für iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Sie können **`IORegistryExplorer`** von den **Zusätzlichen Tools von Xcode** von [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) herunterladen und die **macOS IORegistry** über eine **grafische** Benutzeroberfläche inspizieren.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer werden "planes" verwendet, um die Beziehungen zwischen verschiedenen Objekten in der IORegistry zu organisieren und anzuzeigen. Jeder Plane repräsentiert eine bestimmte Art von Beziehung oder eine bestimmte Ansicht der Hardware- und Treiberkonfiguration des Systems. Hier sind einige der häufigen Planes, die Sie in IORegistryExplorer finden können:

1. **IOService Plane**: Dies ist der allgemeinste Plane, der die Service-Objekte darstellt, die Treiber und Nubs (Kommunikationskanäle zwischen Treibern) repräsentieren. Es zeigt die Provider-Client-Beziehungen zwischen diesen Objekten an.
2. **IODeviceTree Plane**: Dieser Plane repräsentiert die physischen Verbindungen zwischen Geräten, wie sie mit dem System verbunden sind. Er wird oft verwendet, um die Hierarchie der über Busse wie USB oder PCI verbundenen Geräte zu visualisieren.
3. **IOPower Plane**: Zeigt Objekte und ihre Beziehungen in Bezug auf das Energiemanagement an. Es kann anzeigen, welche Objekte den Energiezustand anderer Objekte beeinflussen, was bei der Fehlerbehebung von energiebezogenen Problemen hilfreich ist.
4. **IOUSB Plane**: Speziell auf USB-Geräte und ihre Beziehungen fokussiert, zeigt die Hierarchie von USB-Hubs und angeschlossenen Geräten an.
5. **IOAudio Plane**: Dieser Plane dient zur Darstellung von Audiogeräten und deren Beziehungen im System.
6. ...

## Beispielcode für Treiberkommunikation

Der folgende Code stellt eine Verbindung zum IOKit-Dienst `"IhrServiceNameHier"` her und ruft die Funktion im Selector 0 auf. Dafür:

* ruft er zuerst **`IOServiceMatching`** und **`IOServiceGetMatchingServices`** auf, um den Dienst zu erhalten.
* Er stellt dann eine Verbindung her, indem er **`IOServiceOpen`** aufruft.
* Und schließlich ruft er eine Funktion mit **`IOConnectCallScalarMethod`** auf und gibt den Selector 0 an (der Selector ist die Nummer, die der Funktion zugewiesen ist, die Sie aufrufen möchten).
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

Sie könnten diese zum Beispiel aus einem [**Firmware-Image (ipsw)**](./#ipsw) erhalten. Laden Sie es dann in Ihren bevorzugten Decompiler.

Sie könnten damit beginnen, die Funktion **`externalMethod`** zu dekompilieren, da dies die Treiberfunktion ist, die den Aufruf empfängt und die richtige Funktion aufruft:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Dieser schreckliche Aufruf bedeutet:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Beachten Sie, wie in der vorherigen Definition der Parameter **`self`** fehlt. Die korrekte Definition wäre:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Tatsächlich finden Sie die eigentliche Definition unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mit diesen Informationen können Sie Ctrl+Rechts -> `Funktions-Signatur bearbeiten` umschreiben und die bekannten Typen festlegen:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Der neue dekompilierte Code sieht wie folgt aus:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Für den nächsten Schritt müssen wir die **`IOExternalMethodDispatch2022`** Struktur definiert haben. Sie ist Open Source unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) verfügbar, Sie können sie definieren:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Nun können Sie nach `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` viele Daten sehen:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Ändern Sie den Datentyp in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

nach der Änderung:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

Und wie wir jetzt wissen, haben wir dort ein **Array mit 7 Elementen** (überprüfen Sie den endgültigen dekompilierten Code), klicken Sie, um ein Array mit 7 Elementen zu erstellen:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Nachdem das Array erstellt wurde, können Sie alle exportierten Funktionen sehen:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Wenn Sie sich erinnern, um eine **exportierte** Funktion aus dem Benutzerraum aufzurufen, müssen Sie nicht den Namen der Funktion aufrufen, sondern die **Selektornummer**. Hier sehen Sie, dass der Selektor **0** die Funktion **`initializeDecoder`** ist, der Selektor **1** ist **`startDecoder`**, der Selektor **2** **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the official [**PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
