# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlegende Informationen

**Grand Central Dispatch (GCD)**, auch bekannt als **libdispatch**, ist sowohl in macOS als auch in iOS verfügbar. Es handelt sich um eine von Apple entwickelte Technologie zur Optimierung der Anwendung für die gleichzeitige (mehrfädige) Ausführung auf Mehrkernhardware.

**GCD** stellt und verwaltet **FIFO-Warteschlangen**, an die Ihre Anwendung **Aufgaben in Form von Blockobjekten** übergeben kann. Die an Dispatch-Warteschlangen übergebenen Blöcke werden auf einem vom System vollständig verwalteten Thread-Pool ausgeführt. GCD erstellt automatisch Threads zur Ausführung der Aufgaben in den Dispatch-Warteschlangen und plant diese Aufgaben zur Ausführung auf den verfügbaren Kernen.

{% hint style="success" %}
Zusammenfassend können Prozesse zur Ausführung von Code **parallel** Blöcke von Code an GCD senden, das sich um deren Ausführung kümmert. Prozesse erstellen also keine neuen Threads; **GCD führt den gegebenen Code mit seinem eigenen Thread-Pool aus**.
{% endhint %}

Dies ist sehr hilfreich, um die parallele Ausführung erfolgreich zu verwalten, da die Anzahl der Threads, die Prozesse erstellen, erheblich reduziert wird und die parallele Ausführung optimiert wird. Dies ist ideal für Aufgaben, die eine **große Parallelität** erfordern (Brute-Force?) oder für Aufgaben, die den Hauptthread nicht blockieren sollten: Zum Beispiel behandelt der Hauptthread in iOS UI-Interaktionen, daher wird jede andere Funktionalität, die die App zum Hängen bringen könnte (Suchen, Zugriff auf das Web, Lesen einer Datei...), auf diese Weise verwaltet.

## Objective-C

In Objective-C gibt es verschiedene Funktionen, um einen Block zur parallelen Ausführung zu senden:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Sendet einen Block zur asynchronen Ausführung an eine Dispatch-Warteschlange und gibt sofort zurück.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Sendet ein Blockobjekt zur Ausführung und gibt erst zurück, nachdem der Block ausgeführt wurde.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Führt ein Blockobjekt nur einmal während der Lebensdauer einer Anwendung aus.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Sendet ein Arbeitsobjekt zur Ausführung und gibt erst zurück, nachdem es ausgeführt wurde. Im Gegensatz zu [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync) respektiert diese Funktion alle Attribute der Warteschlange bei der Ausführung des Blocks.

Diese Funktionen erwarten folgende Parameter: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Dies ist die **Struktur eines Blocks**:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
Und dies ist ein Beispiel für die Verwendung von **Parallelität** mit **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

Die Bibliothek **`libswiftDispatch`** stellt Swift-Bindungen für das Grand Central Dispatch (GCD)-Framework bereit, das ursprünglich in C geschrieben wurde.\
Die **`libswiftDispatch`**-Bibliothek umhüllt die C GCD APIs in eine benutzerfreundlichere Swift-Schnittstelle, was es Swift-Entwicklern erleichtert, mit GCD zu arbeiten.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Codebeispiel**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

Das folgende Frida-Skript kann verwendet werden, um sich in verschiedene `dispatch`-Funktionen einzuhaken und den Queue-Namen, den Backtrace und den Block zu extrahieren: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Derzeit versteht Ghidra weder die Struktur **`dispatch_block_t`** von ObjectiveC noch die Struktur **`swift_dispatch_block`**.

Wenn Sie möchten, dass Ghidra sie versteht, können Sie sie einfach **deklarieren**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Finden Sie dann eine Stelle im Code, an der sie **verwendet** werden:

{% hint style="success" %}
Beachten Sie alle Verweise auf "block", um herauszufinden, wie Sie die Struktur erkennen können.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Klicken Sie mit der rechten Maustaste auf die Variable -> Retype Variable und wählen Sie in diesem Fall **`swift_dispatch_block`** aus:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra wird automatisch alles umschreiben:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
