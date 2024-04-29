# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandising**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

## Grundlegende Informationen

**Grand Central Dispatch (GCD)**, auch bekannt als **libdispatch** (`libdispatch.dyld`), ist sowohl in macOS als auch in iOS verfügbar. Es handelt sich um eine von Apple entwickelte Technologie zur Optimierung der Anwendungsunterstützung für die gleichzeitige (mehrfädige) Ausführung auf Mehrkern-Hardware.

**GCD** stellt FIFO-Warteschlangen bereit, an die Ihre Anwendung **Aufgaben in Form von Blockobjekten übermitteln** kann. Blöcke, die an Dispatch-Warteschlangen übermittelt werden, werden auf einem vom System vollständig verwalteten Thread-Pool ausgeführt. GCD erstellt automatisch Threads zur Ausführung der Aufgaben in den Dispatch-Warteschlangen und plant diese Aufgaben so, dass sie auf den verfügbaren Kernen ausgeführt werden.

{% hint style="success" %}
Zusammenfassend können Prozesse zur Ausführung von Code **parallel** **Codeblöcke an GCD senden**, die sich um deren Ausführung kümmern. Daher erstellen Prozesse keine neuen Threads; **GCD führt den übergebenen Code mit seinem eigenen Thread-Pool aus** (der bei Bedarf erhöht oder verringert werden kann).
{% endhint %}

Dies ist sehr hilfreich, um die parallele Ausführung erfolgreich zu verwalten, da die Anzahl der Threads, die Prozesse erstellen, erheblich reduziert wird und die parallele Ausführung optimiert wird. Dies ist ideal für Aufgaben, die eine **große Parallelität** erfordern (Brute-Force?) oder für Aufgaben, die den Hauptthread nicht blockieren sollten: Beispielsweise behandelt der Hauptthread auf iOS UI-Interaktionen, sodass alle anderen Funktionen, die die App zum Absturz bringen könnten (Suchen, auf eine Website zugreifen, eine Datei lesen...), auf diese Weise verwaltet werden.

### Blöcke

Ein Block ist ein **in sich geschlossener Abschnitt des Codes** (wie eine Funktion mit Argumenten, die einen Wert zurückgeben) und kann auch gebundene Variablen angeben.\
Auf Compiler-Ebene existieren Blöcke jedoch nicht, sie sind `os_object`s. Jedes dieser Objekte besteht aus zwei Strukturen:

* **Blockliteral**:&#x20;
* Es beginnt mit dem Feld **`isa`**, das auf die Klasse des Blocks zeigt:
* `NSConcreteGlobalBlock` (Blöcke aus `__DATA.__const`)
* `NSConcreteMallocBlock` (Blöcke im Heap)
* `NSConcreateStackBlock` (Blöcke im Stack)
* Es hat **`flags`** (die Felder im Blockbeschreibung anzeigen) und einige reservierte Bytes
* Der Funktionszeiger zum Aufruf
* Ein Zeiger auf die Blockbeschreibung
* Importierte Blockvariablen (falls vorhanden)
* **Blockbeschreibung**: Ihre Größe hängt von den vorhandenen Daten ab (wie in den vorherigen Flags angegeben)
* Es hat einige reservierte Bytes
* Die Größe davon
* Es wird normalerweise einen Zeiger auf eine Objective-C-Style-Signatur haben, um zu wissen, wie viel Platz für die Parameter benötigt wird (Flag `BLOCK_HAS_SIGNATURE`)
* Wenn Variablen referenziert werden, wird dieser Block auch Zeiger auf einen Kopierhelfer (der den Wert am Anfang kopiert) und einen Entsorgungshelfer (der ihn freigibt) haben.

### Warteschlangen

Eine Dispatch-Warteschlange ist ein benanntes Objekt, das die FIFO-Reihenfolge von Blöcken für die Ausführung bereitstellt.

Blöcke werden in Warteschlangen eingestellt, um ausgeführt zu werden, und diese unterstützen 2 Modi: `DISPATCH_QUEUE_SERIAL` und `DISPATCH_QUEUE_CONCURRENT`. Natürlich wird die **serielle** Warteschlange **keine Probleme mit Rennbedingungen haben**, da ein Block erst ausgeführt wird, wenn der vorherige beendet ist. Aber **der andere Typ der Warteschlange könnte es haben**.

Standardwarteschlangen:

* `.main-thread`: Von `dispatch_get_main_queue()`
* `.libdispatch-manager`: GCD-Warteschlangen-Manager
* `.root.libdispatch-manager`: GCD-Warteschlangen-Manager
* `.root.maintenance-qos`: Aufgaben mit niedrigster Priorität
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Höchste Priorität
* `.root.background-qos.overcommit`

Beachten Sie, dass das System entscheidet, **welche Threads welche Warteschlangen zu einem bestimmten Zeitpunkt bearbeiten** (mehrere Threads können in derselben Warteschlange arbeiten oder derselbe Thread kann zu einem bestimmten Zeitpunkt in verschiedenen Warteschlangen arbeiten).

#### Attribute

Beim Erstellen einer Warteschlange mit **`dispatch_queue_create`** ist das dritte Argument ein `dispatch_queue_attr_t`, das normalerweise entweder `DISPATCH_QUEUE_SERIAL` (das tatsächlich NULL ist) oder `DISPATCH_QUEUE_CONCURRENT` ist, was ein Zeiger auf eine `dispatch_queue_attr_t`-Struktur ist, die es ermöglicht, einige Parameter der Warteschlange zu steuern.

### Dispatch-Objekte

Es gibt mehrere Objekte, die libdispatch verwendet, und Warteschlangen und Blöcke sind nur 2 davon. Es ist möglich, diese Objekte mit `dispatch_object_create` zu erstellen:

* `block`
* `data`: Datenblöcke
* `group`: Gruppe von Blöcken
* `io`: Asynchrone I/O-Anforderungen
* `mach`: Mach-Ports
* `mach_msg`: Mach-Nachrichten
* `pthread_root_queue`: Eine Warteschlange mit einem pthread-Thread-Pool und keine Arbeitswarteschlangen
* `queue`
* `semaphore`
* `source`: Ereignisquelle

## Objective-C

In Objective-C gibt es verschiedene Funktionen, um einen Block zur parallelen Ausführung zu senden:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Übermittelt einen Block zur asynchronen Ausführung in einer Dispatch-Warteschlange und kehrt sofort zurück.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Übermittelt ein Blockobjekt zur Ausführung und kehrt zurück, nachdem dieser Block die Ausführung beendet hat.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Führt ein Blockobjekt nur einmal während der Lebensdauer einer Anwendung aus.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Übermittelt ein Arbeitsobjekt zur Ausführung und kehrt erst zurück, nachdem es die Ausführung beendet hat. Im Gegensatz zu [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync) respektiert diese Funktion alle Attribute der Warteschlange, wenn sie den Block ausführt.

Diese Funktionen erwarten diese Parameter: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

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
Und dies ist ein Beispiel zur Verwendung von **Parallelismus** mit **`dispatch_async`**:
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

**`libswiftDispatch`** ist eine Bibliothek, die **Swift-Bindungen** zum Grand Central Dispatch (GCD)-Framework bereitstellt, das ursprünglich in C geschrieben wurde.\
Die Bibliothek **`libswiftDispatch`** kapselt die C GCD-APIs in eine benutzerfreundlichere Schnittstelle für Swift, was es für Swift-Entwickler einfacher und intuitiver macht, mit GCD zu arbeiten.

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

Das folgende Frida-Skript kann verwendet werden, um **sich in mehrere `dispatch`-Funktionen einzuhaken** und den Warteschlangennamen, den Backtrace und den Block zu extrahieren: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Aktuell versteht Ghidra weder die ObjectiveC-Struktur **`dispatch_block_t`** noch die **`swift_dispatch_block`**.

Wenn Sie möchten, dass es sie versteht, könnten Sie sie einfach **deklarieren**:

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Dann finden Sie eine Stelle im Code, wo sie **verwendet** werden:

{% hint style="success" %}
Beachten Sie alle Verweise auf "block", um zu verstehen, wie Sie herausfinden können, dass die Struktur verwendet wird.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Klicken Sie mit der rechten Maustaste auf die Variable -> Variablentyp ändern und wählen Sie in diesem Fall **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra wird automatisch alles neu schreiben:

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenzen

* [**\*OS Internals, Band I: Benutzermodus. Von Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
