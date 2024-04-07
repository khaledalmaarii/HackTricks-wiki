# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

**Grand Central Dispatch (GCD),** znany również jako **libdispatch**, jest dostępny zarówno w macOS, jak i iOS. Jest to technologia opracowana przez Apple do optymalizacji obsługi aplikacji dla równoczesnego (wielowątkowego) wykonywania na sprzęcie wielordzeniowym.

**GCD** dostarcza i zarządza **kolejkami FIFO**, do których twoja aplikacja może **przesyłać zadania** w postaci **bloków kodu**. Bloki przesłane do kolejek dystrybucji są **wykonywane na puli wątków** w pełni zarządzanej przez system. GCD automatycznie tworzy wątki do wykonywania zadań w kolejkach dystrybucji i harmonogramuje te zadania do uruchomienia na dostępnych rdzeniach.

{% hint style="success" %}
Podsumowując, aby wykonać kod **równolegle**, procesy mogą wysyłać **bloki kodu do GCD**, który zajmie się ich wykonaniem. Dlatego procesy nie tworzą nowych wątków; **GCD wykonuje dany kod za pomocą własnej puli wątków**.
{% endhint %}

Jest to bardzo pomocne do skutecznego zarządzania równoczesnym wykonywaniem, znacznie zmniejszając liczbę wątków tworzonych przez procesy i optymalizując równoległe wykonanie. Jest to idealne rozwiązanie dla zadań wymagających **dużej równoległości** (łamanie haseł?) lub dla zadań, które nie powinny blokować głównego wątku: Na przykład główny wątek w iOS obsługuje interakcje z interfejsem użytkownika, więc wszelkie inne funkcjonalności, które mogłyby zawiesić aplikację (wyszukiwanie, dostęp do sieci, odczyt pliku...) są obsługiwane w ten sposób.

## Objective-C

W Objetive-C istnieją różne funkcje do wysyłania bloku do wykonania równolegle:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Przesyła blok do asynchronicznego wykonania w kolejce dystrybucji i natychmiast zwraca.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Przesyła obiekt bloku do wykonania i zwraca po zakończeniu tego bloku.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Wykonuje obiekt bloku tylko raz przez cały czas życia aplikacji.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Przesyła element roboczy do wykonania i zwraca dopiero po zakończeniu jego wykonania. W przeciwieństwie do [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), ta funkcja respektuje wszystkie atrybuty kolejki podczas wykonywania bloku.

Te funkcje oczekują tych parametrów: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Oto **struktura Bloku**:
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
Oto przykład użycia **równoległości** z **`dispatch_async`**:
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

**`libswiftDispatch`** to biblioteka dostarczająca **powiązania Swift** do frameworku Grand Central Dispatch (GCD), który jest pierwotnie napisany w języku C.\
Biblioteka **`libswiftDispatch`** owija interfejsy API C GCD w bardziej przyjazny dla języka Swift sposób, ułatwiając i bardziej intuicyjnie dla programistów Swift pracować z GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Przykład kodu**:
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

Następujący skrypt Frida może być użyty do **hookowania kilku funkcji `dispatch`** i wydobycia nazwy kolejki, śladu stosu i bloku: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Obecnie Ghidra nie rozumie ani struktury **`dispatch_block_t`** w ObjectiveC, ani struktury **`swift_dispatch_block`**.

Jeśli chcesz, aby je zrozumiał, po prostu możesz je **zadeklarować**:

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Następnie znajdź miejsce w kodzie, gdzie są **używane**:

{% hint style="success" %}
Zauważ wszystkie odniesienia do "block", aby zrozumieć, jak można ustalić, że struktura jest używana.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Kliknij prawym przyciskiem na zmienną -> Zmień typ zmiennej i wybierz w tym przypadku **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra automatycznie przepisze wszystko:

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>
