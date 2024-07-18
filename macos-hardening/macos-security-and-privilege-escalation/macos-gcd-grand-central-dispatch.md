# macOS GCD - Grand Central Dispatch

{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## Podstawowe informacje

**Grand Central Dispatch (GCD)**, znany również jako **libdispatch** (`libdispatch.dyld`), jest dostępny zarówno w macOS, jak i iOS. Jest to technologia opracowana przez Apple, która optymalizuje obsługę aplikacji dla równoczesnego (wielowątkowego) wykonywania na sprzęcie wielordzeniowym.

**GCD** dostarcza i zarządza **kolejkami FIFO**, do których twoja aplikacja może **przesyłać zadania** w postaci **bloków kodu**. Bloki przesłane do kolejek dystrybucji są **wykonywane na puli wątków** w pełni zarządzanej przez system. GCD automatycznie tworzy wątki do wykonywania zadań w kolejkach dystrybucji i harmonogramuje te zadania do uruchomienia na dostępnych rdzeniach.

{% hint style="success" %}
Podsumowując, aby wykonać kod **równolegle**, procesy mogą wysyłać **bloki kodu do GCD**, który zajmie się ich wykonaniem. Dlatego procesy nie tworzą nowych wątków; **GCD wykonuje dany kod za pomocą własnej puli wątków** (która może się zwiększać lub zmniejszać w miarę potrzeby).
{% endhint %}

Jest to bardzo pomocne do skutecznego zarządzania równoczesnym wykonywaniem, znacznie zmniejszając liczbę wątków, które tworzą procesy, i optymalizując równoczesne wykonanie. Jest to idealne rozwiązanie dla zadań wymagających **dużej równoległości** (brute-forcing?) lub dla zadań, które nie powinny blokować głównego wątku: na przykład główny wątek w iOS obsługuje interakcje z interfejsem użytkownika, więc wszelkie inne funkcje, które mogą spowodować zawieszenie aplikacji (wyszukiwanie, dostęp do sieci, odczyt pliku...) są obsługiwane w ten sposób.

### Bloki

Blokiem jest **samodzielny fragment kodu** (podobny do funkcji z argumentami zwracającymi wartość) i może również określić zmienne związane.\
Jednak na poziomie kompilatora bloki nie istnieją, są to `os_object`s. Każdy z tych obiektów składa się z dwóch struktur:

* **blok literałowy**:&#x20;
* Rozpoczyna się od pola **`isa`**, wskazującego na klasę bloku:
* `NSConcreteGlobalBlock` (bloki z `__DATA.__const`)
* `NSConcreteMallocBlock` (bloki na stercie)
* `NSConcreateStackBlock` (bloki na stosie)
* Posiada **`flagi`** (wskazujące na pola obecne w deskryptorze bloku) oraz kilka zarezerwowanych bajtów
* Wskaźnik do funkcji do wywołania
* Wskaźnik do deskryptora bloku
* Zaimplementowane zmienne bloku (jeśli takie istnieją)
* **deskryptor bloku**: Jego rozmiar zależy od danych, które są obecne (jak wskazano w poprzednich flagach)
* Posiada kilka zarezerwowanych bajtów
* Jego rozmiar
* Zazwyczaj będzie miał wskaźnik do sygnatury w stylu Objective-C, aby wiedzieć, ile miejsca jest potrzebne na parametry (flaga `BLOCK_HAS_SIGNATURE`)
* Jeśli zmienne są odwoływane, ten blok będzie również miał wskaźniki do pomocnika kopiowania (kopiującego wartość na początku) i pomocnika usuwania (zwalniającego ją).

### Kolejki

Kolejka dystrybucji to nazwany obiekt zapewniający kolejność FIFO bloków do wykonania.

Bloki są umieszczane w kolejkach do wykonania, a te obsługują 2 tryby: `DISPATCH_QUEUE_SERIAL` i `DISPATCH_QUEUE_CONCURRENT`. Oczywiście **kolejka szeregowa** **nie będzie miała problemów z warunkami wyścigowymi**, ponieważ blok nie zostanie wykonany, dopóki poprzedni nie zakończy działania. Ale **inny typ kolejki może je mieć**.

Kolejki domyślne:

* `.main-thread`: Z `dispatch_get_main_queue()`
* `.libdispatch-manager`: Menedżer kolejek GCD
* `.root.libdispatch-manager`: Menedżer kolejek GCD
* `.root.maintenance-qos`: Zadania o najniższym priorytecie
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Dostępne jako `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Najwyższy priorytet
* `.root.background-qos.overcommit`

Zauważ, że to system decyduje, **które wątki obsługują które kolejki w danym momencie** (wiele wątków może pracować w tej samej kolejce lub ten sam wątek może pracować w różnych kolejkach w pewnym momencie)

#### Atrybuty

Podczas tworzenia kolejki za pomocą **`dispatch_queue_create`** trzeci argument to `dispatch_queue_attr_t`, który zazwyczaj jest albo `DISPATCH_QUEUE_SERIAL` (który jest właściwie NULL), albo `DISPATCH_QUEUE_CONCURRENT`, który jest wskaźnikiem do struktury `dispatch_queue_attr_t`, która pozwala kontrolować niektóre parametry kolejki.

### Obiekty dystrybucji

Istnieje kilka obiektów, których używa libdispatch, a kolejki i bloki to tylko 2 z nich. Można tworzyć te obiekty za pomocą `dispatch_object_create`:

* `block`
* `data`: Bloki danych
* `group`: Grupa bloków
* `io`: Asynchroniczne żądania wejścia/wyjścia
* `mach`: Porty Mach
* `mach_msg`: Komunikaty Mach
* `pthread_root_queue`: Kolejka z pulą wątków pthread, a nie kolejkami pracy
* `queue`
* `semaphore`
* `source`: Źródło zdarzeń

## Objective-C

W Objective-C istnieją różne funkcje do wysłania bloku do wykonania równoległego:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Przesyła blok do asynchronicznego wykonania w kolejce dystrybucji i natychmiast zwraca.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Przesyła obiekt bloku do wykonania i zwraca po zakończeniu tego bloku.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Wykonuje blok tylko raz przez cały czas życia aplikacji.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Przesyła element pracy do wykonania i zwraca dopiero po zakończeniu jego wykonania. W przeciwieństwie do [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), ta funkcja respektuje wszystkie atrybuty kolejki podczas wykonywania bloku.

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
I oto przykład użycia **równoległości** z **`dispatch_async`**:
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

**`libswiftDispatch`** to biblioteka zapewniająca **powiązania Swift** do frameworka Grand Central Dispatch (GCD), który jest pierwotnie napisany w języku C.\
Biblioteka **`libswiftDispatch`** owija interfejsy API C GCD w bardziej przyjazny dla języka Swift interfejs, ułatwiając i bardziej intuicyjnie dla programistów Swift pracować z GCD.

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

Obecnie Ghidra nie rozumie ani struktury **`dispatch_block_t`** ObjectiveC, ani **`swift_dispatch_block`**.

Więc jeśli chcesz, aby je zrozumiał, po prostu możesz je **zadeklarować**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Następnie znajdź miejsce w kodzie, gdzie są **używane**:

{% hint style="success" %}
Zauważ wszystkie odniesienia do "block", aby zrozumieć, jak możesz ustalić, że struktura jest używana.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Kliknij prawym przyciskiem na zmienną -> Zmień typ zmiennej i wybierz w tym przypadku **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra automatycznie przepisze wszystko:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencje

* [**\*OS Internals, Tom I: Tryb użytkownika. Autor: Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
