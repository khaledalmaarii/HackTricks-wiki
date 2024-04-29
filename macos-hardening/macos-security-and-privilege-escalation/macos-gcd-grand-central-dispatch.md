# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

**Grand Central Dispatch (GCD),** takođe poznat kao **libdispatch** (`libdispatch.dyld`), dostupan je i na macOS-u i iOS-u. To je tehnologija koju je razvio Apple kako bi optimizovao podršku aplikacija za konkurentno (višenitno) izvršavanje na višejezgarnom hardveru.

**GCD** obezbeđuje i upravlja **FIFO redovima** u koje vaša aplikacija može **podneti zadatke** u obliku **blok objekata**. Blokovi podneti na dispečerske redove se **izvršavaju na poolu niti** potpuno upravljanim od strane sistema. GCD automatski kreira niti za izvršavanje zadataka u dispečerskim redovima i raspoređuje te zadatke da se izvrše na dostupnim jezgrima.

{% hint style="success" %}
U suštini, da bi se izvršio kod **paralelno**, procesi mogu poslati **blokove koda GCD-u**, koji će se pobrinuti za njihovo izvršavanje. Dakle, procesi ne stvaraju nove niti; **GCD izvršava dati kod sa svojim poolom niti** (koji se može povećati ili smanjiti po potrebi).
{% endhint %}

Ovo je veoma korisno za uspešno upravljanje paralelnim izvršavanjem, značajno smanjujući broj niti koje procesi kreiraju i optimizujući paralelno izvršavanje. Ovo je idealno za zadatke koji zahtevaju **veliku paralelnost** (bruteforcing?) ili za zadatke koji ne bi trebali blokirati glavnu nit: Na primer, glavna nit na iOS-u upravlja interakcijama sa korisničkim interfejsom, pa se na ovaj način upravlja svaka druga funkcionalnost koja bi mogla da zamrzne aplikaciju (pretraga, pristup vebu, čitanje fajla...).

### Blokovi

Blok je **samo-sadržani deo koda** (kao funkcija sa argumentima koji vraćaju vrednost) i može takođe specificirati vezane promenljive.\
Međutim, na nivou kompajlera blokovi ne postoje, oni su `os_object`-i. Svaki od ovih objekata se sastoji od dve strukture:

* **blok literal**:&#x20;
* Počinje sa poljem **`isa`**, koje pokazuje na klasu bloka:
* `NSConcreteGlobalBlock` (blokovi iz `__DATA.__const`)
* `NSConcreteMallocBlock` (blokovi u hipu)
* `NSConcreateStackBlock` (blokovi na steku)
* Ima **`flags`** (koji ukazuju na polja prisutna u deskriptoru bloka) i nekoliko rezervisanih bajtova
* Pokazivač na funkciju za poziv
* Pokazivač na deskriptor bloka
* Uvezeni blokovi promenljivih (ako ih ima)
* **deskriptor bloka**: Njegova veličina zavisi od podataka koji su prisutni (kako je naznačeno u prethodnim zastavicama)
* Ima nekoliko rezervisanih bajtova
* Veličina
* Obično će imati pokazivač na potpis u stilu Objective-C da bi se znalo koliko prostora je potrebno za parametre (zastava `BLOCK_HAS_SIGNATURE`)
* Ako se referišu promenljive, ovaj blok će takođe imati pokazivače na pomoćnika za kopiranje (kopiranje vrednosti na početku) i pomoćnika za oslobađanje (oslobađanje).

### Redovi

Dispečerski red je nazivani objekat koji obezbeđuje FIFO redosled blokova za izvršavanje.

Blokovi se postavljaju u redove da bi se izvršili, i oni podržavaju 2 moda: `DISPATCH_QUEUE_SERIAL` i `DISPATCH_QUEUE_CONCURRENT`. Naravno, **serijski** neće imati probleme sa trkom za stanjem jer blok neće biti izvršen dok prethodni ne završi. Ali **drugi tip reda može imati**.

Podrazumevani redovi:

* `.main-thread`: Iz `dispatch_get_main_queue()`
* `.libdispatch-manager`: Menadžer redova GCD-a
* `.root.libdispatch-manager`: Menadžer redova GCD-a
* `.root.maintenance-qos`: Zadaci najniže prioriteta
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Najviši prioritet
* `.root.background-qos.overcommit`

Primetite da će sistem odlučiti **koje niti rukuju kojim redovima u svakom trenutku** (više niti može raditi u istom redu ili ista nit može raditi u različitim redovima u nekom trenutku)

#### Atributi

Prilikom kreiranja reda sa **`dispatch_queue_create`** treći argument je `dispatch_queue_attr_t`, koji obično može biti ili `DISPATCH_QUEUE_SERIAL` (što je zapravo NULL) ili `DISPATCH_QUEUE_CONCURRENT` koji je pokazivač na strukturu `dispatch_queue_attr_t` koja omogućava kontrolu nekih parametara reda.

### Dispečerski objekti

Postoji nekoliko objekata koje libdispatch koristi i redovi i blokovi su samo 2 od njih. Moguće je kreirati ove objekte sa `dispatch_object_create`:

* `blok`
* `data`: Blokovi podataka
* `grupa`: Grupa blokova
* `io`: Asinhroni I/O zahtevi
* `mach`: Mach portovi
* `mach_msg`: Mach poruke
* `pthread_root_queue`: Red sa pthread baziranim bazenom niti i ne radnim redovima
* `red`
* `semafor`
* `izvor`: Izvor događaja

## Objective-C

U Objective-C-u postoje različite funkcije za slanje bloka da se izvrši paralelno:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Podnosi blok za asinhrono izvršavanje na dispečerski red i odmah se vraća.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Podnosi blok objekat za izvršavanje i vraća se nakon što se taj blok završi sa izvršavanjem.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Izvršava blok objekat samo jednom za vreme trajanja aplikacije.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Podnosi radnu stavku za izvršavanje i vraća se tek nakon što se završi izvršavanje. Za razliku od [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), ova funkcija poštuje sve atribute reda kada izvršava blok.

Ove funkcije očekuju ove parametre: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Ovo je **struktura Bloka**:
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
I ovo je primer korišćenja **paralelizma** sa **`dispatch_async`**:
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

**`libswiftDispatch`** je biblioteka koja pruža **Swift veze** sa Grand Central Dispatch (GCD) okvirom koji je originalno napisan u C jeziku.\
Biblioteka **`libswiftDispatch`** omotava C GCD API-je u interfejs koji je prijateljskiji za Swift, čineći ga lakšim i intuitivnijim za Swift programere koji rade sa GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Primer koda**:
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

Sledeći Frida skript može se koristiti za **povezivanje na nekoliko `dispatch`** funkcija i izvlačenje imena reda, steka poziva i bloka: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Trenutno Ghidra ne razume ni strukturu ObjectiveC **`dispatch_block_t`**, ni **`swift_dispatch_block`**.

Dakle, ako želite da ih razume, jednostavno ih možete **deklarisati**:

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Zatim pronađite mesto u kodu gde se oni **koriste**:

{% hint style="success" %}
Zabeležite sve reference na "block" kako biste razumeli kako možete utvrditi da se struktura koristi.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Desni klik na promenljivu -> Promeni tip promenljive i izaberite u ovom slučaju **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra će automatski prepraviti sve:

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
