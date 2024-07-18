# Objekte im Speicher

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## CFRuntimeClass

CF\* Objekte stammen aus CoreFoundation, die mehr als 50 Klassen von Objekten wie `CFString`, `CFNumber` oder `CFAllocatior` bereitstellt.

All diese Klassen sind Instanzen der Klasse `CFRuntimeClass`, die beim Aufruf einen Index zur `__CFRuntimeClassTable` zurückgibt. Die CFRuntimeClass ist in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) definiert:
```objectivec
// Some comments were added to the original code

enum { // Version field constants
_kCFRuntimeScannedObject =     (1UL << 0),
_kCFRuntimeResourcefulObject = (1UL << 2),  // tells CFRuntime to make use of the reclaim field
_kCFRuntimeCustomRefCount =    (1UL << 3),  // tells CFRuntime to make use of the refcount field
_kCFRuntimeRequiresAlignment = (1UL << 4),  // tells CFRuntime to make use of the requiredAlignment field
};

typedef struct __CFRuntimeClass {
CFIndex version;  // This is made a bitwise OR with the relevant previous flags

const char *className; // must be a pure ASCII string, nul-terminated
void (*init)(CFTypeRef cf);  // Initializer function
CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf); // Copy function, taking CFAllocatorRef and CFTypeRef to copy
void (*finalize)(CFTypeRef cf); // Finalizer function
Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2); // Function to be called by CFEqual()
CFHashCode (*hash)(CFTypeRef cf); // Function to be called by CFHash()
CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions); // Provides a CFStringRef with a textual description of the object// return str with retain
CFStringRef (*copyDebugDesc)(CFTypeRef cf);	// CFStringRed with textual description of the object for CFCopyDescription

#define CF_RECLAIM_AVAILABLE 1
void (*reclaim)(CFTypeRef cf); // Or in _kCFRuntimeResourcefulObject in the .version to indicate this field should be used
// It not null, it's called when the last reference to the object is released

#define CF_REFCOUNT_AVAILABLE 1
// If not null, the following is called when incrementing or decrementing reference count
uint32_t (*refcount)(intptr_t op, CFTypeRef cf); // Or in _kCFRuntimeCustomRefCount in the .version to indicate this field should be used
// this field must be non-NULL when _kCFRuntimeCustomRefCount is in the .version field
// - if the callback is passed 1 in 'op' it should increment the 'cf's reference count and return 0
// - if the callback is passed 0 in 'op' it should return the 'cf's reference count, up to 32 bits
// - if the callback is passed -1 in 'op' it should decrement the 'cf's reference count; if it is now zero, 'cf' should be cleaned up and deallocated (the finalize callback above will NOT be called unless the process is running under GC, and CF does not deallocate the memory for you; if running under GC, finalize should do the object tear-down and free the object memory); then return 0
// remember to use saturation arithmetic logic and stop incrementing and decrementing when the ref count hits UINT32_MAX, or you will have a security bug
// remember that reference count incrementing/decrementing must be done thread-safely/atomically
// objects should be created/initialized with a custom ref-count of 1 by the class creation functions
// do not attempt to use any bits within the CFRuntimeBase for your reference count; store that in some additional field in your CF object

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#define CF_REQUIRED_ALIGNMENT_AVAILABLE 1
// If not 0, allocation of object must be on this boundary
uintptr_t requiredAlignment; // Or in _kCFRuntimeRequiresAlignment in the .version field to indicate this field should be used; the allocator to _CFRuntimeCreateInstance() will be ignored in this case; if this is less than the minimum alignment the system supports, you'll get higher alignment; if this is not an alignment the system supports (e.g., most systems will only support powers of two, or if it is too high), the result (consequences) will be up to CF or the system to decide

} CFRuntimeClass;
```
## Objective-C

### Verwendete Speicherbereiche

Die meisten Daten, die vom ObjectiveC-Laufzeitumgebung verwendet werden, ändern sich während der Ausführung, daher verwendet sie einige Abschnitte aus dem **\_\_DATA**-Segment im Speicher:

- **`__objc_msgrefs`** (`message_ref_t`): Nachrichtenreferenzen
- **`__objc_ivar`** (`ivar`): Instanzvariablen
- **`__objc_data`** (`...`): Veränderliche Daten
- **`__objc_classrefs`** (`Class`): Klassenreferenzen
- **`__objc_superrefs`** (`Class`): Superklassenreferenzen
- **`__objc_protorefs`** (`protocol_t *`): Protokollreferenzen
- **`__objc_selrefs`** (`SEL`): Selektorreferenzen
- **`__objc_const`** (`...`): Klassen `r/o`-Daten und andere (hoffentlich) konstante Daten
- **`__objc_imageinfo`** (`version, flags`): Wird während des Bildladens verwendet: Aktuelle Version `0`; Flags spezifizieren voroptimierte GC-Unterstützung, etc.
- **`__objc_protolist`** (`protocol_t *`): Protokollliste
- **`__objc_nlcatlist`** (`category_t`): Zeiger auf in dieser Binärdatei definierte Non-Lazy-Kategorien
- **`__objc_catlist`** (`category_t`): Zeiger auf in dieser Binärdatei definierte Kategorien
- **`__objc_nlclslist`** (`classref_t`): Zeiger auf in dieser Binärdatei definierte Non-Lazy-Objective-C-Klassen
- **`__objc_classlist`** (`classref_t`): Zeiger auf alle in dieser Binärdatei definierten Objective-C-Klassen

Es verwendet auch einige Abschnitte im **`__TEXT`**-Segment, um konstante Werte zu speichern, falls es nicht möglich ist, in diesem Abschnitt zu schreiben:

- **`__objc_methname`** (C-String): Methodennamen
- **`__objc_classname`** (C-String): Klassennamen
- **`__objc_methtype`** (C-String): Methodentypen

### Typkodierung

Objective-C verwendet einige Verfremdungen, um Selektor- und Variablentypen von einfachen und komplexen Typen zu kodieren:

- Primitive Typen verwenden ihren ersten Buchstaben des Typs `i` für `int`, `c` für `char`, `l` für `long`... und verwenden den Großbuchstaben, falls es sich um einen unsigned-Typ handelt (`L` für `unsigned Long`).
- Andere Datentypen, deren Buchstaben verwendet werden oder speziell sind, verwenden andere Buchstaben oder Symbole wie `q` für `long long`, `b` für `Bitfelder`, `B` für `Booleans`, `#` für `Klassen`, `@` für `id`, `*` für `Zeiger auf char`, `^` für generische `Zeiger` und `?` für `undefiniert`.
- Arrays, Strukturen und Unionen verwenden `[`, `{` und `(`

#### Beispiel Methodendeklaration

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

Der Selektor wäre `processString:withOptions:andError:`

#### Typencodierung

* `id` wird als `@` codiert
* `char *` wird als `*` codiert

Die vollständige Typencodierung für die Methode lautet:
```less
@24@0:8@16*20^@24
```
#### Detaillierte Aufschlüsselung

1. **Rückgabetyp (`NSString *`)**: Codiert als `@` mit einer Länge von 24
2. **`self` (Objektinstanz)**: Codiert als `@`, bei Offset 0
3. **`_cmd` (Selektor)**: Codiert als `:`, bei Offset 8
4. **Erstes Argument (`char * input`)**: Codiert als `*`, bei Offset 16
5. **Zweites Argument (`NSDictionary * options`)**: Codiert als `@`, bei Offset 20
6. **Drittes Argument (`NSError ** error`)**: Codiert als `^@`, bei Offset 24

**Mit dem Selektor und der Codierung können Sie die Methode rekonstruieren.**

### **Klassen**

Klassen in Objective-C sind eine Struktur mit Eigenschaften, Methodenzeigern... Es ist möglich, die Struktur `objc_class` im [**Quellcode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) zu finden:
```objectivec
struct objc_class : objc_object {
// Class ISA;
Class superclass;
cache_t cache;             // formerly cache pointer and vtable
class_data_bits_t bits;    // class_rw_t * plus custom rr/alloc flags

class_rw_t *data() {
return bits.data();
}
void setData(class_rw_t *newData) {
bits.setData(newData);
}

void setInfo(uint32_t set) {
assert(isFuture()  ||  isRealized());
data()->setFlags(set);
}
[...]
```
Diese Klasse verwendet einige Bits des isa-Feldes, um Informationen über die Klasse anzuzeigen.

Dann hat die Struktur einen Zeiger auf die auf der Festplatte gespeicherte Struktur `class_ro_t`, die Attribute der Klasse wie ihren Namen, Basismethoden, Eigenschaften und Instanzvariablen enthält.\
Während der Laufzeit wird eine zusätzliche Struktur `class_rw_t` verwendet, die Zeiger enthält, die geändert werden können, wie Methoden, Protokolle, Eigenschaften...
