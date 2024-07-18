# Voorwerpe in geheue

{% hint style="success" %}
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## CFRuntimeClass

CF\* voorwerpe kom van CoreFOundation, wat meer as 50 klasse van voorwerpe soos `CFString`, `CFNumber` of `CFAllocatior` bied.

Al hierdie klasse is instansies van die klas `CFRuntimeClass`, wat wanneer dit geroep word 'n indeks na die `__CFRuntimeClassTable` teruggee. Die CFRuntimeClass is gedefinieer in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Gebruikte geheue-afdelings

Die meeste van die data wat deur die ObjectiveC-runtime gebruik word, sal tydens die uitvoering verander, daarom gebruik dit sekere afdelings van die **\_\_DATA** segment in die geheue:

- **`__objc_msgrefs`** (`message_ref_t`): Boodskapverwysings
- **`__objc_ivar`** (`ivar`): Instansie-veranderlikes
- **`__objc_data`** (`...`): Veranderlike data
- **`__objc_classrefs`** (`Class`): Klasverwysings
- **`__objc_superrefs`** (`Class`): Superklasverwysings
- **`__objc_protorefs`** (`protocol_t *`): Protokolverwysings
- **`__objc_selrefs`** (`SEL`): Kieserverwysings
- **`__objc_const`** (`...`): Klas `r/o` data en ander (hopelik) konstante data
- **`__objc_imageinfo`** (`weergawe, vlae`): Gebruik tydens beeldlading: Weergawe tans `0`; Vlae spesifiseer vooraf geoptimeerde GC-ondersteuning, ens.
- **`__objc_protolist`** (`protocol_t *`): Protokollys
- **`__objc_nlcatlist`** (`category_t`): Verwysing na Nie-Luie Kategorieë wat in hierdie binêre lê
- **`__objc_catlist`** (`category_t`): Verwysing na Kategorieë wat in hierdie binêre lê
- **`__objc_nlclslist`** (`classref_t`): Verwysing na Nie-Luie Objective-C-klasse wat in hierdie binêre lê
- **`__objc_classlist`** (`classref_t`): Verwysings na alle Objective-C-klasse wat in hierdie binêre lê

Dit gebruik ook 'n paar afdelings in die **`__TEXT`** segment om konstante waardes te stoor as dit nie moontlik is om in hierdie afdeling te skryf nie:

- **`__objc_methname`** (C-String): Metode name
- **`__objc_classname`** (C-String): Klasname
- **`__objc_methtype`** (C-String): Metode tipes

### Tipe-kodering

Objective-C gebruik 'n bietjie verminking om die kieser- en veranderlike tipes van eenvoudige en komplekse tipes te kodeer:

- Primitiewe tipes gebruik hul eerste letter van die tipe `i` vir `int`, `c` vir `char`, `l` vir `long`... en gebruik die hoofletter in die geval dit onderteken is (`L` vir `unsigned Long`).
- Ander datatipes waarvan die letters gebruik word of spesiaal is, gebruik ander letters of simbole soos `q` vir `long long`, `b` vir `bitvelds`, `B` vir `booleans`, `#` vir `klasse`, `@` vir `id`, `*` vir `char-aanwysers`, `^` vir generiese `aanwysers` en `?` vir `onbepaalde`.
- Arrays, strukture en unies gebruik `[`, `{` en `(`

#### Voorbeeld Metodeverklaring

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

Die kieser sal `processString:withOptions:andError:` wees

#### Tipe Enkodering

* `id` word enkodeer as `@`
* `char *` word enkodeer as `*`

Die volledige tipe enkodering vir die metode is:
```less
@24@0:8@16*20^@24
```
#### Gedetailleerde Uiteensetting

1. **Retourtipe (`NSString *`)**: Opgesluit as `@` met lengte 24
2. **`self` (objekinstansie)**: Opgesluit as `@`, by offset 0
3. **`_cmd` (selekteerder)**: Opgesluit as `:`, by offset 8
4. **Eerste argument (`char * input`)**: Opgesluit as `*`, by offset 16
5. **Tweede argument (`NSDictionary * options`)**: Opgesluit as `@`, by offset 20
6. **Derde argument (`NSError ** error`)**: Opgesluit as `^@`, by offset 24

**Met die selekteerder + die enkodering kan jy die metode herkonstrueer.**

### **Klasse**

Klasse in Objective-C is 'n struktuur met eienskappe, metode-aanwysers... Dit is moontlik om die struktuur `objc_class` in die [**bronkode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) te vind:
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
Hierdie klas gebruik 'n paar bietjies van die isa-veld om inligting oor die klas aan te dui.

Dan het die struktuur 'n verwysing na die struktuur `class_ro_t` wat op die skyf gestoor word en eienskappe van die klas bevat soos sy naam, basiese metodes, eienskappe en instansie-veranderlikes.\
Tydens hardlooptyd word 'n bykomende struktuur `class_rw_t` gebruik wat verwysings bevat wat verander kan word soos metodes, protokolle, eienskappe...
