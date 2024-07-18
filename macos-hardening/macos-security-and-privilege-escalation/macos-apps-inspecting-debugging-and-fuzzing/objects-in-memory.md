# Vitu kwenye kumbukumbu

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## CFRuntimeClass

Vitu vya CF\* vinatoka kwa CoreFOundation, ambayo hutoa zaidi ya darasa 50 za vitu kama vile `CFString`, `CFNumber` au `CFAllocatior`.

Darasa zote hizi ni mifano ya darasa `CFRuntimeClass`, ambayo ikichukuliwa inarudisha kiashiria kwa `__CFRuntimeClassTable`. CFRuntimeClass imedefiniwa katika [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sehemu za kumbukumbu zinazotumiwa

Kiwango kikubwa cha data inayotumiwa na runtime ya ObjectiveC itabadilika wakati wa utekelezaji, hivyo hutumia baadhi ya sehemu kutoka kwenye sehemu ya **\_\_DATA** kwenye kumbukumbu:

- **`__objc_msgrefs`** (`message_ref_t`): Marejeleo ya ujumbe
- **`__objc_ivar`** (`ivar`): Vipengele vya kielelezo
- **`__objc_data`** (`...`): Data inayoweza kubadilishwa
- **`__objc_classrefs`** (`Class`): Marejeleo ya darasa
- **`__objc_superrefs`** (`Class`): Marejeleo ya darasa la juu
- **`__objc_protorefs`** (`protocol_t *`): Marejeleo ya itifaki
- **`__objc_selrefs`** (`SEL`): Marejeleo ya chaguo
- **`__objc_const`** (`...`): Data ya darasa `r/o` na nyingine (kwa matumaini) data ya kudumu
- **`__objc_imageinfo`** (`version, flags`): Hutumiwa wakati wa kupakia picha: Toleo kwa sasa ni `0`; Bendera hufafanua msaada wa GC ulioandaliwa mapema, n.k.
- **`__objc_protolist`** (`protocol_t *`): Orodha ya itifaki
- **`__objc_nlcatlist`** (`category_t`): Kiashiria kwa Jamii Zisizo za uvivu zilizoelezwa katika faili hii
- **`__objc_catlist`** (`category_t`): Kiashiria kwa Jamii zilizoelezwa katika faili hii
- **`__objc_nlclslist`** (`classref_t`): Kiashiria kwa Darasa za Objective-C Zisizo za uvivu zilizoelezwa katika faili hii
- **`__objc_classlist`** (`classref_t`): Viashiria kwa darasa zote za Objective-C zilizoelezwa katika faili hii

Pia hutumia sehemu chache katika sehemu ya **`__TEXT`** kuhifadhi thamani za kudumu ambazo haiwezekani kuandika kwenye sehemu hii:

- **`__objc_methname`** (C-String): Majina ya mbinu
- **`__objc_classname`** (C-String): Majina ya darasa
- **`__objc_methtype`** (C-String): Aina za mbinu

### Ufichamishaji wa Aina

Objective-C hutumia ufichamishaji fulani kuweka alama aina za chaguo na za pembejeo za aina rahisi na ngumu:

- Aina za msingi hutumia herufi yao ya kwanza ya aina `i` kwa `int`, `c` kwa `char`, `l` kwa `long`... na hutumia herufi kubwa ikiwa ni ishara ya kutokuwa na saini (`L` kwa `unsigned Long`).
- Aina nyingine za data ambazo herufi zake hutumiwa au ni maalum, hutumia herufi au alama nyingine kama `q` kwa `long long`, `b` kwa `bitfields`, `B` kwa `booleans`, `#` kwa `classes`, `@` kwa `id`, `*` kwa `char pointers`, `^` kwa `pointers` za jumla na `?` kwa `isiyojulikana`.
- Vipindi, muundo na muungano hutumia `[`, `{` na `(`

#### Mfano wa Tangazo la Mbinu

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

Mchaguzi ungekuwa `processString:withOptions:andError:`

#### Aina ya Ufichamishi

* `id` imefichamishwa kama `@`
* `char *` imefichamishwa kama `*`

Ufichamishi kamili wa aina kwa njia ni:
```less
@24@0:8@16*20^@24
```
#### Uchambuzi wa Kina

1. **Aina ya Kurudi (`NSString *`)**: Imeandikwa kama `@` na urefu wa 24
2. **`self` (kifaa cha kielezo)**: Imeandikwa kama `@`, kwenye nafasi ya 0
3. **`_cmd` (chaguo)**: Imeandikwa kama `:`, kwenye nafasi ya 8
4. **Hoja ya Kwanza (`char * input`)**: Imeandikwa kama `*`, kwenye nafasi ya 16
5. **Hoja ya Pili (`NSDictionary * options`)**: Imeandikwa kama `@`, kwenye nafasi ya 20
6. **Hoja ya Tatu (`NSError ** error`)**: Imeandikwa kama `^@`, kwenye nafasi ya 24

**Kwa chaguo + uandishi unaweza kujenga upya njia.**

### **Madarasa**

Madarasa katika Objective-C ni muundo wenye mali, pointa za njia... Inawezekana kupata muundo `objc_class` katika [**michocheo**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Darasa hili hutumia baadhi ya bits za uga wa isa kuonyesha taarifa fulani kuhusu darasa hilo.

Kisha, muundo una pointer kwenda kwa muundo `class_ro_t` uliowekwa kwenye diski ambao una sifa za darasa kama jina lake, mbinu za msingi, mali na variables za kesi.\
Wakati wa uendeshaji na muundo wa ziada `class_rw_t` hutumiwa ukiwa na pointers ambazo zinaweza kubadilishwa kama vile mbinu, itifaki, mali...
