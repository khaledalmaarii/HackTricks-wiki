# Bellek içindeki nesneler

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşarak PR'ler göndererek [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## CFRuntimeClass

CF\* nesneleri CoreFoundation'dan gelir ve `CFString`, `CFNumber` veya `CFAllocatior` gibi 50'den fazla nesne sınıfı sağlar.

Tüm bu sınıflar, `CFRuntimeClass` sınıfının örnekleridir ve çağrıldığında `__CFRuntimeClassTable`'a bir dizin döndürür. CFRuntimeClass, [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html)'de tanımlanmıştır.
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

### Kullanılan Bellek Bölümleri

ObjectiveC çalışma zamanı tarafından kullanılan verilerin çoğu yürütme sırasında değişeceğinden, bellekte **\_\_DATA** segmentinden bazı bölümleri kullanır:

- **`__objc_msgrefs`** (`message_ref_t`): Mesaj referansları
- **`__objc_ivar`** (`ivar`): Örnek değişkenler
- **`__objc_data`** (`...`): Değiştirilebilir veri
- **`__objc_classrefs`** (`Class`): Sınıf referansları
- **`__objc_superrefs`** (`Class`): Üst sınıf referansları
- **`__objc_protorefs`** (`protocol_t *`): Protokol referansları
- **`__objc_selrefs`** (`SEL`): Seçici referansları
- **`__objc_const`** (`...`): Sınıf `r/o` verileri ve diğer (umuyoruz ki) sabit veriler
- **`__objc_imageinfo`** (`version, flags`): Görüntü yükleme sırasında kullanılır: Şu anda `0` sürüm; Bayraklar önoptimize edilmiş GC desteğini belirtir, vb.
- **`__objc_protolist`** (`protocol_t *`): Protokol listesi
- **`__objc_nlcatlist`** (`category_t`): Bu ikili dosyada tanımlanan Tembel Olmayan Kategorilere işaretçi
- **`__objc_catlist`**** (`category_t`): Bu ikili dosyada tanımlanan Kategorilere işaretçi
- **`__objc_nlclslist`** (`classref_t`): Bu ikili dosyada tanımlanan Tembel Olmayan Objective-C sınıflarına işaretçi
- **`__objc_classlist`** (`classref_t`): Bu ikili dosyada tanımlanan tüm Objective-C sınıflarına işaretçiler

Ayrıca, sabit değerleri saklamak için **`__TEXT`** segmentinde birkaç bölüm daha kullanır:

- **`__objc_methname`** (C-String): Yöntem adları
- **`__objc_classname`** (C-String): Sınıf adları
- **`__objc_methtype`** (C-String): Yöntem tipleri

### Tür Kodlaması

Objective-C, basit ve karmaşık tiplerin seçici ve değişken tiplerini kodlamak için bazı karıştırma kullanır:

- İlkel tipler, tipin ilk harfini kullanır `i` için `int`, `c` için `char`, `l` için `long`... ve büyük harf kullanır işaretli ise (`L` için `unsigned Long`).
- Diğer veri tipleri, harfleri kullanılan veya özel olanlar, diğer harfler veya semboller kullanır, örneğin `q` için `long long`, `b` için `bit alanları`, `B` için `booleanlar`, `#` için `sınıflar`, `@` için `id`, `*` için `char işaretçileri`, `^` için genel `işaretçiler` ve `?` için `tanımsız`.
- Diziler, yapılar ve birlikler `[`, `{` ve `(` kullanır

#### Örnek Yöntem Bildirimi

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

Seçici `processString:withOptions:andError:` olacaktır.

#### Tür Kodlaması

* `id` `@` olarak kodlanır
* `char *` `*` olarak kodlanır

Yöntemin tam tür kodlaması:
```less
@24@0:8@16*20^@24
```
#### Detaylı Açıklama

1. **Dönüş Türü (`NSString *`)**: `@` olarak kodlanmış, uzunluğu 24
2. **`self` (nesne örneği)**: `@` olarak kodlanmış, ofset 0'da
3. **`_cmd` (seçici)**: `:` olarak kodlanmış, ofset 8'de
4. **İlk argüman (`char * input`)**: `*` olarak kodlanmış, ofset 16'da
5. **İkinci argüman (`NSDictionary * options`)**: `@` olarak kodlanmış, ofset 20'de
6. **Üçüncü argüman (`NSError ** error`)**: `^@` olarak kodlanmış, ofset 24'te

**Seçici + kodlama ile yöntemi yeniden oluşturabilirsiniz.**

### **Sınıflar**

Objective-C'deki sınıflar, özellikler, yöntem işaretçileri olan bir yapıdır. `objc_class` yapısını [**kaynak kodunda**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) bulmak mümkündür:
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
Bu sınıf, sınıf hakkında bazı bilgileri göstermek için isa alanının bazı bitlerini kullanır.

Daha sonra, struct, sınıfın adını, temel yöntemleri, özellikleri ve örnek değişkenleri gibi sınıfın özelliklerini içeren diske kaydedilmiş `class_ro_t` yapısına bir işaretçi içerir.\
Çalışma zamanında, değiştirilebilen yöntemler, protokoller, özellikler gibi işaretçiler içeren ek bir yapı olan `class_rw_t` kullanılır...
