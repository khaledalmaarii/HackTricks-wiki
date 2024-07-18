# Об'єкти в пам'яті

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Школа взлому AWS для Червоної Команди (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Школа взлому GCP для Червоної Команди (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## CFRuntimeClass

Об'єкти CF\* походять від CoreFOundation, яка надає понад 50 класів об'єктів, таких як `CFString`, `CFNumber` або `CFAllocatior`.

Усі ці класи є екземплярами класу `CFRuntimeClass`, який, коли викликається, повертає індекс до `__CFRuntimeClassTable`. CFRuntimeClass визначений у [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Використані секції пам'яті

Більшість даних, які використовується в роботі ObjectiveC runtime, будуть змінюватися під час виконання, тому вони використовують деякі секції з сегмента **\_\_DATA** в пам'яті:

* **`__objc_msgrefs`** (`message_ref_t`): Посилання на повідомлення
* **`__objc_ivar`** (`ivar`): Змінні екземпляра
* **`__objc_data`** (`...`): Змінні дані
* **`__objc_classrefs`** (`Class`): Посилання на класи
* **`__objc_superrefs`** (`Class`): Посилання на суперкласи
* **`__objc_protorefs`** (`protocol_t *`): Посилання на протоколи
* **`__objc_selrefs`** (`SEL`): Посилання на селектори
* **`__objc_const`** (`...`): Дані класу `r/o` та інші (сподіваємося) постійні дані
* **`__objc_imageinfo`** (`version, flags`): Використовується під час завантаження зображення: Поточна версія `0`; Прапорці вказують на підтримку попередньо оптимізованого GC тощо.
* **`__objc_protolist`** (`protocol_t *`): Список протоколів
* **`__objc_nlcatlist`** (`category_t`): Вказівник на Non-Lazy категорії, визначені в цьому бінарному файлі
* **`__objc_catlist`**** (`category_t`): Вказівник на категорії, визначені в цьому бінарному файлі
* **`__objc_nlclslist`** (`classref_t`): Вказівник на Non-Lazy класи Objective-C, визначені в цьому бінарному файлі
* **`__objc_classlist`** (`classref_t`): Вказівники на всі класи Objective-C, визначені в цьому бінарному файлі

Також використовує деякі секції в сегменті **`__TEXT`** для зберігання постійних значень, якщо неможливо записати в цій секції:

* **`__objc_methname`** (C-String): Назви методів
* **`__objc_classname`** (C-String): Назви класів
* **`__objc_methtype`** (C-String): Типи методів

### Кодування типів

Objective-C використовує деяке замаскування для кодування селекторів та типів змінних простих і складних типів:

* Примітивні типи використовують першу літеру типу `i` для `int`, `c` для `char`, `l` для `long`... і використовують велику літеру у випадку беззнакового типу (`L` для `unsigned Long`).
* Інші типи даних, чиї літери вже використовуються або є спеціальними, використовують інші літери або символи, наприклад `q` для `long long`, `b` для `бітових полів`, `B` для `булевих значень`, `#` для `класів`, `@` для `id`, `*` для `вказівників на char`, `^` для загальних `вказівників` та `?` для `невизначеного`.
* Масиви, структури та об'єднання використовують `[`, `{` та `(`

#### Приклад оголошення методу

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

Селектор буде `processString:withOptions:andError:`

#### Кодування типу

* `id` кодується як `@`
* `char *` кодується як `*`

Повне кодування типу для методу:
```less
@24@0:8@16*20^@24
```
#### Детальний розбір

1. **Тип повернення (`NSString *`)**: Закодований як `@` з довжиною 24
2. **`self` (екземпляр об'єкта)**: Закодований як `@`, на зміщенні 0
3. **`_cmd` (селектор)**: Закодований як `:`, на зміщенні 8
4. **Перший аргумент (`char * input`)**: Закодований як `*`, на зміщенні 16
5. **Другий аргумент (`NSDictionary * options`)**: Закодований як `@`, на зміщенні 20
6. **Третій аргумент (`NSError ** error`)**: Закодований як `^@`, на зміщенні 24

**З селектором + кодуванням можна відновити метод.**

### **Класи**

Класи в Objective-C - це структура з властивостями, вказівниками на методи... Можна знайти структуру `objc_class` в [**вихідному коді**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Цей клас використовує деякі біти поля isa для вказівки деякої інформації про клас.

Потім структура має вказівник на структуру `class_ro_t`, збережену на диску, яка містить атрибути класу, такі як його ім'я, базові методи, властивості та змінні екземпляра.\
Під час виконання використовується додаткова структура `class_rw_t`, яка містить вказівники, які можуть бути змінені, такі як методи, протоколи, властивості...
