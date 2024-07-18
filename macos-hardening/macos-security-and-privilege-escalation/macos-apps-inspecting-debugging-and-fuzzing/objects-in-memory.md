# मेमोरी में ऑब्जेक्ट्स

{% hint style="success" %}
AWS हैकिंग सीखें और प्रैक्टिस करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और प्रैक्टिस करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम ग्रुप**](https://t.me/peass) और **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर हमें **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
{% endhint %}

## CFRuntimeClass

CF\* ऑब्जेक्ट्स कोर फाउंडेशन से आते हैं, जो `CFString`, `CFNumber` या `CFAllocatior` जैसे 50 से अधिक ऑब्जेक्ट्स की कक्षाएँ प्रदान करता है।

ये सभी कक्षाएँ `CFRuntimeClass` के उदाहरण हैं, जो जब कॉल किया जाता है तो यह `__CFRuntimeClassTable` के लिए एक सूची लौटाता है। CFRuntimeClass [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) में परिभाषित है:
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

### उद्देश्य-सी

### उपयोग किए जाने वाले मेमोरी खंड

ObjectiveC रनटाइम द्वारा उपयोग किए जाने वाले अधिकांश डेटा क्रियान्वयन के दौरान बदल जाएगा, इसलिए यह मेमोरी में **\_\_DATA** सेगमेंट से कुछ खंडों का उपयोग करता है:

* **`__objc_msgrefs`** (`message_ref_t`): संदेश संदर्भ
* **`__objc_ivar`** (`ivar`): इंस्टेंस वेरिएबल्स
* **`__objc_data`** (`...`): म्यूटेबल डेटा
* **`__objc_classrefs`** (`Class`): क्लास संदर्भ
* **`__objc_superrefs`** (`Class`): सुपरक्लास संदर्भ
* **`__objc_protorefs`** (`protocol_t *`): प्रोटोकॉल संदर्भ
* **`__objc_selrefs`** (`SEL`): सेलेक्टर संदर्भ
* **`__objc_const`** (`...`): क्लास `r/o` डेटा और अन्य (आशा है) स्थिर डेटा
* **`__objc_imageinfo`** (`version, flags`): छवि लोड के दौरान उपयोग किया जाता है: संस्करण वर्तमान में `0`; ध्वज पूर्व-अनुकूलित जीसी समर्थन इत्यादि निर्दिष्ट करते हैं।
* **`__objc_protolist`** (`protocol_t *`): प्रोटोकॉल सूची
* **`__objc_nlcatlist`** (`category_t`): इस बाइनरी में परिभाषित गुणसूची न आलसी श्रेणियों के पॉइंटर
* **`__objc_catlist`** (`category_t`): इस बाइनरी में परिभाषित श्रेणियों के पॉइंटर
* **`__objc_nlclslist`** (`classref_t`): इस बाइनरी में परिभाषित गुणसूची न आलसी Objective-C क्लास के पॉइंटर
* **`__objc_classlist`** (`classref_t`): इस बाइनरी में परिभाषित सभी Objective-C क्लास के पॉइंटर

यह इसके संदर्भ में कुछ खंडों का उपयोग करता है **`__TEXT`** सेगमेंट में स्थिर मानों को संग्रहित करने के लिए जिन्हें इस खंड में लिखना संभव नहीं है:

* **`__objc_methname`** (सी-स्ट्रिंग): मेथड नाम
* **`__objc_classname`** (सी-स्ट्रिंग): क्लास नाम
* **`__objc_methtype`** (सी-स्ट्रिंग): मेथड प्रकार

### प्रकार एन्कोडिंग

Objective-C उपयोग करता है कुछ मैंग्लिंग कोड सेलेक्टर और चर प्रकारों को सरल और जटिल प्रकारों के लिए एन्कोड करने के लिए:

* मौलिक प्रकार अपने प्रकार का पहला अक्षर उपयोग करते हैं `i` इंट के लिए, `c` चार के लिए, `l` लॉन्ग के लिए... और उसका उपयोग करते हैं यदि यह असाइन्ड है (`L` असाइन्ड लॉन्ग के लिए)।
* अन्य डेटा प्रकार जिनके अक्षर उपयोग किए जाते हैं या विशेष हैं, वे अन्य अक्षर या प्रतीक जैसे `q` लॉन्ग लॉन्ग के लिए, `b` बिटफील्ड्स के लिए, `B` बूलियन्स के लिए, `#` क्लासेस के लिए, `@` आईडी के लिए, `*` चार पॉइंटर्स के लिए, `^` सामान्य पॉइंटर्स के लिए और `?` अनिर्धारित के लिए।
* एरे, संरचनाएँ और संघ उपयोग करते हैं `[`, `{` और `(`

#### उदाहरण मेथड घोषणा

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

चयनकर्ता `processString:withOptions:andError:` होगा

#### प्रकार एन्कोडिंग

* `id` को `@` के रूप में एन्कोड किया जाता है
* `char *` को `*` के रूप में एन्कोड किया जाता है

इस मेथड के लिए पूर्ण प्रकार एन्कोडिंग है:
```less
@24@0:8@16*20^@24
```
#### विस्तृत विश्लेषण

1. **रिटर्न प्रकार (`NSString *`)**: `@` के रूप में एन्कोड किया गया है, जिसकी लंबाई 24 है
2. **`self` (ऑब्जेक्ट इंस्टेंस)**: `@` के रूप में एन्कोड किया गया है, ऑफसेट 0 पर
3. **`_cmd` (सेलेक्टर)**: `:` के रूप में एन्कोड किया गया है, ऑफसेट 8 पर
4. **पहला तर्क (`char * input`)**: `*` के रूप में एन्कोड किया गया है, ऑफसेट 16 पर
5. **दूसरा तर्क (`NSDictionary * options`)**: `@` के रूप में एन्कोड किया गया है, ऑफसेट 20 पर
6. **तीसरा तर्क (`NSError ** error`)**: `^@` के रूप में एन्कोड किया गया है, ऑफसेट 24 पर

**सेलेक्टर + एन्कोडिंग के साथ आप विधि को पुनर्निर्माण कर सकते हैं।**

### **कक्षाएँ**

Objective-C में कक्षाएँ एक संरचना है जिसमें गुण, विधि प्वाइंटर... होते हैं। आप [**स्रोत कोड**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) में `objc_class` संरचना खोजना संभव है:
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
यह कक्षा इस्सा फील्ड के कुछ बिट्स का उपयोग करती है ताकि कक्षा के बारे में कुछ जानकारी को सूचित कर सके।

फिर, स्ट्रक्ट में डिस्क पर स्टोर किए गए स्ट्रक्ट `class_ro_t` के लिए एक पॉइंटर होता है जिसमें कक्षा के नाम, बेस मेथड्स, गुण और इंस्टेंस वेरिएबल्स जैसी विशेषताएं होती हैं।\
रनटाइम के दौरान और एक्सट्रा स्ट्रक्चर `class_rw_t` का उपयोग किया जाता है जिसमें पॉइंटर्स होते हैं जो बदले जा सकते हैं जैसे कि मेथड्स, प्रोटोकॉल्स, गुण।...
