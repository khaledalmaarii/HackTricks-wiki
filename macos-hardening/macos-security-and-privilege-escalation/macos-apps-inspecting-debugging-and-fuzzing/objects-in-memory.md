# Αντικείμενα στη μνήμη

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}

## CFRuntimeClass

Τα αντικείμενα CF\* προέρχονται από το CoreFOundation, το οποίο παρέχει περισσότερες από 50 κλάσεις αντικειμένων όπως `CFString`, `CFNumber` ή `CFAllocatior`.

Όλες αυτές οι κλάσεις είναι παραδείγματα της κλάσης `CFRuntimeClass`, η οποία όταν καλείται επιστρέφει ένα δείκτη στον πίνακα `__CFRuntimeClassTable`. Η CFRuntimeClass ορίζεται στο [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Χρησιμοποιούμενες ενότητες μνήμης

Τα περισσότερα δεδομένα που χρησιμοποιούνται από το runtime του ObjectiveC θα αλλάξουν κατά τη διάρκεια της εκτέλεσης, γι' αυτό χρησιμοποιεί ορισμένες ενότητες από το τμήμα **\_\_DATA** στη μνήμη:

* **`__objc_msgrefs`** (`message_ref_t`): Αναφορές μηνυμάτων
* **`__objc_ivar`** (`ivar`): Μεταβλητές ιδιότητας
* **`__objc_data`** (`...`): Μεταβλητά δεδομένα
* **`__objc_classrefs`** (`Class`): Αναφορές κλάσεων
* **`__objc_superrefs`** (`Class`): Αναφορές υπερκλάσεων
* **`__objc_protorefs`** (`protocol_t *`): Αναφορές πρωτοκόλλων
* **`__objc_selrefs`** (`SEL`): Αναφορές επιλογέα
* **`__objc_const`** (`...`): Δεδομένα κλάσης `r/o` και άλλα (ελπίζουμε) σταθερά δεδομένα
* **`__objc_imageinfo`** (`version, flags`): Χρησιμοποιείται κατά τη φόρτωση της εικόνας: Η έκδοση είναι προς το παρόν `0`; Τα σημαία καθορίζουν την προεπιλεγμένη υποστήριξη GC, κλπ.
* **`__objc_protolist`** (`protocol_t *`): Λίστα πρωτοκόλλων
* **`__objc_nlcatlist`** (`category_t`): Δείκτης σε μη-τεμπέλιες κατηγορίες που έχουν οριστεί σε αυτό το δυαδικό
* **`__objc_catlist`**** (`category_t`): Δείκτης σε κατηγορίες που έχουν οριστεί σε αυτό το δυαδικό
* **`__objc_nlclslist`** (`classref_t`): Δείκτης σε μη-τεμπέλιες κλάσεις Objective-C που έχουν οριστεί σε αυτό το δυαδικό
* **`__objc_classlist`** (`classref_t`): Δείκτες σε όλες τις κλάσεις Objective-C που έχουν οριστεί σε αυτό το δυαδικό

Χρησιμοποιεί επίσης μερικές ενότητες στο τμήμα **`__TEXT`** για να αποθηκεύσει σταθερές τιμές που δεν είναι δυνατό να γραφτούν σε αυτή την ενότητα:

* **`__objc_methname`** (C-String): Ονόματα μεθόδων
* **`__objc_classname`** (C-String): Ονόματα κλάσεων
* **`__objc_methtype`** (C-String): Τύποι μεθόδων

### Κωδικοποίηση Τύπου

Το Objective-C χρησιμοποιεί κάποια μετατροπή για να κωδικοποιήσει τους τύπους επιλογέα και μεταβλητών απλών και πολύπλοκων τύπων:

* Οι πρωτογενείς τύποι χρησιμοποιούν τον πρώτο χαρακτήρα του τύπου, όπως `i` για `int`, `c` για `char`, `l` για `long`... και χρησιμοποιεί το κεφαλαίο γράμμα σε περίπτωση που είναι unsigned (`L` για `unsigned Long`).
* Άλλοι τύποι δεδομένων οι οποίοι χρησιμοποιούνται ή είναι ειδικοί, χρησιμοποιούν άλλους χαρακτήρες ή σύμβολα όπως `q` για `long long`, `b` για `bitfields`, `B` για `booleans`, `#` για `classes`, `@` για `id`, `*` για `char pointers`, `^` για γενικούς `pointers` και `?` για `undefined`.
* Οι πίνακες, δομές και ένωση χρησιμοποιούν `[`, `{` και `(`

#### Δήλωση Παραδείγματος Μεθόδου

{% code overflow="wrap" %}
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
{% endcode %}

Ο επιλογέας θα ήταν `processString:withOptions:andError:`

#### Κωδικοποίηση Τύπου

* Το `id` κωδικοποιείται ως `@`
* Το `char *` κωδικοποιείται ως `*`

Η πλήρης κωδικοποίηση τύπου για τη μέθοδο είναι:
```less
@24@0:8@16*20^@24
```
#### Αναλυτική Ανάλυση

1. **Τύπος Επιστροφής (`NSString *`)**: Κωδικοποιείται ως `@` με μήκος 24
2. **`self` (παράδειγμα αντικειμένου)**: Κωδικοποιείται ως `@`, στη θέση 0
3. **`_cmd` (επιλογέας)**: Κωδικοποιείται ως `:`, στη θέση 8
4. **Πρώτο όρισμα (`char * input`)**: Κωδικοποιείται ως `*`, στη θέση 16
5. **Δεύτερο όρισμα (`NSDictionary * options`)**: Κωδικοποιείται ως `@`, στη θέση 20
6. **Τρίτο όρισμα (`NSError ** error`)**: Κωδικοποιείται ως `^@`, στη θέση 24

**Με τον επιλογέα + την κωδικοποίηση μπορείτε να ανακατασκευάσετε τη μέθοδο.**

### **Κλάσεις**

Οι κλάσεις στο Objective-C είναι μια δομή με ιδιότητες, δείκτες μεθόδων... Είναι δυνατόν να βρείτε τη δομή `objc_class` στο [**κώδικα πηγής**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Αυτή η κλάση χρησιμοποιεί μερικά bits του πεδίου isa για να υποδείξει πληροφορίες σχετικά με την κλάση.

Στη συνέχεια, η δομή έχει ένα δείκτη προς τη δομή `class_ro_t` που αποθηκεύεται στο δίσκο και περιέχει χαρακτηριστικά της κλάσης όπως το όνομά της, τις βασικές μεθόδους, τις ιδιότητες και τις μεταβλητές της παρουσίας.\
Κατά τη διάρκεια της εκτέλεσης, μια επιπλέον δομή `class_rw_t` χρησιμοποιείται περιέχοντας δείκτες που μπορούν να τροποποιηθούν, όπως μεθόδους, πρωτόκολλα, ιδιότητες...
