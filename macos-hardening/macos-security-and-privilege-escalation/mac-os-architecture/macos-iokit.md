# macOS IOKit

<details>

<summary><strong>Μάθε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεσαι σε μια **εταιρεία κυβερνοασφάλειας**; Θέλεις να δεις την **εταιρεία σου να διαφημίζεται στο HackTricks**; Ή θέλεις πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσεις το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΥΝΔΡΟΜΗΣΤΙΚΑ ΠΛΑΝΑ**](https://github.com/sponsors/carlospolop)!
* Ανακάλυψε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), την αποκλειστική μας συλλογή [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο swag του PEASS και του HackTricks**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) **ομάδα Discord** ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε με** στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Μοιραστείτε τα κόλπα σας για το χάκινγκ, στέλνοντας PR στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Βασικές Πληροφορίες

Το I/O Kit είναι ένα ανοιχτού κώδικα, αντικειμενοστραφές **πλαίσιο οδηγών συσκευών** στον πυρήνα XNU, χειρίζεται **δυναμικά φορτωμένους οδηγούς συσκευών**. Επιτρέπει την προσθήκη αρθρωτού κώδικα στον πυρήνα κατά τη διάρκεια της εκτέλεσης, υποστηρίζοντας διάφορο υλικό.

Οι οδηγοί IOKit βασικά **εξάγουν συναρτήσεις από τον πυρήνα**. Οι τύποι παραμέτρων αυτών των συναρτήσεων είναι **προκαθορισμένοι** και επαληθεύονται. Επιπλέον, παρόμοια με το XPC, το IOKit είναι απλώς ένα ακόμα επίπεδο πάνω από τα μηνύματα Mach.

Ο κώδικας του **IOKit XNU πυρήνα** είναι ανοιχτού κώδικα από την Apple στο [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Επιπλέον, οι συστατικές χώρου χρήστη του IOKit είναι επίσης ανοιχτού κώδικα [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ωστόσο, **κανένας οδηγός IOKit** δεν είναι ανοιχτού κώδικα. Παρ' όλα αυτά, κατά καιρούς μια έκδοση ενός οδηγού μπορεί να περιέχει σύμβολα που διευκολύνουν την αποσφαλμάτωσή του. Ελέγξτε πώς να [**πάρετε τις επεκτάσεις οδηγού από το firmware εδώ**](./#ipsw)**.**

Είναι γραμμένο σε **C++**. Μπορείτε να πάρετε αποδιαιρεμένα σύμβολα C++ με:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Οι **εκθέσεις συναρτήσεων** του IOKit μπορούν να πραγματοποιήσουν **επιπλέον ελέγχους ασφαλείας** όταν ένας πελάτης προσπαθεί να καλέσει μια συνάρτηση, αλλά να σημειωθεί ότι οι εφαρμογές είναι συνήθως **περιορισμένες** από το **sandbox** με το οποίο το IOKit μπορεί να αλληλεπιδράσει.
{% endhint %}

## Οδηγοί

Στο macOS βρίσκονται στα:

* **`/System/Library/Extensions`**
* Αρχεία KEXT που έχουν ενσωματωθεί στο λειτουργικό σύστημα OS X.
* **`/Library/Extensions`**
* Αρχεία KEXT που έχουν εγκατασταθεί από λογισμικό τρίτων

Στο iOS βρίσκονται στα:

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Μέχρι τον αριθμό 9, οι αναφερόμενοι οδηγοί φορτώνονται στη διεύθυνση 0. Αυτό σημαίνει ότι αυτοί δεν είναι πραγματικοί οδηγοί αλλά μέρος του πυρήνα και δεν μπορούν να απενεργοποιηθούν.

Για να βρείτε συγκεκριμένες επεκτάσεις, μπορείτε να χρησιμοποιήσετε:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Για να φορτώσετε και να απενεργοποιήσετε επεκτάσεις πυρήνα, κάντε τα εξής:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Το **IORegistry** είναι ένας κρίσιμος μέρος του πλαισίου IOKit στο macOS και το iOS, το οποίο λειτουργεί ως μια βάση δεδομένων για την αναπαράσταση της υπαρξιακής διάταξης και κατάστασης του υλικού του συστήματος. Είναι μια **ιεραρχική συλλογή αντικειμένων που αναπαριστούν όλο το υλικό και τους προγραμματιστές που φορτώνονται στο σύστημα** και τις σχέσεις τους μεταξύ τους.&#x20;

Μπορείτε να αποκτήσετε το IORegistry χρησιμοποιώντας το εργαλείο γραμμής εντολών **`ioreg`** για να το επιθεωρήσετε από την κονσόλα (ιδιαίτερα χρήσιμο για το iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Μπορείτε να κατεβάσετε το **`IORegistryExplorer`** από τα **Επιπλέον Εργαλεία του Xcode** από το [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) και να επιθεωρήσετε το **macOS IORegistry** μέσω μιας **γραφικής** διεπαφής.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

Στο IORegistryExplorer, τα "planes" χρησιμοποιούνται για να οργανώσουν και να εμφανίσουν τις σχέσεις μεταξύ διάφορων αντικειμένων στο IORegistry του macOS. Κάθε plane αντιπροσωπεύει ένα συγκεκριμένο τύπο σχέσης ή μια συγκεκριμένη προβολή της υλικής σύνθεσης και της διαμόρφωσης των οδηγών του συστήματος. Παρακάτω παρουσιάζονται μερικά από τα κοινά planes που μπορείτε να συναντήσετε στο IORegistryExplorer:

1. **IOService Plane**: Αυτό είναι το πιο γενικό plane, που εμφανίζει τα αντικείμενα υπηρεσίας που αντιπροσωπεύουν οδηγούς και nubs (κανάλια επικοινωνίας μεταξύ των οδηγών). Εμφανίζει τις σχέσεις παροχέα-πελάτη μεταξύ αυτών των αντικειμένων.
2. **IODeviceTree Plane**: Αυτό το plane αναπαριστά τις φυσικές συνδέσεις μεταξύ συσκευών καθώς είναι συνδεδεμένες στο σύστημα. Χρησιμοποιείται συχνά για να οπτικοποιήσει την ιεραρχία των συσκευών που συνδέονται μέσω διαύλων όπως USB ή PCI.
3. **IOPower Plane**: Εμφανίζει αντικείμενα και τις σχέσεις τους σε σχέση με τη διαχείριση ισχύος. Μπορεί να εμφανίσει ποια αντικείμενα επηρεάζουν την κατάσταση ισχύος άλλων, χρήσιμο για την αντιμετώπιση προβλημάτων που σχετίζονται με την ισχύ.
4. **IOUSB Plane**: Εστιάζει ειδικά σε συσκευές USB και τις σχέσεις τους, εμφανίζοντας την ιεραρχία των USB hubs και των συνδεδεμένων συσκευών.
5. **IOAudio Plane**: Αυτό το plane χρησιμοποιείται για την αναπαράσταση συσκευών ήχου και των σχέσεών τους εντός του συστήματος.
6. ...

## Παράδειγμα Κώδικα Επικοινωνίας Οδηγού

Ο παρακάτω κώδικας συνδέεται με την υπηρεσία IOKit `"YourServiceNameHere"` και καλεί τη συνάρτηση μέσα στον επιλογέα 0. Για να το κάνετε:

* πρώτα καλεί την **`IOServiceMatching`** και την **`IOServiceGetMatchingServices`** για να λάβει την υπηρεσία.
* Στη συνέχεια, εγκαθιστά μια σύνδεση καλώντας την **`IOServiceOpen`**.
* Και τέλος καλεί μια συνάρτηση με την **`IOConnectCallScalarMethod`** δηλώνοντας τον επιλογέα 0 (ο επιλογέας είναι ο αριθμός που έχει ανατεθεί στη συνάρτηση που θέλετε να καλέσετε).
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
Υπάρχουν **άλλες** λειτουργίες που μπορούν να χρησιμοποιηθούν για να καλέσουν τις λειτουργίες του IOKit εκτός από τη **`IOConnectCallScalarMethod`** όπως η **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Ανάκτηση του σημείου εισόδου του προγράμματος οδήγησης (driver entrypoint)

Μπορείτε να αποκτήσετε αυτές, για παράδειγμα, από μια [**εικόνα firmware (ipsw)**](./#ipsw). Στη συνέχεια, φορτώστε την στον αγαπημένο σας αποκωδικοποιητή.

Μπορείτε να ξεκινήσετε την αποκωδικοποίηση της συνάρτησης **`externalMethod`** καθώς αυτή είναι η συνάρτηση του προγράμματος οδήγησης που θα λαμβάνει την κλήση και θα καλεί τη σωστή συνάρτηση:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Αυτή η αποκωδικοποίηση της κλήσης σημαίνει:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Παρατηρήστε ότι στον προηγούμενο ορισμό λείπει η παράμετρος **`self`**, ο σωστός ορισμός θα ήταν:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Πραγματικά, μπορείτε να βρείτε τον πραγματικό ορισμό στο [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Με αυτές τις πληροφορίες μπορείτε να ξαναγράψετε το Ctrl+Right -> `Επεξεργασία υπογραφής συνάρτησης` και να ορίσετε τους γνωστούς τύπους:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Ο νέος αποκωδικοποιημένος κώδικας θα φαίνεται όπως παρακάτω:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Για το επόμενο βήμα, πρέπει να έχουμε ορίσει τη δομή **`IOExternalMethodDispatch2022`**. Είναι ανοικτού κώδικα στο [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), μπορείτε να την ορίσετε:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Τώρα, ακολουθώντας το `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` μπορείτε να δείτε πολλά δεδομένα:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Αλλάξτε τον τύπο δεδομένων σε **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

μετά την αλλαγή:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

Και τώρα μπορούμε να δημιουργήσουμε έναν πίνακα με 7 στοιχεία:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Αφού δημιουργηθεί ο πίνακας, μπορείτε να δείτε όλες τις εξαγόμενες συναρτήσεις:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Αν θυμάστε, για να **καλέσετε** μια **εξαγόμενη** συνάρτηση από τον χώρο χρήστη, δεν χρειάζεται να καλέσετε το όνομα της συνάρτησης, αλλά τον **αριθμό επιλογής**. Εδώ μπορείτε να δείτε ότι ο αριθμός επιλογής **0** είναι η συνάρτηση **`initializeDecoder`**, ο αριθμός επιλογής **1** είναι η **`startDecoder`**, ο αριθμός επιλογής **2** είναι η **`initializeEncoder`**...
{% endhint %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΥΝΔΡΟΜΗΣΤΙΚΑ ΠΑΚΕΤΑ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), την αποκλειστική μας συλλογή [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο swag του PEASS και του HackTricks**](https://peass.creator-spring.com)
* **Συμμετάσχετε στην** [**💬**](https://emojipedia.org/speech-balloon/) **ομάδα Discord** ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε με** στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Μοιραστείτε τα κόλπα σας για το hacking στέλνοντας PR στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
