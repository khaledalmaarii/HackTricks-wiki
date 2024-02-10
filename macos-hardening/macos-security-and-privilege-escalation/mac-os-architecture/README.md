# Πυρήνας και Επεκτάσεις Συστήματος του macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πυρήνας XNU

Ο **πυρήνας του macOS είναι ο XNU**, που σημαίνει "X is Not Unix". Αυτός ο πυρήνας αποτελείται ουσιαστικά από τον **μικροπυρήνα Mach** (που θα συζητηθεί αργότερα), **και** στοιχεία από την Berkeley Software Distribution (**BSD**). Ο XNU παρέχει επίσης μια πλατφόρμα για **οδηγούς πυρήνα μέσω ενός συστήματος που ονομάζεται I/O Kit**. Ο πυρήνας XNU είναι μέρος του ανοιχτού πηγαίου κώδικα του έργου Darwin, πράγμα που σημαίνει ότι **ο πηγαίος κώδικας του είναι ελεύθερα προσβάσιμος**.

Από την οπτική γωνία ενός ερευνητή ασφαλείας ή ενός προγραμματιστή Unix, το **macOS** μπορεί να φαίνεται αρκετά **παρόμοιο** με ένα σύστημα **FreeBSD** με μια κομψή γραφική διεπαφή χρήστη και μια σειρά προσαρμοσμένων εφαρμογών. Οι περισσότερες εφαρμογές που έχουν αναπτυχθεί για το BSD θα μεταγλωττιστούν και θα εκτελεστούν στο macOS χωρίς να χρειάζονται τροποποιήσεις, καθώς τα εργαλεία γραμμής εντολών που είναι γνωστά στους χρήστες Unix είναι όλα παρόντα στο macOS. Ωστόσο, επειδή ο πυρήνας XNU ενσωματώνει το Mach, υπάρχουν ορισμένες σημαντικές διαφορές μεταξύ ενός παραδοσιακού συστήματος Unix και του macOS, και αυτές οι διαφορές μπορεί να προκαλέσουν προβλήματα ή να παρέχουν μοναδικά πλεονεκτήματα.

Πηγαίος κώδικας του XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Ο Mach είναι ένας **μικροπυρήνας** που σχεδιάστηκε να είναι **συμβατός με το UNIX**. Ένα από τα βασικά αρχέτυπα σχεδίασής του ήταν να **ελαχιστοποιήσει** τον αριθμό των **κώδικα** που εκτελείται στον **χώρο του πυρήνα** και αντ' αυτού να επιτρέπει σε πολλές τυπικές λειτουργίες του πυρήνα, όπως το σύστημα αρχείων, η δικτύωση και η είσοδος/έξοδος, να **εκτελούνται ως εργασίες σε επίπεδο χρήστη**.

Στο XNU, ο Mach είναι **υπεύθυνος για πολλές από τις κρίσιμες λειτουργίες χαμηλού επιπέδου** που συνήθως χειρίζεται ένας πυρήνας, όπως ο προγραμματισμός του επεξεργαστή, ο πολυεργασιακός χειρισμός και η διαχείριση της εικονικής μνήμης.

### BSD

Ο πυρήνας XNU **ενσωματώνει επίσης** μια σημαντική ποσότητα κώδικα που προέρχεται από το έργο **FreeBSD**. Αυτός ο κώδικας **εκτελείται ως μέρος του πυρήνα μαζί με το Mach**, στον ίδιο χώρο διευθύνσεων. Ωστόσο, ο κώδικας του FreeBSD μέσα στο XNU μπορεί να διαφέρει σημαντικά από τον αρχικό κώδικα του FreeBSD επειδή έγιναν τροποποιήσεις για να
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Σύμβολα του Kernelcache

Ορισμένες φορές η Apple κυκλοφορεί το **kernelcache** με **σύμβολα**. Μπορείτε να κατεβάσετε ορισμένα firmwares με σύμβολα ακολουθώντας τους συνδέσμους στην ιστοσελίδα [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Αυτά είναι τα Apple **firmwares** που μπορείτε να κατεβάσετε από την ιστοσελίδα [**https://ipsw.me/**](https://ipsw.me/). Μεταξύ άλλων αρχείων, θα περιέχει το **kernelcache**.\
Για να **εξαγάγετε** τα αρχεία, απλά μπορείτε να το αποσυμπιέσετε.

Αφού αποσυμπιέσετε το firmware, θα λάβετε ένα αρχείο όπως: **`kernelcache.release.iphone14`**. Είναι σε μορφή **IMG4**, μπορείτε να εξάγετε τις ενδιαφέρουσες πληροφορίες με:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Μπορείτε να ελέγξετε τον εξαγόμενο πυρήνα για σύμβολα με: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Με αυτό τώρα μπορούμε να **εξάγουμε όλες τις επεκτάσεις** ή την **επέκταση που σας ενδιαφέρει:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Επεκτάσεις πυρήνα macOS

Το macOS είναι **υπερβολικά περιοριστικό στο να φορτώσει επεκτάσεις πυρήνα** (.kext) λόγω των υψηλών προνομιακών δικαιωμάτων που θα εκτελεστεί ο κώδικας. Πράγματι, από προεπιλογή είναι σχεδόν αδύνατο (εκτός αν βρεθεί κάποια παράκαμψη).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Επεκτάσεις συστήματος macOS

Αντί να χρησιμοποιεί επεκτάσεις πυρήνα, το macOS δημιούργησε τις επεκτάσεις συστήματος, οι οποίες προσφέρουν στο επίπεδο χρήστη διεπαφές προγραμματισμού εφαρμογών (APIs) για την αλληλεπίδραση με τον πυρήνα. Με αυτόν τον τρόπο, οι προγραμματιστές μπορούν να αποφύγουν τη χρήση επεκτάσεων πυρήνα.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Αναφορές

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
