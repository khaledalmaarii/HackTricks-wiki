<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

# Οδηγός Αποσυναρμολόγησης και Συναρμολόγησης Wasm

Στον κόσμο του **WebAssembly**, τα εργαλεία για την **αποσυναρμολόγηση** και **συναρμολόγηση** είναι απαραίτητα για τους προγραμματιστές. Αυτός ο οδηγός παρουσιάζει μερικούς διαδικτυακούς πόρους και λογισμικά για την επεξεργασία αρχείων **Wasm (WebAssembly binary)** και **Wat (WebAssembly text)**.

## Διαδικτυακά Εργαλεία

- Για την **αποσυναρμολόγηση** του Wasm σε Wat, το εργαλείο που είναι διαθέσιμο στη διεύθυνση [wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) είναι πολύ χρήσιμο.
- Για την **συναρμολόγηση** του Wat πίσω σε Wasm, το [wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) εξυπηρετεί τον σκοπό.
- Μια άλλη επιλογή αποσυναρμολόγησης μπορεί να βρεθεί στο [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Λογισμικά Λύσεις

- Για μια πιο ισχυρή λύση, το [JEB από την PNF Software](https://www.pnfsoftware.com/jeb/demo) προσφέρει εκτεταμένες δυνατότητες.
- Το ανοιχτού κώδικα έργο [wasmdec](https://github.com/wwwg/wasmdec) είναι επίσης διαθέσιμο για αποσυναρμολόγηση.

# Πόροι Αποσυναρμολόγησης .Net

Η αποσυναρμολόγηση των συναρμολογήσεων .Net μπορεί να γίνει με εργαλεία όπως:

- [ILSpy](https://github.com/icsharpcode/ILSpy), το οποίο προσφέρει επίσης ένα [πρόσθετο για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), επιτρέποντας τη χρήση σε πολλές πλατφόρμες.
- Για εργασίες που αφορούν την **αποσυναρμολόγηση**, **τροποποίηση** και **συναρμολόγηση**, συνιστάται ένθετα το [dnSpy](https://github.com/0xd4d/dnSpy/releases). Επιλέγοντας δεξί κλικ σε μια μέθοδο και επιλέγοντας **Τροποποίηση Μεθόδου** επιτρέπει την αλλαγή του κώδικα.
- [dotPeek της JetBrains](https://www.jetbrains.com/es-es/decompiler/) είναι μια άλλη εναλλακτική για την αποσυναρμολόγηση των συναρμολογήσεων .Net.

## Ενισχύοντας την Αποσφαλμάτωση και την Καταγραφή με το DNSpy

### Καταγραφή με το DNSpy
Για να καταγράψετε πληροφορίες σε ένα αρχείο χρησιμοποιώντας το DNSpy, ενσωματώστε το παρακάτω τμήμα κώδικα .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Αποσφαλμάτωση με το DNSpy
Για μια αποτελεσματική αποσφαλμάτωση με το DNSpy, συνιστάται μια ακολουθία βημάτων για την προσαρμογή των **Χαρακτηριστικών Συναρμογής** για την αποσφαλμάτωση, εξασφαλίζοντας ότι οι βελτιστοποιήσεις που μπ
## **Delphi**
- Για τα δυαδικά αρχεία Delphi, συνιστάται η χρήση του [IDR](https://github.com/crypto2011/IDR).


# Μαθήματα

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Αποκωδικοποίηση δυαδικών\)



<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
