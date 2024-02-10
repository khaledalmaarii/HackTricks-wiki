# macOS Apple Scripts

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Apple Scripts

Είναι μια γλώσσα σεναρίων που χρησιμοποιείται για την αυτοματοποίηση εργασιών **αλληλεπίδρασης με απομακρυσμένες διεργασίες**. Καθιστά αρκετά εύκολο να **ζητήσετε από άλλες διεργασίες να εκτελέσουν κάποιες ενέργειες**. Το **κακόβουλο λογισμικό** μπορεί να καταχραστεί αυτές τις λειτουργίες για να καταχραστεί τις λειτουργίες που εξάγονται από άλλες διεργασίες.\
Για παράδειγμα, ένα κακόβουλο λογισμικό μπορεί να **ενθέσει αυθαίρετο κώδικα JS σε ανοιχτές σελίδες περιήγησης**. Ή να **κάνει αυτόματα κλικ** σε κάποιες άδειες που ζητούνται από τον χρήστη.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Εδώ έχετε μερικά παραδείγματα: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Βρείτε περισσότερες πληροφορίες σχετικά με κακόβουλο λογισμικό που χρησιμοποιεί AppleScripts [**εδώ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Τα Apple scripts μπορούν εύκολα να "**μεταγλωττιστούν**". Αυτές οι εκδόσεις μπορούν εύκολα να "**απομεταγλωττιστούν**" με τη χρήση της εντολής `osadecompile`.

Ωστόσο, αυτά τα scripts μπορούν επίσης να εξαχθούν ως "**Μόνο για ανάγνωση**" (μέσω της επιλογής "Εξαγωγή..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Ωστόσο, υπάρχουν ακόμα μερικά εργαλεία που μπορούν να χρησιμοποιηθούν για να κατανοήσουν αυτού του είδους τα εκτελέσιμα, [**διαβάστε αυτή την έρευνα για περισσότερες πληροφορίες**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Το εργαλείο [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) με το [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) θα είναι πολύ χρήσιμο για να κατανοήσετε πώς λειτουργεί το σενάριο.

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
