# Παράκαμψη του Sandbox του macOS Office

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

### Παράκαμψη του Sandbox του Word μέσω των Launch Agents

Η εφαρμογή χρησιμοποιεί ένα **προσαρμοσμένο Sandbox** χρησιμοποιώντας το entitlement **`com.apple.security.temporary-exception.sbpl`** και αυτό το προσαρμοσμένο sandbox επιτρέπει την εγγραφή αρχείων οπουδήποτε, όσο το όνομα του αρχείου ξεκινά με `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Επομένως, η παράκαμψη ήταν τόσο εύκολη όσο το **γράψιμο ενός `plist`** LaunchAgent στο `~/Library/LaunchAgents/~$escape.plist`.

Ελέγξτε την [**αρχική αναφορά εδώ**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Παράκαμψη του Sandbox του Word μέσω των Login Items και του zip

Θυμηθείτε ότι από την πρώτη παράκαμψη, το Word μπορεί να γράψει αυθαίρετα αρχεία των οποίων το όνομα ξεκινά με `~$`, αν και μετά την επιδιόρθωση της προηγούμενης ευπάθειας δεν ήταν δυνατή η εγγραφή στο `/Library/Application Scripts` ή στο `/Library/LaunchAgents`.

Ανακαλύφθηκε ότι από το εσωτερικό του sandbox είναι δυνατή η δημιουργία ενός **Login Item** (εφαρμογές που θα εκτελούνται όταν ο χρήστης συνδέεται). Ωστόσο, αυτές οι εφαρμογές **δεν θα εκτελεστούν εκτός αν** είναι **υπογεγραμμένες** και δεν είναι δυνατή η προσθήκη ορισμένων παραμέτρων (οπότε δεν μπορείτε απλά να εκτελέσετε ένα αντίστροφο κέλυφος χρησιμοποιώντας το **`bash`**).

Από την προηγούμενη παράκαμψη του Sandbox, η Microsoft απενεργοποίησε τη δυνατότητα εγγραφής αρχείων στο `~/Library/LaunchAgents`. Ωστόσο, ανακαλύφθηκε ότι εάν τοποθετήσετε ένα **αρχείο zip ως Login Item**, το `Archive Utility` θα το αποσυμπιέσει στην τρέχουσα τοποθεσία του. Έτσι, επειδή από προεπιλογή ο φάκελος `LaunchAgents` από το `~/Library` δεν δημιουργείται, ήταν δυνατό να **συμπιέσετε ένα plist στο `LaunchAgents/~$escape.plist`** και να τοποθετήσετε το αρχείο zip στο **`~/Library`** έτσι ώστε όταν αποσυμπιέσετε να φτάσει στον προορισμό της μόνιμης αποθήκευσης.

Ελέγξτε την [**αρχική αναφορά εδώ**](https://objective-see.org/blog/blog\_0x4B.html).

### Παράκαμψη του Sandbox του Word μέσω των Login Items και του .zshenv

(Θυμηθείτε ότι από την πρώτη παράκαμψη, το Word μπορεί να γράψει αυθαίρετα αρχεία των οποίων το όνομα ξεκινά με `~$`).

Ωστόσο, η προηγούμενη τεχνική είχε μια περιορισμένη λειτουργία,
