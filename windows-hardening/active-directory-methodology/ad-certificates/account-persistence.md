# AD CS Μόνιμη Παραμονή Λογαριασμού

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτό είναι ένα μικρό σύνολο πληροφοριών από τα κεφάλαια μόνιμης παραμονής της μηχανής από την εκπληκτική έρευνα του [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Κατανόηση Κλοπής Διαπιστευτηρίων Ενεργού Χρήστη με Πιστοποιητικά - PERSIST1**

Σε ένα σενάριο όπου ένα πιστοποιητικό που επιτρέπει την πιστοποίηση του τομέα μπορεί να ζητηθεί από έναν χρήστη, ένας επιτιθέμενος έχει την ευκαιρία να **ζητήσει** και **κλέψει** αυτό το πιστοποιητικό για να **διατηρήσει τη μόνιμη παρουσία** σε ένα δίκτυο. Από προεπιλογή, το πρότυπο `User` στο Active Directory επιτρέπει τέτοια αιτήματα, αν και μερικές φορές μπορεί να είναι απενεργοποιημένο.

Χρησιμοποιώντας ένα εργαλείο με το όνομα [**Certify**](https://github.com/GhostPack/Certify), μπορεί κανείς να αναζητήσει έγκυρα πιστοποιητικά που επιτρέπουν μόνιμη πρόσβαση:
```bash
Certify.exe find /clientauth
```
Είναι επισημασμένο ότι η δύναμη ενός πιστοποιητικού βρίσκεται στην ικανότητά του να **πιστοποιηθεί ως ο χρήστης** στον οποίο ανήκει, ανεξάρτητα από οποιεσδήποτε αλλαγές κωδικού πρόσβασης, εφόσον το πιστοποιητικό παραμένει **έγκυρο**.

Τα πιστοποιητικά μπορούν να ζητηθούν μέσω γραφικού περιβάλλοντος χρησιμοποιώντας το `certmgr.msc` ή μέσω της γραμμής εντολών με τη χρήση του `certreq.exe`. Με το **Certify**, η διαδικασία για την αίτηση ενός πιστοποιητικού απλοποιείται ως εξής:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Μετά από μια επιτυχημένη αίτηση, δημιουργείται ένα πιστοποιητικό μαζί με το ιδιωτικό του κλειδί σε μορφή `.pem`. Για να μετατραπεί αυτό σε ένα αρχείο `.pfx`, το οποίο μπορεί να χρησιμοποιηθεί σε συστήματα Windows, χρησιμοποιείται η παρακάτω εντολή:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Το αρχείο `.pfx` μπορεί να ανέβει σε ένα σύστημα-στόχο και να χρησιμοποιηθεί με ένα εργαλείο που ονομάζεται [**Rubeus**](https://github.com/GhostPack/Rubeus) για να ζητηθεί ένα Ticket Granting Ticket (TGT) για τον χρήστη, επεκτείνοντας την πρόσβαση του επιτιθέμενου για όσο διάστημα είναι **έγκυρο** το πιστοποιητικό (συνήθως ένα έτος):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Μια σημαντική προειδοποίηση κοινοποιείται σχετικά με το πώς αυτή η τεχνική, σε συνδυασμό με μια άλλη μέθοδο που περιγράφεται στην ενότητα **THEFT5**, επιτρέπει σε έναν επιτιθέμενο να αποκτήσει με αντοχή το **NTLM hash** ενός λογαριασμού χωρίς να αλληλεπιδρά με την υπηρεσία Local Security Authority Subsystem (LSASS) και από ένα μη ανυψωμένο περιβάλλον, παρέχοντας έτσι μια πιο αόρατη μέθοδο για μακροπρόθεσμη κλοπή διαπιστευτηρίων.

## **Απόκτηση Μόνιμης Επιμονής στο Μηχάνημα με Πιστοποιητικά - PERSIST2**

Μια άλλη μέθοδος περιλαμβάνει την εγγραφή του λογαριασμού μηχανής ενός παραβιασμένου συστήματος για ένα πιστοποιητικό, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `Machine` που επιτρέπει τέτοιες ενέργειες. Αν ένας επιτιθέμενος αποκτήσει ανυψωμένα προνόμια σε ένα σύστημα, μπορεί να χρησιμοποιήσει τον λογαριασμό **SYSTEM** για να ζητήσει πιστοποιητικά, παρέχοντας έτσι μια μορφή **επιμονής**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Αυτή η πρόσβαση επιτρέπει στον επιτιθέμενο να πιστοποιηθεί στο **Kerberos** ως λογαριασμός της μηχανής και να χρησιμοποιήσει το **S4U2Self** για να λάβει εισιτήρια υπηρεσίας Kerberos για οποιαδήποτε υπηρεσία στον υπολογιστή, παρέχοντας αποτελεσματική μόνιμη πρόσβαση στη μηχανή.

## **Επέκταση της Διατήρησης μέσω της Ανανέωσης Πιστοποιητικών - PERSIST3**

Η τελική μέθοδος που συζητείται εμπλέκει την αξιοποίηση της **ισχύος** και των **περιόδων ανανέωσης** των προτύπων πιστοποιητικών. Με την **ανανέωση** ενός πιστοποιητικού πριν από τη λήξη του, ένας επιτιθέμενος μπορεί να διατηρήσει την πιστοποίησή του στο Active Directory χωρίς την ανάγκη για επιπλέον εγγραφές εισιτηρίων, οι οποίες θα μπορούσαν να αφήσουν ίχνη στον διακομιστή Αρχής Πιστοποίησης (CA).

Αυτή η προσέγγιση επιτρέπει μια **επεκτεινόμενη διατήρηση**, μειώνοντας τον κίνδυνο ανίχνευσης μέσω λιγότερων αλληλεπιδράσεων με τον διακομιστή CA και αποφεύγοντας τη δημιουργία αρχείων που θα μπορούσαν να ειδοποιήσουν τους διαχειριστές για την παραβίαση.

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
