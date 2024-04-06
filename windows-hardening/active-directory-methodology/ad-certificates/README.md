# Πιστοποιητικά AD

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Εισαγωγή

### Συστατικά ενός πιστοποιητικού

- Το **Θέμα** του πιστοποιητικού υποδηλώνει τον ιδιοκτήτη του.
- Ένα **Δημόσιο Κλειδί** συνδέεται με ένα ιδιωτικό κλειδί για να συσχετίσει το πιστοποιητικό με τον νόμιμο ιδιοκτήτη του.
- Η **Περίοδος Ισχύος**, καθορίζεται από τις ημερομηνίες **NotBefore** και **NotAfter**, καθορίζει την αποτελεσματική διάρκεια του πιστοποιητικού.
- Ένας μοναδικός **Σειριακός Αριθμός**, που παρέχεται από την Αρχή Πιστοποίησης (CA), αναγνωρίζει κάθε πιστοποιητικό.
- Ο **Εκδότης** αναφέρεται στην Αρχή Πιστοποίησης που έχει εκδώσει το πιστοποιητικό.
- Το **SubjectAlternativeName** επιτρέπει επιπλέον ονόματα για το θέμα, βελτιώνοντας την ευελιξία της αναγνώρισης.
- Οι **Βασικοί Περιορισμοί** αναγνωρίζουν εάν το πιστοποιητικό είναι για μια Αρχή Πιστοποίησης ή για ένα τελικό στοιχείο και καθορίζουν περιορισμούς χρήσης.
- Οι **Επεκταμένες Χρήσεις Κλειδιού (EKUs)** διαχωρίζουν τους συγκεκριμένους σκοπούς του πιστοποιητικού, όπως η υπογραφή κώδικα ή η κρυπτογράφηση ηλεκτρονικού ταχυδρομείου, μέσω ταυτοποιητικών αντικειμένων (OIDs).
- Ο **Αλγόριθμος Υπογραφής** καθορίζει τη μέθοδο υπογραφής του πιστοποιητικού.
- Η **Υπογραφή**, που δημιουργείται με το ιδιωτικό κλειδί του εκδότη, εγγυάται την αυθεντικότητα του πιστοποιητικού.

### Ειδικές Προσοχές

- Οι **Εναλλακτικές Ονομασίες Θέματος (SANs)** επεκτείνουν την εφαρμογή ενός πιστοποιητικού σε πολλαπλές ταυτότητες, κρίσιμες για διακομιστές με πολλά τομέα. Είναι ζωτικής σημασίας η ασφαλής διαδικασία έκδοσης για να αποφευχθούν οι κίνδυνοι παραπληροφόρησης από επιτιθέμενους που επεξεργάζονται την προδιαγραφή SAN.

### Αρχές Πιστοποίησης (CAs) στο Active Directory (AD)

Το AD CS αναγνωρίζει τα πιστοποιητικά CA σε ένα δάσος AD μέσω ειδικών δοχείων, τα οποία εξυπηρετούν μοναδικούς ρόλους:

- Το δοχείο **Certification Authorities** περιέχει πιστοποιητικά ρίζας CA.
- Το δοχείο **Enrolment Services** περιλαμβάνει τις επιχειρησιακές CA και τα πρότυπα πιστοποιητικών τους.
- Το αντικείμενο **NTAuthCertificates** περιλαμβάνει πιστοποιητικά CA που έχουν εξουσιοδοτηθεί για την πιστοποίηση AD.
- Το δοχείο **AIA (Authority Information Access)** διευκολύνει τον έλεγχο της αλυσίδας πιστοποιητικών με ενδιάμεσα και διασυνοριακά πιστοποιητικά CA.

### Απόκτηση Πιστοποιητικού: Ροή Αίτησης Πιστοποιητικού Πελάτη

1. Η διαδικασία αίτησης ξεκινά με τους πελάτες να βρίσκουν μια Επιχειρησιακή CA.
2. Δημιουργείται ένα CSR, που περιέχει ένα δημόσιο κλειδί και άλλες λεπτομέρειες, μετά τ
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Πιστοποίηση με Πιστοποιητικά

Το Active Directory (AD) υποστηρίζει την πιστοποίηση με πιστοποιητικά, χρησιμοποιώντας κυρίως τα πρωτόκολλα **Kerberos** και **Secure Channel (Schannel)**.

### Διαδικασία Πιστοποίησης Kerberos

Στη διαδικασία πιστοποίησης Kerberos, ο αίτημα ενός χρήστη για ένα Ticket Granting Ticket (TGT) υπογράφεται χρησιμοποιώντας το **ιδιωτικό κλειδί** του πιστοποιητικού του χρήστη. Αυτό το αίτημα υπόκειται σε αρκετές επαληθεύσεις από τον ελεγκτή του τομέα, συμπεριλαμβανομένης της **εγκυρότητας**, της **διαδρομής** και της **κατάστασης ανάκλησης** του πιστοποιητικού. Οι επαληθεύσεις περιλαμβάνουν επίσης τον έλεγχο ότι το πιστοποιητικό προέρχεται από ένα αξιόπιστο πηγή και την επιβεβαίωση της παρουσίας του εκδότη στο **κατάστημα πιστοποιητικών NTAUTH**. Επιτυχείς επαληθεύσεις οδηγούν στην έκδοση ενός TGT. Το αντικείμενο **`NTAuthCertificates`** στο AD, βρίσκεται στην:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
είναι κεντρικό για την εγκαθίδρυση εμπιστοσύνης για την πιστοποίηση με πιστοποιητικά.

### Πιστοποίηση Ασφαλούς Καναλιού (Schannel)

Το Schannel διευκολύνει ασφαλείς συνδέσεις TLS/SSL, όπου κατά τη διάρκεια μιας χειραψίας, ο πελάτης παρουσιάζει ένα πιστοποιητικό που, εάν επικυρωθεί με επιτυχία, εξουσιοδοτεί την πρόσβαση. Η αντιστοίχιση ενός πιστοποιητικού σε έναν λογαριασμό AD μπορεί να περιλαμβάνει τη λειτουργία **S4U2Self** του Kerberos ή το **Subject Alternative Name (SAN)** του πιστοποιητικού, μεταξύ άλλων μεθόδων.

### Απαρίθμηση Υπηρεσιών Πιστοποιητικών AD

Οι υπηρεσίες πιστοποιητικών του AD μπορούν να απαριθμηθούν μέσω ερωτημάτων LDAP, αποκαλύπτοντας πληροφορίες σχετικά με τις **Επιχειρησιακές Αρχές Πιστοποίησης (CAs)** και τις ρυθμίσεις τους. Αυτό είναι προσβάσιμο από οποιονδήποτε χρήστη που έχει επαληθευτεί στον τομέα χωρίς ειδικά προνόμια. Εργαλεία όπως το **[Certify](https://github.com/GhostPack/Certify)** και το **[Certipy](https://github.com/ly4k/Certipy)** χρησιμοποιούνται για την απαρίθμηση και την αξιολόγηση ευπαθειών σε περιβάλλοντα AD CS.

Οι εντολές για τη χρήση αυτών των εργαλείων περιλαμβάνουν:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Αναφορές

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
