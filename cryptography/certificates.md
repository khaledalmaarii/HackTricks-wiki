# Πιστοποιητικά

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Τι είναι ένα πιστοποιητικό

Ένα **πιστοποιητικό δημόσιου κλειδιού** είναι ένα ψηφιακό αναγνωριστικό που χρησιμοποιείται στην κρυπτογραφία για να αποδείξει ότι κάποιος είναι κάτοχος ενός δημόσιου κλειδιού. Περιλαμβάνει τις λεπτομέρειες του κλειδιού, την ταυτότητα του ιδιοκτήτη (το θέμα) και μια ψηφιακή υπογραφή από μια αξιόπιστη αρχή (ο εκδότης). Εάν το λογισμικό εμπιστεύεται τον εκδότη και η υπογραφή είναι έγκυρη, είναι δυνατή η ασφαλής επικοινωνία με τον ιδιοκτήτη του κλειδιού.

Τα πιστοποιητικά εκδίδονται κυρίως από [πιστοποιητικές αρχές](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) σε ένα περιβάλλον [υποδομής δημόσιου κλειδιού](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Ένας άλλος τρόπος είναι το [δίκτυο εμπιστοσύνης](https://en.wikipedia.org/wiki/Web_of_trust), όπου οι χρήστες επαληθεύουν απευθείας τα κλειδιά τους. Η κοινή μορφή για τα πιστοποιητικά είναι η [X.509](https://en.wikipedia.org/wiki/X.509), η οποία μπορεί να προσαρμοστεί για συγκεκριμένες ανάγκες, όπως περιγράφεται στο RFC 5280.

## Κοινά πεδία x509

### **Κοινά πεδία στα πιστοποιητικά x509**

Στα πιστοποιητικά x509, αρκετά **πεδία** παίζουν κρίσιμο ρόλο για την εγκυρότητα και την ασφάλεια του πιστοποιητικού. Εδώ υπάρχει μια ανάλυση αυτών των πεδίων:

- Ο αριθμός **Έκδοσης** υποδηλώνει την έκδοση της μορφής x509.
- Ο αριθμός **Σειράς** αναγνωρίζει μοναδικά το πιστοποιητικό εντός του συστήματος μιας Πιστοποιητικής Αρχής (CA), κυρίως για την παρακολούθηση ανάκλησης.
- Το πεδίο **Θέματος** αντιπροσωπεύει τον ιδιοκτήτη του πιστοποιητικού, ο οποίος μπορεί να είναι μια μηχανή, ένα άτομο ή μια οργάνωση. Περιλαμβάνει λεπτομερείς πληροφορίες, όπως:
- **Κοινό Όνομα (CN)**: Τομείς που καλύπτονται από το πιστοποιητικό.
- **Χώρα (C)**, **Τοποθεσία (L)**, **Πολιτεία ή Επαρχία (ST, S ή P)**, **Οργανισμός (O)** και **Μονάδα Οργανισμού (OU)** παρέχουν γεωγραφικές και οργανωτικές λεπτομέρειες.
- Το **Διακριτικό Όνομα (DN)** ενθυλακώνει την πλήρη ταυτοποίηση του θέματος.
- Ο **Εκδότης** αναφέρει ποιος επαλήθευσε και υπέγραψε το πιστοποιητικό, περιλαμβάνοντας παρόμοια υποπεδία με το Θέμα για την ΠΑ.
- Η **Περίοδος Ισχύος** σηματοδοτείται από τις χρονοσφραγίδες **Μη Πριν** και **Μη Μετά**, εξασφαλίζοντας ότι το πιστοποιητικό δεν χρησιμοποιείται πριν ή μετά από μια συγκεκριμένη ημερομηνία.
- Η ενότητα **Δημόσιο Κλειδί**, η οποία είναι κρίσιμη για την ασφάλεια του πιστοποιητικού, κα
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Διαφορά μεταξύ OCSP και CRL Distribution Points**

Το **OCSP** (**RFC 2560**) περιλαμβάνει έναν πελάτη και έναν ανταποκρίτη που συνεργάζονται για να ελέγξουν εάν ένα ψηφιακό πιστοποιητικό δημόσιου κλειδιού έχει ανακληθεί, χωρίς να χρειάζεται να κατεβάσουν το πλήρες **CRL**. Αυτή η μέθοδος είναι πιο αποδοτική από το παραδοσιακό **CRL**, το οποίο παρέχει μια λίστα με τους αριθμούς σειράς των ανακλημένων πιστοποιητικών αλλά απαιτεί τη λήψη ενός ενδεχομένως μεγάλου αρχείου. Τα CRL μπορούν να περιλαμβάνουν έως και 512 καταχωρήσεις. Περισσότερες λεπτομέρειες είναι διαθέσιμες [εδώ](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Τι είναι η Certificate Transparency**

Η Certificate Transparency βοηθά στην καταπολέμηση απειλών που σχετίζονται με πιστοποιητικά, εξασφαλίζοντας ότι η έκδοση και η ύπαρξη των πιστοποιητικών SSL είναι ορατές για τους ιδιοκτήτες τομέα, τις αρχές πιστοποίησης και τους χρήστες. Οι στόχοι της είναι:

* Να αποτρέπει τις αρχές πιστοποίησης από το να εκδίδουν πιστοποιητικά SSL για έναν τομέα χωρίς τη γνώση του ιδιοκτήτη του τομέα.
* Να θεσπίσει ένα ανοιχτό σύστημα ελέγχου για την παρακολούθηση πιστοποιητικών που έχουν εκδοθεί κατά λάθος ή κακόβουλα.
* Να προστατεύει τους χρήστες από απάτες με πιστοποιητικά.

#### **Αρχεία καταγραφής πιστοποιητικών**

Τα αρχεία καταγραφής πιστοποιητικών είναι δημόσια ελεγξίμα αρχεία με αποκλειστική εγγραφή πιστοποιητικών, τα οποία διατηρούνται από υπηρεσίες δικτύου. Αυτά τα αρχεία παρέχουν κρυπτογραφικές αποδείξεις για σκοπούς ελέγχου. Τόσο οι αρχές έκδοσης όσο και το κοινό μπορούν να υποβάλουν πιστοποιητικά σε αυτά τα αρχεία ή να τα ερωτήσουν για επαλήθευση. Ενώ ο ακριβής αριθμός των διακομιστών καταγραφής δεν είναι σταθερός, αναμένεται να είναι λιγότερο από χίλια παγκοσμίως. Αυτοί οι διακομιστές μπορούν να διαχειρίζονται ανεξάρτητα από αρχές πιστοποίησης, παροχείς υπηρεσιών Internet ή οποιοδήποτε ενδιαφερόμενο φορέα.

#### **Ερώτημα**

Για να εξερευνήσετε τα αρχεία καταγραφής πιστοποιητικών Certificate Transparency για οποιονδήποτε τομέα, επισκεφθείτε το [https://crt.sh/](https://crt.sh).

Υπάρχουν διάφορες μορφές για την αποθήκευση πιστοποιητικών, καθεμία με τις δικές της περιπτώσεις χρήσης και συμβατότητα. Αυτό το σύνοψη καλύπτει τις κύριες μορφές και παρέχει καθοδήγηση για τη μετατροπή μεταξύ τους.

## **Μορφές**

### **Μορφή PEM**
- Η πιο διαδεδομένη μορφή για πιστοποιητικά.
- Απαιτεί ξεχωριστά αρχεία για πιστοποιητικά και ιδιωτικά κλειδιά, κωδικοποιημένα σε Base64 ASCII.
- Συνηθισμένες επεκτάσεις: .cer, .crt, .pem, .key.
- Χρησιμοποιείται κυρίως από τον Apache και παρόμοιους διακομιστές.

### **Μορφή DER**
- Μια δυαδική μορφή πιστοποιητικών.
- Δεν περιλαμβάνει τις δηλώσεις "BEGIN/END CERTIFICATE" που βρίσκονται στα αρχεία PEM.
- Συνηθισμένες επεκτάσεις: .cer, .der.
- Χρησιμοποιείται συχνά με πλατφόρμες Java.

### **Μορφή P7B/PKCS#7**
- Αποθηκεύεται σε Base64 ASCII, με επεκτάσεις .p7b ή .p7c.
- Περιέχει μόνο πιστοποιητικά και αλυσίδες πιστοποιητικών, χωρίς το ιδιωτικό κλειδί.
- Υποστηρίζεται από τα Microsoft Windows και Java Tomcat.

### **Μορφή PFX/P12/PKCS#12**
- Μια δυαδική μορφή που ενθυλακώνει πιστοποιητικά διακομιστή, ενδιάμεσα πιστοποιητικά και ιδιωτικά κλειδιά σε ένα αρχείο.
- Επεκτάσεις: .pfx, .p12.
- Χρησιμοποιείται κυρίως στα Windows για την εισαγωγή και εξαγωγή πιστοποιητικών. 

### **Μετατροπή μορφών**

Οι **μετατροπές PEM** είναι απαραίτητες για τη συμβατότητα:

- **x509 σε PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM σε DER**

Η μετατροπή από τη μορφή PEM στη μορφή DER μπορεί να γίνει με τη χρήση του εργαλείου `openssl`. Ακολουθήστε τα παρακάτω βήματα για να πραγματοποιήσετε τη μετατροπή:

1. Ανοίξτε ένα τερματικό και εκτελέστε την ακόλουθη εντολή:
   ```
   openssl x509 -outform der -in certificate.pem -out certificate.der
   ```

   Αντικαταστήστε το `certificate.pem` με το όνομα του αρχείου PEM που θέλετε να μετατρέψετε και το `certificate.der` με το όνομα που θέλετε να δώσετε στο νέο αρχείο DER.

2. Το εργαλείο `openssl` θα δημιουργήσει ένα νέο αρχείο με το όνομα που καθορίσατε, σε μορφή DER.

Με αυτόν τον τρόπο, μπορείτε να μετατρέψετε ένα αρχείο πιστοποιητικού από τη μορφή PEM στη μορφή DER.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER σε PEM**

Για να μετατρέψετε ένα πιστοποιητικό από τη μορφή DER σε μορφή PEM, μπορείτε να χρησιμοποιήσετε την εντολή `openssl`. Ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε ένα τερματικό και εκτελέστε την εντολή:

   ```plaintext
   openssl x509 -inform der -in certificate.der -out certificate.pem
   ```

   Αντικαταστήστε το `certificate.der` με το όνομα του αρχείου DER πιστοποιητικού που θέλετε να μετατρέψετε και το `certificate.pem` με το όνομα που θέλετε να δώσετε στο νέο αρχείο PEM.

2. Το πιστοποιητικό σας τώρα έχει μετατραπεί από τη μορφή DER σε μορφή PEM και είναι έτοιμο για χρήση.
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **Μετατροπή από PEM σε P7B**

Για να μετατρέψετε ένα αρχείο πιστοποιητικού στη μορφή PEM σε μορφή P7B, μπορείτε να χρησιμοποιήσετε την εντολή `openssl`. Ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε ένα τερματικό και εκτελέστε την εντολή:
   ```
   openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b
   ```

   Αντικαταστήστε το `certificate.pem` με το όνομα του αρχείου πιστοποιητικού που θέλετε να μετατρέψετε.

2. Το αρχείο P7B θα δημιουργηθεί στον ίδιο φάκελο με το αρχείο PEM.

Τώρα έχετε μετατρέψει με επιτυχία το αρχείο πιστοποιητικού από τη μορφή PEM στη μορφή P7B.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **Μετατροπή PKCS7 σε PEM**

To convert a PKCS7 certificate to PEM format, you can use the following OpenSSL command:

```plaintext
openssl pkcs7 -print_certs -in certificate.p7b -out certificate.pem
```

This command will extract the certificates from the PKCS7 file and save them in PEM format. The resulting PEM file can then be used for various cryptographic operations.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Οι μετατροπές PFX** είναι κρίσιμες για τη διαχείριση πιστοποιητικών στα Windows:

- **PFX σε PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX σε PKCS#8** περιλαμβάνει δύο βήματα:
1. Μετατροπή PFX σε PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Μετατροπή από PEM σε PKCS8

Για να μετατρέψετε ένα αρχείο PEM σε μορφή PKCS8, μπορείτε να χρησιμοποιήσετε την εντολή `openssl` στο τερματικό. Ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε ένα τερματικό και εκτελέστε την εντολή:
   ```
   openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.pkcs8
   ```

   Αντικαταστήστε το `private_key.pem` με το όνομα του αρχείου PEM που θέλετε να μετατρέψετε και το `private_key.pkcs8` με το όνομα που θέλετε να δώσετε στο νέο αρχείο PKCS8.

2. Θα σας ζητηθεί να εισαγάγετε τον κωδικό πρόσβασης του ιδιωτικού κλειδιού PEM.

3. Το νέο αρχείο PKCS8 θα δημιουργηθεί στον ίδιο φάκελο με το αρχικό αρχείο PEM.

Με αυτόν τον τρόπο, μπορείτε να μετατρέψετε ένα αρχείο PEM σε μορφή PKCS8 για περαιτέρω χρήση στις κρυπτογραφικές σας εργασίες.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B σε PFX** απαιτεί επίσης δύο εντολές:
1. Μετατροπή P7B σε CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Μετατροπή CER και Ιδιωτικού Κλειδιού σε PFX

Για να μετατρέψετε ένα αρχείο CER και το αντίστοιχο ιδιωτικό κλειδί σε μορφή PFX, μπορείτε να χρησιμοποιήσετε το εργαλείο OpenSSL. Ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε ένα τερματικό παράθυρο και μεταβείτε στον φάκελο όπου βρίσκονται τα αρχεία CER και ιδιωτικού κλειδιού.

2. Εκτελέστε την παρακάτω εντολή για να δημιουργήσετε ένα αρχείο PFX:

```plaintext
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.cer
```

Σημείωση: Αντικαταστήστε τα `private.key` και `certificate.cer` με τα ονόματα των αρχείων που έχετε.

3. Θα σας ζητηθεί να εισαγάγετε έναν κωδικό πρόσβασης για το αρχείο PFX. Εισαγάγετε τον επιθυμητό κωδικό πρόσβασης και πατήστε Enter.

4. Το αρχείο PFX με το πιστοποιητικό και το ιδιωτικό κλειδί θα δημιουργηθεί στον ίδιο φάκελο όπου εκτελέσατε την εντολή.

Μετά την ολοκλήρωση αυτών των βημάτων, θα έχετε μετατρέψει με επιτυχία το αρχείο CER και το ιδιωτικό κλειδί σε μορφή PFX.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εργασιακές διαδικασίες με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
