# Πιστοποιητικά

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Τι είναι ένα Πιστοποιητικό

Ένα **πιστοποιητικό δημόσιου κλειδιού** είναι μια ψηφιακή ταυτότητα που χρησιμοποιείται στην κρυπτογραφία για να αποδείξει ότι κάποιος κατέχει ένα δημόσιο κλειδί. Περιλαμβάνει τις λεπτομέρειες του κλειδιού, την ταυτότητα του κατόχου (το υποκείμενο) και μια ψηφιακή υπογραφή από μια αξιόπιστη αρχή (τον εκδότη). Εάν το λογισμικό εμπιστεύεται τον εκδότη και η υπογραφή είναι έγκυρη, είναι δυνατή η ασφαλής επικοινωνία με τον κάτοχο του κλειδιού.

Τα πιστοποιητικά εκδίδονται κυρίως από [αρχές πιστοποίησης](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) σε μια ρύθμιση [υποδομής δημόσιου κλειδιού](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Μια άλλη μέθοδος είναι το [δίκτυο εμπιστοσύνης](https://en.wikipedia.org/wiki/Web\_of\_trust), όπου οι χρήστες επαληθεύουν άμεσα τα κλειδιά ο ένας του άλλου. Η κοινή μορφή για τα πιστοποιητικά είναι το [X.509](https://en.wikipedia.org/wiki/X.509), το οποίο μπορεί να προσαρμοστεί για συγκεκριμένες ανάγκες όπως περιγράφεται στο RFC 5280.

## Κοινά Πεδία x509

### **Κοινά Πεδία σε Πιστοποιητικά x509**

Στα πιστοποιητικά x509, αρκετά **πεδία** παίζουν κρίσιμο ρόλο στην εξασφάλιση της εγκυρότητας και της ασφάλειας του πιστοποιητικού. Ακολουθεί μια ανάλυση αυτών των πεδίων:

* Ο **Αριθμός Έκδοσης** υποδηλώνει την έκδοση της μορφής x509.
* Ο **Αριθμός Σειράς** προσδιορίζει μοναδικά το πιστοποιητικό μέσα στο σύστημα μιας Αρχής Πιστοποίησης (CA), κυρίως για παρακολούθηση ανάκλησης.
* Το πεδίο **Υποκείμενο** αντιπροσωπεύει τον κάτοχο του πιστοποιητικού, ο οποίος μπορεί να είναι μια μηχανή, ένα άτομο ή ένας οργανισμός. Περιλαμβάνει λεπτομερή ταυτοποίηση όπως:
* **Κοινό Όνομα (CN)**: Τομείς που καλύπτονται από το πιστοποιητικό.
* **Χώρα (C)**, **Τοποθεσία (L)**, **Πολιτεία ή Επαρχία (ST, S, ή P)**, **Οργάνωση (O)** και **Οργανωτική Μονάδα (OU)** παρέχουν γεωγραφικές και οργανωτικές λεπτομέρειες.
* Το **Διακριτό Όνομα (DN)** περιλαμβάνει την πλήρη ταυτοποίηση του υποκειμένου.
* Ο **Εκδότης** αναφέρει ποιος επαλήθευσε και υπέγραψε το πιστοποιητικό, περιλαμβάνοντας παρόμοια υποπεδία όπως το Υποκείμενο για την CA.
* Η **Περίοδος Ικανότητας** σημειώνεται με τις χρονικές σφραγίδες **Not Before** και **Not After**, εξασφαλίζοντας ότι το πιστοποιητικό δεν χρησιμοποιείται πριν ή μετά από μια συγκεκριμένη ημερομηνία.
* Η ενότητα **Δημόσιο Κλειδί**, κρίσιμη για την ασφάλεια του πιστοποιητικού, προσδιορίζει τον αλγόριθμο, το μέγεθος και άλλες τεχνικές λεπτομέρειες του δημόσιου κλειδιού.
* Οι **επέκταση x509v3** ενισχύουν τη λειτουργικότητα του πιστοποιητικού, προσδιορίζοντας τη **Χρήση Κλειδιού**, τη **Εκτεταμένη Χρήση Κλειδιού**, το **Εναλλακτικό Όνομα Υποκειμένου** και άλλες ιδιότητες για την ακριβή ρύθμιση της εφαρμογής του πιστοποιητικού.

#### **Χρήση Κλειδιού και Επεκτάσεις**

* Η **Χρήση Κλειδιού** προσδιορίζει τις κρυπτογραφικές εφαρμογές του δημόσιου κλειδιού, όπως ψηφιακή υπογραφή ή κρυπτογράφηση κλειδιού.
* Η **Εκτεταμένη Χρήση Κλειδιού** περιορίζει περαιτέρω τις περιπτώσεις χρήσης του πιστοποιητικού, π.χ., για πιστοποίηση διακομιστή TLS.
* Το **Εναλλακτικό Όνομα Υποκειμένου** και ο **Βασικός Περιορισμός** καθορίζουν πρόσθετα ονόματα κεντρικών υπολογιστών που καλύπτονται από το πιστοποιητικό και αν είναι πιστοποιητικό CA ή τελικού φορέα, αντίστοιχα.
* Αναγνωριστικά όπως το **Αναγνωριστικό Κλειδιού Υποκειμένου** και το **Αναγνωριστικό Κλειδιού Αρχής** εξασφαλίζουν μοναδικότητα και ιχνηλασιμότητα των κλειδιών.
* Η **Πρόσβαση Πληροφοριών Αρχής** και τα **Σημεία Διανομής CRL** παρέχουν διαδρομές για την επαλήθευση της εκδούσας CA και τον έλεγχο της κατάστασης ανάκλησης του πιστοποιητικού.
* Οι **SCTs Προπιστοποιητικού CT** προσφέρουν διαφάνεια, κρίσιμη για τη δημόσια εμπιστοσύνη στο πιστοποιητικό.
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

**OCSP** (**RFC 2560**) περιλαμβάνει έναν πελάτη και έναν απαντητή που συνεργάζονται για να ελέγξουν αν ένα ψηφιακό πιστοποιητικό δημόσιου κλειδιού έχει ανακληθεί, χωρίς να χρειάζεται να κατεβάσουν ολόκληρη την **CRL**. Αυτή η μέθοδος είναι πιο αποδοτική από την παραδοσιακή **CRL**, η οποία παρέχει μια λίστα με τους αριθμούς σειράς των ανακληθέντων πιστοποιητικών αλλά απαιτεί τη λήψη ενός ενδεχομένως μεγάλου αρχείου. Οι CRL μπορούν να περιλαμβάνουν έως και 512 καταχωρίσεις. Περισσότερες λεπτομέρειες είναι διαθέσιμες [εδώ](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Τι είναι η Διαφάνεια Πιστοποιητικών**

Η Διαφάνεια Πιστοποιητικών βοηθά στην καταπολέμηση των απειλών που σχετίζονται με τα πιστοποιητικά, διασφαλίζοντας ότι η έκδοση και η ύπαρξη των SSL πιστοποιητικών είναι ορατές στους ιδιοκτήτες τομέων, τις CA και τους χρήστες. Οι στόχοι της είναι:

* Να αποτρέψει τις CA από το να εκδίδουν SSL πιστοποιητικά για έναν τομέα χωρίς τη γνώση του ιδιοκτήτη του τομέα.
* Να καθιερώσει ένα ανοιχτό σύστημα ελέγχου για την παρακολούθηση πιστοποιητικών που εκδόθηκαν κατά λάθος ή κακόβουλα.
* Να προστατεύσει τους χρήστες από δόλια πιστοποιητικά.

#### **Καταγραφές Πιστοποιητικών**

Οι καταγραφές πιστοποιητικών είναι δημόσια ελεγχόμενα, μόνο προσθετικά αρχεία πιστοποιητικών, που διατηρούνται από υπηρεσίες δικτύου. Αυτές οι καταγραφές παρέχουν κρυπτογραφικές αποδείξεις για σκοπούς ελέγχου. Τόσο οι αρχές έκδοσης όσο και το κοινό μπορούν να υποβάλουν πιστοποιητικά σε αυτές τις καταγραφές ή να τα ελέγξουν για επαλήθευση. Ενώ ο ακριβής αριθμός των διακομιστών καταγραφής δεν είναι σταθερός, αναμένεται να είναι λιγότερος από χίλια παγκοσμίως. Αυτοί οι διακομιστές μπορούν να διαχειρίζονται ανεξάρτητα από τις CA, ISPs ή οποιαδήποτε ενδιαφερόμενη οντότητα.

#### **Ερώτημα**

Για να εξερευνήσετε τις καταγραφές Διαφάνειας Πιστοποιητικών για οποιονδήποτε τομέα, επισκεφθείτε [https://crt.sh/](https://crt.sh).

Διαφορετικές μορφές υπάρχουν για την αποθήκευση πιστοποιητικών, καθεμία με τις δικές της περιπτώσεις χρήσης και συμβατότητα. Αυτή η σύνοψη καλύπτει τις κύριες μορφές και παρέχει καθοδήγηση για τη μετατροπή μεταξύ τους.

## **Μορφές**

### **Μορφή PEM**

* Η πιο ευρέως χρησιμοποιούμενη μορφή για πιστοποιητικά.
* Απαιτεί ξεχωριστά αρχεία για πιστοποιητικά και ιδιωτικά κλειδιά, κωδικοποιημένα σε Base64 ASCII.
* Κοινές επεκτάσεις: .cer, .crt, .pem, .key.
* Χρησιμοποιείται κυρίως από Apache και παρόμοιους διακομιστές.

### **Μορφή DER**

* Μια δυαδική μορφή πιστοποιητικών.
* Λείπουν οι δηλώσεις "BEGIN/END CERTIFICATE" που βρίσκονται σε αρχεία PEM.
* Κοινές επεκτάσεις: .cer, .der.
* Συχνά χρησιμοποιείται με πλατφόρμες Java.

### **Μορφή P7B/PKCS#7**

* Αποθηκεύεται σε Base64 ASCII, με επεκτάσεις .p7b ή .p7c.
* Περιέχει μόνο πιστοποιητικά και αλυσίδες πιστοποιητικών, εξαιρώντας το ιδιωτικό κλειδί.
* Υποστηρίζεται από Microsoft Windows και Java Tomcat.

### **Μορφή PFX/P12/PKCS#12**

* Μια δυαδική μορφή που περιλαμβάνει πιστοποιητικά διακομιστή, ενδιάμεσα πιστοποιητικά και ιδιωτικά κλειδιά σε ένα αρχείο.
* Επεκτάσεις: .pfx, .p12.
* Χρησιμοποιείται κυρίως σε Windows για εισαγωγή και εξαγωγή πιστοποιητικών.

### **Μετατροπή Μορφών**

**Οι μετατροπές PEM** είναι απαραίτητες για τη συμβατότητα:

* **x509 σε PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM σε DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER σε PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM σε P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 σε PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Οι μετατροπές PFX** είναι κρίσιμες για τη διαχείριση πιστοποιητικών στα Windows:

* **PFX σε PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX σε PKCS#8** περιλαμβάνει δύο βήματα:
1. Μετατροπή PFX σε PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Μετατροπή PEM σε PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B σε PFX** απαιτεί επίσης δύο εντολές:
1. Μετατροπή P7B σε CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Μετατροπή CER και Ιδιωτικού Κλειδιού σε PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στο** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) ή στο [**telegram group**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
