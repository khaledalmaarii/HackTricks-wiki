# AD CS Διατήρηση τομέα

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτό είναι ένα σύνοψη των τεχνικών διατήρησης τομέα που κοινοποιούνται στο [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Ελέγξτε το για περαιτέρω λεπτομέρειες.

## Πλαστογράφηση Πιστοποιητικών με Κλεμμένα Πιστοποιητικά Αρχής - DPERSIST1

Πώς μπορείτε να πείτε ότι ένα πιστοποιητικό είναι πιστοποιητικό Αρχής;

Μπορεί να προσδιοριστεί ότι ένα πιστοποιητικό είναι πιστοποιητικό Αρχής εάν πληρούνται αρκετές συνθήκες:

- Το πιστοποιητικό αποθηκεύεται στον διακομιστή Αρχής, με το ιδιωτικό του κλειδί ασφαλισμένο από το DPAPI της μηχανής, ή από υλικό όπως ένα TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τόσο τα πεδία Εκδότης όσο και Θέματος του πιστοποιητικού ταιριάζουν με το διακριτικό όνομα της Αρχής.
- Υπάρχει μια επέκταση "Έκδοση Αρχής" αποκλειστικά στα πιστοποιητικά Αρχής.
- Το πιστοποιητικό δεν έχει πεδία Επεκτεινόμενης Χρήσης Κλειδιού (EKU).

Για να εξαχθεί το ιδιωτικό κλειδί αυτού του πιστοποιητικού, η εργαλειοθήκη `certsrv.msc` στον διακομιστή Αρχής είναι η υποστηριζόμενη μέθοδος μέσω της ενσωματωμένης γραφικής διεπαφής χρήστη. Ωστόσο, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που αποθηκεύονται στο σύστημα. Έτσι, μπορούν να εφαρμοστούν μεθόδοι όπως η τεχνική [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) για την εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να αποκτηθούν χρησιμοποιώντας το Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Μετά την απόκτηση του πιστοποιητικού CA και του ιδιωτικού του κλειδιού σε μορφή `.pfx`, μπορούν να χρησιμοποιηθούν εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) για τη δημιουργία έγκυρων πιστοποιητικών:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Ο χρήστης που επιλέγεται για πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και να μπορεί να πιστοποιηθεί στο Active Directory για να επιτευχθεί η διαδικασία. Η πλαστογράφηση ενός πιστοποιητικού για ειδικούς λογαριασμούς όπως το krbtgt είναι αναποτελεσματική.
{% endhint %}

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** μέχρι την ημερομηνία λήξης που έχει οριστεί και όσο **είναι έγκυρο το πιστοποιητικό της ρίζας της Αρχής Πιστοποίησης** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανές**, οπότε σε συνδυασμό με το **S4U2Self**, ένας επιτιθέμενος μπορεί να **διατηρήσει την μόνιμη παρουσία του σε οποιαδήποτε μηχανή του τομέα** για όσο είναι έγκυρο το πιστοποιητικό της Αρχής Πιστοποίησης.\
Επιπλέον, τα **πιστοποιητικά που δημιουργούνται** με αυτήν τη μέθοδο **δεν μπορούν να ανακληθούν**, καθώς η Αρχή Πιστοποίησης δεν τα γνωρίζει.

## Εμπιστοσύνη σε παράνομα πιστοποιητικά CA - DPERSIST2

Το αντικείμενο `NTAuthCertificates` έχει οριστεί να περιέχει ένα ή περισσότερα **πιστοποιητικά CA** στο χαρακτηριστικό `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **ελεγκτή τομέα** περιλαμβάνει τον έλεγχο του αντικειμένου `NTAuthCertificates` για μια καταχώρηση που αντιστοιχεί στο **CA που έχει καθοριστεί** στο πεδίο Issuer του πιστοποιητικού πιστοποίησης. Η πιστοποίηση συνεχίζεται αν βρεθεί αντιστοιχία.

Ένα πιστοποιητικό CA που έχει υπογραφεί από τον ίδιο τον επιτιθέμενο μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates`, εφόσον ο επιτιθέμενος έχει έλεγχο επί αυτού του αντικειμένου AD. Συνήθως, μόνο τα μέλη της ομάδας **Enterprise Admin**, μαζί με τους **Domain Admins** ή τους **Administrators** στον **τομέα της ρίζας του δάσους**, έχουν δικαίωμα να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας το `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Αυτή η δυνατότητα είναι ιδιαίτερα σημαντική όταν χρησιμοποιείται σε συνδυασμό με μια προηγουμένως αναφερθείσα μέθοδο που περιλαμβάνει τη χρήση του ForgeCert για τη δυναμική δημιουργία πιστοποιητικών.

## Κακόβουλη Εσφαλμένη Διαμόρφωση - DPERSIST3

Οι ευκαιρίες για **μόνιμη παρουσία** μέσω **τροποποιήσεων των περιγραφών ασφαλείας των στοιχείων AD CS** είναι πολλές. Οι τροποποιήσεις που περιγράφονται στην ενότητα "[Ανόδου τομέα](domain-escalation.md)" μπορούν να εφαρμοστούν κακόβουλα από έναν επιτιθέμενο με αυξημένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "δικαιωμάτων ελέγχου" (π.χ. WriteOwner/WriteDACL κλπ.) σε ευαίσθητα στοιχεία, όπως:

- Το αντικείμενο υπολογιστή AD του **διακομιστή CA**
- Ο διακομιστής **RPC/DCOM** του διακομιστή CA
- Οποιοδήποτε **κατώτερο αντικείμενο ή δοχείο AD** στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το δοχείο προτύπων πιστοποιητικού, το δοχείο Αρχών Πιστοποίησης, το αντικείμενο NTAuthCertificates κλπ.)
- **Ομάδες AD με εξουσιοδότηση για έλεγχο του AD CS** από προεπιλογή ή από τον οργανισμό (όπως η ενσωματωμένη ομάδα Cert Publishers και οποιοδήποτε από τα μέλη της)

Ένα παράδειγμα κακόβουλης εφαρμογής θα περιλάμβανε έναν επιτιθέμενο, ο οποίος έχει **αυξημένα δικαιώματα** στον τομέα, να προσθέτει το δικαίωμα **`WriteOwner`** στο προεπιλεγμένο πρότυπο πιστοποιητικού **`User`**, με τον επιτιθέμενο να είναι ο κύριος για το δικαίωμα. Για να εκμεταλλευτεί αυτό, ο επιτιθέμενος θα άλλαζε αρχικά την κυριότητα του προτύπου **`User`** σε εαυτόν. Στη συνέχεια, θα ορίζονταν το **`mspki-certificate-name-flag`** σε **1** σ
