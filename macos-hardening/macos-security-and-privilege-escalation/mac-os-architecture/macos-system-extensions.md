# Επεκτάσεις Συστήματος macOS

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>
{% endhint %}

## Επεκτάσεις Συστήματος / Πλαίσιο Ασφάλειας Τερματικού

Σε αντίθεση με τις Πυρήνας Επεκτάσεις, **οι Επεκτάσεις Συστήματος λειτουργούν στον χώρο χρήστη** αντί για τον χώρο πυρήνα, μειώνοντας τον κίνδυνο από κατάρρευση του συστήματος λόγω δυσλειτουργίας της επέκτασης.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Υπάρχουν τρία είδη επεκτάσεων συστήματος: Επεκτάσεις **DriverKit**, Επεκτάσεις **Δικτύου** και Επεκτάσεις **Ασφάλειας Τερματικού**.

### **Επεκτάσεις DriverKit**

Το DriverKit είναι μια αντικατάσταση για τις πυρήνας επεκτάσεις που **παρέχουν υποστήριξη υλικού**. Επιτρέπει στους οδηγούς συσκευών (όπως USB, Serial, NIC και HID drivers) να λειτουργούν στον χώρο χρήστη αντί για τον χώρο πυρήνα. Το πλαίσιο DriverKit περιλαμβάνει **εκδόσεις χώρου χρήστη ορισμένων κλάσεων I/O Kit**, και ο πυρήνας προωθεί κανονικά τα συμβάντα I/O Kit στον χώρο χρήστη, προσφέροντας ένα πιο ασφαλές περιβάλλον για αυτούς τους οδηγούς να λειτουργούν.

### **Επεκτάσεις Δικτύου**

Οι Επεκτάσεις Δικτύου παρέχουν τη δυνατότητα προσαρμογής των συμπεριφορών του δικτύου. Υπάρχουν διάφοροι τύποι Επεκτάσεων Δικτύου:

* **Προξειδωτής Εφαρμογής**: Χρησιμοποιείται για τη δημιουργία ενός πελάτη VPN που υλοποιεί ένα πρωτόκολλο VPN που εστιάζεται σε ροές σύνδεσης αντί για μεμονωμένα πακέτα.
* **Σήραγγα Πακέτων**: Χρησιμοποιείται για τη δημιουργία ενός πελάτη VPN που υλοποιεί ένα πρωτόκολλο VPN που εστιάζεται σε μεμονωμένα πακέτα.
* **Φίλτρο Δεδομένων**: Χρησιμοποιείται για το φιλτράρισμα "ροών" δικτύου. Μπορεί να παρακολουθεί ή να τροποποιεί δεδομένα δικτύου στο επίπεδο ροής.
* **Φίλτρο Πακέτων**: Χρησιμοποιείται για το φιλτράρισμα μεμονωμένων πακέτων δικτύου. Μπορεί να παρακολουθεί ή να τροποποιεί δεδομένα δικτύου στο επίπεδο πακέτου.
* **Προξειδωτής DNS**: Χρησιμοποιείται για τη δημιουργία ενός προσαρμοσμένου παροχέα DNS. Μπορεί να χρησιμοποιηθεί για την παρακολούθηση ή την τροποποίηση αιτημάτων και απαντήσεων DNS.

## Πλαίσιο Ασφάλειας Τερματικού

Το Πλαίσιο Ασφάλειας Τερματικού είναι ένα πλαίσιο που παρέχεται από την Apple στο macOS και παρέχει ένα σύνολο APIs για την ασφάλεια του συστήματος. Προορίζεται για χρήση από **προμηθευτές ασφάλειας και προγραμματιστές για τη δημιουργία προϊόντων που μπορούν να παρακολουθούν και να ελέγχουν τη δραστηριότητα του συστήματος** για την αναγνώριση και προστασία από κακόβουλη δραστηριότητα.

Αυτό το πλαίσιο παρέχει μια **συλλογή από APIs για την παρακολούθηση και τον έλεγχο της δραστηριότητας του συστήματος**, όπως εκτελέσεις διεργασιών, συμβάντα συστήματος αρχείων, δικτύου και πυρήνα.

Η καρδιά αυτού του πλαισίου υλοποιείται στον πυρήνα, ως Πυρήνας Επέκτασης (KEXT) που βρίσκεται στο **`/System/Library/Extensions/EndpointSecurity.kext`**. Αυτός ο KEXT αποτελείται από αρκετά βασικά στοιχεία:

* **EndpointSecurityDriver**: Λειτουργεί ως "σημείο εισόδου" για την πυρήνα επέκταση. Είναι το κύριο σημείο αλληλεπίδρασης μεταξύ του λειτουργικού συστήματος και του πλαισίου Ασφάλειας Τερματικού.
* **EndpointSecurityEventManager**: Αυτό το στοιχείο είναι υπεύθυνο για την υλοποίηση των συνδέσεων πυρήνα. Οι συνδέσεις πυρήνα επιτρέπουν στο πλαίσιο να παρακολουθεί συμβάντα συστήματος με την παρέμβαση κλήσεων συστήματος.
* **EndpointSecurityClientManager**: Διαχειρίζεται την επικοινωνία με τους πελάτες χώρου χρήστη, παρακολουθώντας ποιοι πελάτες είναι συνδεδεμένοι και χρειάζονται να λάβουν ειδοποιήσεις συμβάντων.
* **EndpointSecurityMessageManager**: Αποστέλλει μηνύματα και ειδοποιήσεις συμβάντων στους πελάτες χώρου χρήστη.

Τα συμβάντα που μπορεί να παρακολουθήσει το πλαίσιο Ασφάλειας Τερματικού κατηγοριοποιούνται σε:

* Συμβάντα αρχείων
* Συμβάντα διεργασιών
* Συμβάντα socket
* Συμβάντα πυρήνα (όπως φόρτωση/εκφόρτωση μιας πυρήνας επέκτασης ή ανοίγμα ενός συσκευής I/O Kit)

### Αρχιτεκτονική Πλαισίου Ασφάλειας Τερματικού

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Η **επικοινωνία χώρου χρήστη** με το πλαίσιο Ασφάλειας Τερματικού γίνεται μέσω της κλάσης IOUserClient. Χρησιμοποιούνται δύο διαφορετικές υποκλάσεις, ανάλογα με τον τύπο του καλούντος:

* **EndpointSecurityDriverClient**: Αυτό απαιτεί την άδεια `com.apple.private.endpoint-security.manager`, η οποία κατέχεται μόνο από τη διεργασία συστήματος `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Αυτό απαιτεί την άδεια `com.apple.developer.endpoint-security.client`. Αυτό θα χρησιμοποιούνταν τυπικά από λογισμικό ασφαλείας τρίτων που χρειάζεται να αλληλεπιδρά με το πλαίσιο Ασφάλειας Τερματικού.

Οι Επεκτάσεις Ασφάλειας Τερματικού: **`
```bash
tccutil reset All
```
Για **περισσότερες πληροφορίες** σχετικά με αυτήν την παράκαμψη και σχετικές, ελέγξτε την ομιλία [#OBTS v5.0: "Η Αχίλλειος Πτέρνα της Ασφάλειας Τερματικού" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Στο τέλος αυτό διορθώθηκε δίνοντας τη νέα άδεια **`kTCCServiceEndpointSecurityClient`** στην εφαρμογή ασφαλείας που διαχειρίζεται ο **`tccd`** έτσι ώστε το `tccutil` να μην εκκαθαρίζει τις άδειές της εμποδίζοντάς την από το να εκτελεστεί.

## Αναφορές

* [**OBTS v3.0: "Ασφάλεια & Ανασφάλεια Τερματικού" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
