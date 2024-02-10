# Επεκτάσεις συστήματος macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Επεκτάσεις συστήματος / Πλαίσιο ασφαλείας τερματικού σημείου

Αντίθετα από τις επεκτάσεις πυρήνα, οι **επεκτάσεις συστήματος εκτελούνται στον χώρο χρήστη** αντί του χώρου πυρήνα, μειώνοντας τον κίνδυνο από ανατροπή του συστήματος λόγω δυσλειτουργίας της επέκτασης.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Υπάρχουν τρία είδη επεκτάσεων συστήματος: οι επεκτάσεις **DriverKit**, οι επεκτάσεις **Network** και οι επεκτάσεις **Endpoint Security**.

### **Επεκτάσεις DriverKit**

Το DriverKit είναι μια αντικατάσταση των επεκτάσεων πυρήνα που **παρέχουν υποστήριξη υλικού**. Επιτρέπει στους οδηγούς συσκευής (όπως οι οδηγοί USB, Serial, NIC και HID) να εκτελούνται στον χώρο χρήστη αντί του χώρου πυρήνα. Το πλαίσιο DriverKit περιλαμβάνει **εκδόσεις χώρου χρήστη ορισμένων κλάσεων I/O Kit**, και ο πυρήνας προωθεί τα κανονικά γεγονότα I/O Kit στον χώρο χρήστη, προσφέροντας ένα ασφαλές περιβάλλον για την εκτέλεση αυτών των οδηγών.

### **Επεκτάσεις δικτύου**

Οι επεκτάσεις δικτύου παρέχουν τη δυνατότητα προσαρμογής της συμπεριφοράς του δικτύου. Υπάρχουν αρκετοί τύποι επεκτάσεων δικτύου:

* **App Proxy**: Χρησιμοποιείται για τη δημιουργία ενός πελάτη VPN που υλοποιεί ένα πρωτόκολλο VPN με ροή. Αυτό σημαίνει ότι χειρίζεται την κίνηση του δικτύου με βάση τις συνδέσεις (ή τις ροές) και όχι τα μεμονωμένα πακέτα.
* **Packet Tunnel**: Χρησιμοποιείται για τη δημιουργία ενός πελάτη VPN που υλοποιεί ένα πρωτόκολλο VPN με πακέτα. Αυτό σημαίνει ότι χειρίζεται την κίνηση του δικτύου με βάση τα μεμονωμένα πακέτα.
* **Filter Data**: Χρησιμοποιείται για το φιλτράρισμα των "ροών" του δικτύου. Μπορεί να παρακολουθεί ή να τροποποιεί δεδομένα δικτύου σε επίπεδο ροής.
* **Filter Packet**: Χρησιμοποιείται για το φιλτράρισμα των μεμονωμένων πακέτων δικτύου. Μπορεί να παρακολουθεί ή να τροποποιεί δεδομένα δικτύου σε επίπεδο πακέτου.
* **DNS Proxy**: Χρησιμοποιείται για τη δημιουργία ενός προσαρμοσμένου παροχέα DNS. Μπορεί να χρησιμοποιηθεί για την παρακολούθηση ή την τροποποίηση αιτημάτων και απαντήσεων DNS.

## Πλαίσιο ασφαλείας τερματικού σημείου

Το πλαίσιο ασφαλείας τερματικού σημείου είναι ένα πλαίσιο που παρέχεται από την Apple στο macOS και παρέχει ένα σύνολο διεπαφών προγραμματισμού εφαρμογών (APIs) για την ασφάλεια του συστήματος. Προορίζεται για χρήση από **προμηθευτές ασφάλειας και προγραμματιστές για τη δημιουρ
```bash
tccutil reset All
```
Για **περισσότερες πληροφορίες** σχετικά με αυτήν την παράκαμψη και σχετικές, ελέγξτε την ομιλία [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Στο τέλος, αυτό διορθώθηκε δίνοντας τη νέα άδεια **`kTCCServiceEndpointSecurityClient`** στην εφαρμογή ασφαλείας που διαχειρίζεται ο **`tccd`**, έτσι ώστε το `tccutil` να μην καθαρίζει τις άδειές της, εμποδίζοντάς την από το να εκτελεστεί.

## Αναφορές

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
