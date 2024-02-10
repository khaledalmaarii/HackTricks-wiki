# Έλεγχος Προνομίων Ανόδου - Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετέχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετάσχετε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) διακομιστή για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς αμοιβών ευρημάτων!

**Εισαγωγή στο Χάκινγκ**\
Ασχοληθείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις νεότερες αμοιβές ευρημάτων που ξεκινούν και τις κρίσιμες ενημερώσεις των πλατφορμών

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **και αρχίστε να συνεργάζεστε με τους κορυφαίους χάκερ σήμερα!**

### **Καλύτερο εργαλείο για την αναζήτηση διανομών εκμετάλλευσης προνομίων σε Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](privilege-escalation/#system-information)

* [ ] Λάβετε τις **πληροφορίες του ΛΣ**
* [ ] Ελέγξτε το [**PATH**](privilege-escalation/#path), οποιοδήποτε **εγγράψιμο φάκελο**;
* [ ] Ελέγξτε τις [**μεταβλητές περιβάλλοντος**](privilege-escalation/#env-info), οποιαδήποτε ευαίσθητη λεπτομέρεια;
* [ ] Αναζήτηση για [**εκμεταλλεύσεις πυρήνα**](privilege-escalation/#kernel-exploits) **χρησιμοποιώντας σενάρια** (DirtyCow;)
* [ ] **Ελέγξτε** αν η [**έκδοση του sudo είναι ευάλωτη**](privilege-escalation/#sudo-version)
* [ ] [**Αποτυχία επαλήθευσης υπογραφής Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Περισσότερη αναγνώριση του συστήματος ([ημερομηνία, στατιστικά συστήματος, πληροφορίες CPU, εκτυπωτές](privilege-escalation/#more-system-enumeration))
* [ ] [Αναγνωρίστε περισσότερες αμύνες](privilege-escalation/#enumerate-possible-defenses)

### [Δίσκοι](privilege-escalation/#drives)

* [ ] Λίστα με τους **προσαρτημένους** δίσκους
* [ ] **Οποιοσδήποτε μη προσαρτημένος δίσκος;**
* [ ] **Ο
### [Δυνατότητες](privilege-escalation/#capabilities)

* [ ] Έχει οποιοδήποτε εκτελέσιμο οποιαδήποτε **απροσδόκητη δυνατότητα**;

### [ACLs](privilege-escalation/#acls)

* [ ] Έχει οποιοδήποτε αρχείο οποιαδήποτε **απροσδόκητη ACL**;

### [Ανοιχτές συνεδρίες κέλυφους](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Ενδιαφέρουσες τιμές ρυθμίσεων SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Ενδιαφέροντα αρχεία](privilege-escalation/#interesting-files)

* [ ] **Αρχεία προφίλ** - Διαβάζουν ευαίσθητα δεδομένα; Γράφουν για προνομιούχο ανέβασμα;
* [ ] **Αρχεία passwd/shadow** - Διαβάζουν ευαίσθητα δεδομένα; Γράφουν για προνομιούχο ανέβασμα;
* [ ] **Έλεγξε συνήθως ενδιαφέρουσες φακέλους** για ευαίσθητα δεδομένα
* [ ] **Παράξενη τοποθεσία/Αρχεία που ανήκουν,** μπορεί να έχετε πρόσβαση ή να αλλάξετε εκτελέσιμα αρχεία
* [ ] **Τροποποιήθηκαν** τις τελευταίες λεπτές
* [ ] **Αρχεία βάσης δεδομένων Sqlite**
* [ ] **Κρυφά αρχεία**
* [ ] **Σενάρια/Δυαδικά στην PATH**
* [ ] **Αρχεία ιστού** (κωδικοί πρόσβασης;)
* [ ] **Αντίγραφα ασφαλείας**;
* [ ] **Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης**: Χρησιμοποιήστε **Linpeas** και **LaZagne**
* [ ] **Γενική αναζήτηση**

### [**Εγγράψιμα αρχεία**](privilege-escalation/#writable-files)

* [ ] **Τροποποίηση βιβλιοθήκης python** για εκτέλεση αυθαίρετων εντολών;
* [ ] Μπορείτε να **τροποποιήσετε αρχεία καταγραφής**; Εκμετάλλευση Logtotten
* [ ] Μπορείτε να **τροποποιήσετε το /etc/sysconfig/network-scripts/**; Εκμετάλλευση Centos/Redhat
* [ ] Μπορείτε να [**γράψετε σε αρχεία ini, int.d, systemd ή rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d);

### [**Άλλα κόλπα**](privilege-escalation/#other-tricks)

* [ ] Μπορείτε να [**καταχραστείτε το NFS για επέκταση προνομιών**](privilege-escalation/#nfs-privilege-escalation);
* [ ] Χρειάζεστε να [**δραπετεύσετε από έναν περιοριστικό κέλυφος**](privilege-escalation/#escaping-from-restricted-shells);

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στον διακομιστή [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Hacking**\
Ασχοληθείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του χάκινγκ

**Ειδήσεις Hack σε πραγματικό χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις νεότερες ανακοινώσεις για τις νέες ανταμοιβές ευρετηρίου σφαλμάτων και τις κρίσιμες ενημερώσεις της πλατφόρμας

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **και αρχίστε να συνεργάζεστε με τους κορυφαίους χάκερ σήμερα!**

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετέχετε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
