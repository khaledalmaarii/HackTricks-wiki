# Φυσικές Επιθέσεις

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

## Ανάκτηση Κωδικού BIOS και Ασφάλεια Συστήματος

**Η επαναφορά του BIOS** μπορεί να επιτευχθεί με διάφορους τρόπους. Οι περισσότερες μητρικές πλακέτες περιλαμβάνουν μια **μπαταρία** που, όταν αφαιρεθεί για περίπου **30 λεπτά**, θα επαναφέρει τις ρυθμίσεις του BIOS, συμπεριλαμβανομένου του κωδικού πρόσβασης. Εναλλακτικά, μπορεί να ρυθμιστεί μια **γέφυρα στη μητρική πλακέτα** για να επαναφέρει αυτές τις ρυθμίσεις συνδέοντας συγκεκριμένες ακίδες.

Για καταστάσεις όπου οι υλικές ρυθμίσεις δεν είναι δυνατές ή πρακτικές, τα **λογισμικά εργαλεία** προσφέρουν μια λύση. Η εκτέλεση ενός συστήματος από ένα **Live CD/USB** με διανομές όπως το **Kali Linux** παρέχει πρόσβαση σε εργαλεία όπως το **_killCmos_** και το **_CmosPWD_**, τα οποία μπορούν να βοηθήσουν στην ανάκτηση του κωδικού BIOS.

Σε περιπτώσεις όπου ο κωδικός BIOS είναι άγνωστος, η λανθασμένη εισαγωγή του **τρεις φορές** θα έχει συνήθως ως αποτέλεσμα έναν κωδικό σφάλματος. Αυτός ο κωδικός μπορεί να χρησιμοποιηθεί σε ιστοσελίδες όπως το [https://bios-pw.org](https://bios-pw.org) για να ανακτηθεί πιθανώς ένας χρήσιμος κωδικός.

### Ασφάλεια UEFI

Για σύγχρονα συστήματα που χρησιμοποιούν **UEFI** αντί για παραδοσιακό BIOS, το εργαλείο **chipsec** μπορεί να χρησιμοποιηθεί για την ανάλυση και την τροποποίηση των ρυθμίσεων UEFI, συμπεριλαμβανομένης της απενεργοποίησης του **Secure Boot**. Αυτό μπορεί να επιτευχθεί με την ακόλουθη εντολή:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Ανάλυση RAM και Επιθέσεις Ψυχρού Εκκίνησης

Η RAM διατηρεί δεδομένα για λίγο μετά την διακοπή ρεύματος, συνήθως για **1 έως 2 λεπτά**. Αυτή η επιμονή μπορεί να παραταθεί σε **10 λεπτά** με την εφαρμογή ψυχρών ουσιών, όπως το υγρό άζωτο. Κατά τη διάρκεια αυτής της παρατεταμένης περιόδου, μπορεί να δημιουργηθεί μια **λήψη μνήμης** χρησιμοποιώντας εργαλεία όπως το **dd.exe** και το **volatility** για ανάλυση.

### Επιθέσεις Άμεσης Πρόσβασης Μνήμης (DMA)

**INCEPTION** είναι ένα εργαλείο σχεδιασμένο για **φυσική χειραγώγηση μνήμης** μέσω DMA, συμβατό με διεπαφές όπως το **FireWire** και το **Thunderbolt**. Επιτρέπει την παράκαμψη διαδικασιών σύνδεσης με την επιδιόρθωση της μνήμης για να αποδεχτεί οποιονδήποτε κωδικό πρόσβασης. Ωστόσο, είναι αναποτελεσματικό κατά των συστημάτων **Windows 10**.

### Live CD/USB για Πρόσβαση στο Σύστημα

Η αλλαγή συστημικών δυαδικών αρχείων όπως το **_sethc.exe_** ή το **_Utilman.exe_** με ένα αντίγραφο του **_cmd.exe_** μπορεί να παρέχει μια γραμμή εντολών με δικαιώματα συστήματος. Εργαλεία όπως το **chntpw** μπορούν να χρησιμοποιηθούν για την επεξεργασία του αρχείου **SAM** μιας εγκατάστασης Windows, επιτρέποντας αλλαγές κωδικών πρόσβασης.

**Kon-Boot** είναι ένα εργαλείο που διευκολύνει την είσοδο σε συστήματα Windows χωρίς να γνωρίζετε τον κωδικό πρόσβασης, τροποποιώντας προσωρινά τον πυρήνα των Windows ή το UEFI. Περισσότερες πληροφορίες μπορείτε να βρείτε στο [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Διαχείριση Χαρακτηριστικών Ασφαλείας των Windows

#### Συντομεύσεις Εκκίνησης και Ανάκτησης

- **Supr**: Πρόσβαση στις ρυθμίσεις BIOS.
- **F8**: Είσοδος σε λειτουργία Ανάκτησης.
- Πατώντας **Shift** μετά την μπάνερ των Windows μπορεί να παρακαμφθεί η αυτόματη σύνδεση.

#### BAD USB Συσκευές

Συσκευές όπως το **Rubber Ducky** και το **Teensyduino** χρησιμεύουν ως πλατφόρμες για τη δημιουργία **bad USB** συσκευών, ικανών να εκτελούν προκαθορισμένα payloads όταν συνδεθούν σε έναν υπολογιστή στόχο.

#### Αντίγραφο Σκιάς Όγκου

Δικαιώματα διαχειριστή επιτρέπουν τη δημιουργία αντιγράφων ευαίσθητων αρχείων, συμπεριλαμβανομένου του αρχείου **SAM**, μέσω του PowerShell.

### Παράκαμψη Κρυπτογράφησης BitLocker

Η κρυπτογράφηση BitLocker μπορεί ενδεχομένως να παρακαμφθεί εάν ο **κωδικός ανάκτησης** βρεθεί μέσα σε ένα αρχείο λήψης μνήμης (**MEMORY.DMP**). Εργαλεία όπως το **Elcomsoft Forensic Disk Decryptor** ή το **Passware Kit Forensic** μπορούν να χρησιμοποιηθούν για αυτό το σκοπό.

### Κοινωνική Μηχανική για Προσθήκη Κωδικού Ανάκτησης

Ένας νέος κωδικός ανάκτησης BitLocker μπορεί να προστεθεί μέσω τακτικών κοινωνικής μηχανικής, πείθοντας έναν χρήστη να εκτελέσει μια εντολή που προσθέτει έναν νέο κωδικό ανάκτησης που αποτελείται από μηδενικά, απλοποιώντας έτσι τη διαδικασία αποκρυπτογράφησης.

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
