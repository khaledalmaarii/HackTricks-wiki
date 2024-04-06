# SmbExec/ScExec

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πώς λειτουργεί

Το **Smbexec** είναι ένα εργαλείο που χρησιμοποιείται για απομακρυσμένη εκτέλεση εντολών σε συστήματα Windows, παρόμοιο με το **Psexec**, αλλά αποφεύγει την τοποθέτηση κακόβουλων αρχείων στο στόχο.

### Κύρια σημεία για το **SMBExec**

- Λειτουργεί δημιουργώντας ένα προσωρινό υπηρεσία (για παράδειγμα, "BTOBTO") στον στόχο για να εκτελέσει εντολές μέσω cmd.exe (%COMSPEC%), χωρίς να αποθέτει κανένα δυαδικό αρχείο.
- Παρά την αθόρυβη προσέγγισή του, δημιουργεί αρχεία καταγραφής γεγονότων για κάθε εκτελεσμένη εντολή, προσφέροντας μια μορφή μη διαδραστικού "κέλυφους".
- Η εντολή για σύνδεση χρησιμοποιώντας το **Smbexec** φαίνεται κάπως έτσι:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Εκτέλεση Εντολών χωρίς Δυαδικά Αρχεία

- Το **Smbexec** επιτρέπει την άμεση εκτέλεση εντολών μέσω των binPaths των υπηρεσιών, εξαλείφοντας την ανάγκη για φυσικά δυαδικά αρχεία στον στόχο.
- Αυτή η μέθοδος είναι χρήσιμη για την εκτέλεση μιας εντολής μια φορά σε έναν στόχο Windows. Για παράδειγμα, συνδυάζοντάς το με το εργαλείο `web_delivery` του Metasploit, επιτρέπει την εκτέλεση ενός αντίστροφου Meterpreter payload που στοχεύει στο PowerShell.
- Δημιουργώντας μια απομακρυσμένη υπηρεσία στον υπολογιστή του επιτιθέμενου με το binPath που ορίζει την εκτέλεση της παρεχόμενης εντολής μέσω του cmd.exe, είναι δυνατή η επιτυχής εκτέλεση του payload, επιτυγχάνοντας την επικοινωνία και την εκτέλεση του payload με τον ακροατή του Metasploit, ακόμα κι αν παρουσιαστούν σφάλματα απόκρισης της υπηρεσίας.

### Παράδειγμα Εντολών

Η δημιουργία και η εκκίνηση της υπηρεσίας μπορεί να γίνει με τις παρακάτω εντολές:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Για περισσότερες λεπτομέρειες, ελέγξτε [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Αναφορές
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
