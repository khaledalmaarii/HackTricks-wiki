# Kerberos Double Hop Problem

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduction

Το πρόβλημα "Double Hop" του Kerberos εμφανίζεται όταν ένας επιτιθέμενος προσπαθεί να χρησιμοποιήσει **Kerberos authentication across two** **hops**, για παράδειγμα χρησιμοποιώντας **PowerShell**/**WinRM**.

Όταν συμβαίνει μια **authentication** μέσω **Kerberos**, οι **credentials** **δεν** αποθηκεύονται στη **μνήμη.** Επομένως, αν εκτελέσετε το mimikatz **δεν θα βρείτε credentials** του χρήστη στη μηχανή ακόμα και αν εκτελεί διαδικασίες.

Αυτό συμβαίνει επειδή όταν συνδέεστε με Kerberos αυτά είναι τα βήματα:

1. Ο Χρήστης1 παρέχει credentials και ο **domain controller** επιστρέφει ένα Kerberos **TGT** στον Χρήστη1.
2. Ο Χρήστης1 χρησιμοποιεί το **TGT** για να ζητήσει ένα **service ticket** για να **συνδεθεί** με τον Server1.
3. Ο Χρήστης1 **συνδέεται** με τον **Server1** και παρέχει το **service ticket**.
4. Ο **Server1** **δεν** έχει **credentials** του Χρήστη1 αποθηκευμένα ή το **TGT** του Χρήστη1. Επομένως, όταν ο Χρήστης1 από τον Server1 προσπαθεί να συνδεθεί σε έναν δεύτερο server, **δεν μπορεί να αυθεντικοποιηθεί**.

### Unconstrained Delegation

Αν είναι ενεργοποιημένη η **unconstrained delegation** στον υπολογιστή, αυτό δεν θα συμβεί καθώς ο **Server** θα **λάβει** ένα **TGT** κάθε χρήστη που τον προσπελάσει. Επιπλέον, αν χρησιμοποιηθεί η unconstrained delegation, πιθανώς μπορείτε να **συμβιβάσετε τον Domain Controller** από αυτό.\
[**Περισσότερες πληροφορίες στη σελίδα της unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Ένας άλλος τρόπος για να αποφευχθεί αυτό το πρόβλημα, ο οποίος είναι [**ιδιαίτερα ανασφαλής**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), είναι ο **Credential Security Support Provider**. Από τη Microsoft:

> Η αυθεντικοποίηση CredSSP αναθέτει τα credentials του χρήστη από τον τοπικό υπολογιστή σε έναν απομακρυσμένο υπολογιστή. Αυτή η πρακτική αυξάνει τον κίνδυνο ασφαλείας της απομακρυσμένης λειτουργίας. Αν ο απομακρυσμένος υπολογιστής συμβιβαστεί, όταν τα credentials μεταβιβάζονται σε αυτόν, τα credentials μπορούν να χρησιμοποιηθούν για τον έλεγχο της δικτυακής συνεδρίας.

Συνιστάται έντονα να είναι απενεργοποιημένο το **CredSSP** σε παραγωγικά συστήματα, ευαίσθητα δίκτυα και παρόμοια περιβάλλοντα λόγω ανησυχιών ασφαλείας. Για να προσδιορίσετε αν είναι ενεργοποιημένο το **CredSSP**, μπορεί να εκτελεστεί η εντολή `Get-WSManCredSSP`. Αυτή η εντολή επιτρέπει τον **έλεγχο της κατάστασης του CredSSP** και μπορεί να εκτελεστεί ακόμη και απομακρυσμένα, εφόσον είναι ενεργοποιημένο το **WinRM**.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Για να αντιμετωπιστεί το πρόβλημα του διπλού hop, παρουσιάζεται μια μέθοδος που περιλαμβάνει ένα εσωτερικό `Invoke-Command`. Αυτό δεν λύνει το πρόβλημα άμεσα αλλά προσφέρει μια λύση χωρίς να απαιτούνται ειδικές ρυθμίσεις. Η προσέγγιση επιτρέπει την εκτέλεση μιας εντολής (`hostname`) σε έναν δευτερεύοντα διακομιστή μέσω μιας εντολής PowerShell που εκτελείται από μια αρχική επιτιθέμενη μηχανή ή μέσω μιας προηγουμένως καθορισμένης PS-Session με τον πρώτο διακομιστή. Να πώς γίνεται:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Εναλλακτικά, προτείνεται η δημιουργία μιας PS-Session με τον πρώτο διακομιστή και η εκτέλεση του `Invoke-Command` χρησιμοποιώντας το `$cred` για την κεντρικοποίηση των εργασιών.

### Εγγραφή Ρυθμίσεων PSSession

Μια λύση για την παράκαμψη του προβλήματος διπλού άλματος περιλαμβάνει τη χρήση του `Register-PSSessionConfiguration` με το `Enter-PSSession`. Αυτή η μέθοδος απαιτεί μια διαφορετική προσέγγιση από το `evil-winrm` και επιτρέπει μια συνεδρία που δεν υποφέρει από τον περιορισμό του διπλού άλματος.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Για τοπικούς διαχειριστές σε έναν ενδιάμεσο στόχο, η προώθηση θυρών επιτρέπει την αποστολή αιτημάτων σε έναν τελικό διακομιστή. Χρησιμοποιώντας το `netsh`, μπορεί να προστεθεί ένας κανόνας για την προώθηση θυρών, μαζί με έναν κανόνα τείχους προστασίας των Windows για να επιτραπεί η προωθημένη θύρα.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` μπορεί να χρησιμοποιηθεί για την προώθηση αιτημάτων WinRM, ενδεχομένως ως μια λιγότερο ανιχνεύσιμη επιλογή αν η παρακολούθηση PowerShell είναι ανησυχία. Η παρακάτω εντολή δείχνει τη χρήση του:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Η εγκατάσταση του OpenSSH στον πρώτο διακομιστή επιτρέπει μια λύση για το πρόβλημα του double-hop, ιδιαίτερα χρήσιμη για σενάρια jump box. Αυτή η μέθοδος απαιτεί εγκατάσταση και ρύθμιση του OpenSSH για Windows μέσω CLI. Όταν ρυθμιστεί για Αυθεντικοποίηση με Κωδικό, αυτό επιτρέπει στον ενδιάμεσο διακομιστή να αποκτήσει ένα TGT εκ μέρους του χρήστη.

#### Βήματα Εγκατάστασης OpenSSH

1. Κατεβάστε και μεταφέρετε το τελευταίο zip του OpenSSH στον στόχο διακομιστή.
2. Αποσυμπιέστε και εκτελέστε το σενάριο `Install-sshd.ps1`.
3. Προσθέστε έναν κανόνα τείχους προστασίας για να ανοίξετε την πόρτα 22 και επαληθεύστε ότι οι υπηρεσίες SSH εκτελούνται.

Για να επιλυθούν τα σφάλματα `Connection reset`, οι άδειες ενδέχεται να χρειαστεί να ενημερωθούν ώστε να επιτρέπουν σε όλους την πρόσβαση για ανάγνωση και εκτέλεση στον κατάλογο του OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Αναφορές

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
