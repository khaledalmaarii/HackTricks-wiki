# Πρόβλημα Διπλού Άλματος στο Kerberos

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team Expert του HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Εισαγωγή

Το πρόβλημα "Διπλού Άλματος" στο Kerberos εμφανίζεται όταν ένας επιτιθέμενος προσπαθεί να χρησιμοποιήσει **επαλήθευση Kerberos σε δύο** **άλματα**, για παράδειγμα χρησιμοποιώντας **PowerShell**/**WinRM**.

Όταν μια **επαλήθευση** συμβαίνει μέσω **Kerberos**, οι **διαπιστευτήρια** **δεν** αποθηκεύονται στη **μνήμη**. Επομένως, αν εκτελέσετε το mimikatz δεν θα βρείτε τα διαπιστευτήρια του χρήστη στον υπολογιστή ακόμα κι αν εκτελεί διεργασίες.

Αυτό συμβαίνει επειδή κατά τη σύνδεση με το Kerberos αυτά είναι τα βήματα:

1. Ο Χρήστης1 παρέχει διαπιστευτήρια και το **domain controller** επιστρέφει ένα Kerberos **TGT** στον Χρήστη1.
2. Ο Χρήστης1 χρησιμοποιεί το **TGT** για να ζητήσει ένα **εισιτήριο υπηρεσίας** για να **συνδεθεί** στον Διακομιστή1.
3. Ο Χρήστης1 **συνδέεται** στον **Διακομιστή1** και παρέχει το **εισιτήριο υπηρεσίας**.
4. Ο **Διακομιστής1** **δεν** έχει τα **διαπιστευτήρια** του Χρήστη1 αποθηκευμένα ή το **TGT** του Χρήστη1. Επομένως, όταν ο Χρήστης1 από τον Διακομιστή1 προσπαθεί να συνδεθεί σε ένα δεύτερο διακομιστή, δεν μπορεί να πιστοποιηθεί.

### Απεριόριστη Ανακατεύθυνση

Αν η **απεριόριστη ανακατεύθυνση** είναι ενεργοποιημένη στον Η/Υ, αυτό δεν θα συμβεί καθώς ο **Διακομιστής** θα **λάβει** ένα **TGT** από κάθε χρήστη που έχει πρόσβαση σε αυτόν. Επιπλέον, αν χρησιμοποιείται η απεριόριστη ανακατεύθυνση, πιθανόν να μπορείτε να **θέσετε σε κίνδυνο τον ελεγκτή του τομέα** από αυτόν.\
[**Περισσότερες πληροφορίες στη σελίδα της απεριόριστης ανακατεύθυνσης**](unconstrained-delegation.md).

### CredSSP

Ένας άλλος τρόπος να αποφευχθεί αυτό το πρόβλημα, ο οποίος είναι [**εξαιρετικά ανασφαλής**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) είναι ο **Πάροχος Υποστήριξης Ασφάλειας Διαπιστευτηρίων**. Από τη Microsoft:

> Η επαλήθευση CredSSP αναθέτει τα διαπιστευτήρια του χρήστη από τον τοπικό υπολογιστή σε έναν απομακρυσμένο υπολογιστή. Αυτή η πρακτική αυξάνει τον κίνδυνο ασφάλειας της απομακρυσμένης λειτουργίας. Αν ο απομακρυσμένος υπολογιστής διαρρεύσει, όταν τα διαπιστευτήρια περνούν σε αυτόν, τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν για τον έλεγχο της δικτυακής συνεδρίας.

Συνιστάται ιδιαίτερα να απενεργοποιηθεί το **CredSSP** σε συστήματα παραγωγής, ευαίσθητα δίκτυα και παρόμοια περιβάλλοντα λόγω ανησυχιών για την ασφάλεια. Για να προσδιοριστεί εάν το **CredSSP** είναι ενεργοποιημένο, μπορεί να εκτελεστεί η εντολή `Get-WSManCredSSP`. Αυτή η εντολή επιτρέπει τον **έλεγχο της κατάστασης του CredSSP** και μπορεί ακόμα να εκτελεστεί απομακρυσμένα, εφόσον το **WinRM** είναι ενεργοποιημένο.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Παρακάμψεις

### Εκκίνηση Εντολής

Για να αντιμετωπιστεί το πρόβλημα του διπλού hop, παρουσιάζεται μια μέθοδος που περιλαμβάνει ένα εμφωλευμένο `Invoke-Command`. Αυτό δεν επιλύει το πρόβλημα απευθείας, αλλά προσφέρει μια παράκαμψη χωρίς την ανάγκη ειδικών ρυθμίσεων. Η προσέγγιση επιτρέπει την εκτέλεση μιας εντολής (`hostname`) σε ένα δευτερεύον διακομιστή μέσω μιας εντολής PowerShell που εκτελείται από μια αρχική μηχανή επίθεσης ή μέσω μιας προηγουμένως καθιερωμένης συνεδρίας PS με τον πρώτο διακομιστή. Εδώ είναι πώς γίνεται:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Καταχώρηση Ρύθμισης Συνεδρίας PS

Μια λύση για την παράκαμψη του προβλήματος διπλής ανακατεύθυνσης περιλαμβάνει τη χρήση του `Register-PSSessionConfiguration` με το `Enter-PSSession`. Αυτή η μέθοδος απαιτεί μια διαφορετική προσέγγιση από το `evil-winrm` και επιτρέπει μια συνεδρία που δεν υποφέρει από τον περιορισμό της διπλής ανακατεύθυνσης.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Προώθηση Θύρας

Για τους τοπικούς διαχειριστές σε έναν ενδιάμεσο στόχο, η προώθηση θύρας επιτρέπει την αποστολή αιτημάτων σε έναν τελικό διακομιστή. Χρησιμοποιώντας το `netsh`, μπορεί να προστεθεί μια κανόνα για την προώθηση θύρας, συνοδευόμενη από έναν κανόνα του τοίχου προστασίας των Windows για να επιτραπεί η πρόσβαση στην προωθημένη θύρα.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

Το `winrs.exe` μπορεί να χρησιμοποιηθεί για την προώθηση αιτημάτων WinRM, πιθανώς ως μια λιγότερο ανιχνεύσιμη επιλογή εάν υπάρχει ανησυχία για την παρακολούθηση του PowerShell. Η παρακάτω εντολή δείχνει τον τρόπο χρήσης του:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Η εγκατάσταση του OpenSSH στον πρώτο διακομιστή επιτρέπει μια παράκαμψη για το πρόβλημα του διπλού άλματος, ιδιαίτερα χρήσιμη για σενάρια jump box. Αυτή η μέθοδος απαιτεί εγκατάσταση και ρύθμιση του OpenSSH για τα Windows μέσω της γραμμής εντολών. Όταν ρυθμιστεί για Ελέγχου ταυτότητας με κωδικό πρόσβασης, αυτό επιτρέπει στον ενδιάμεσο διακομιστή να λάβει ένα TGT εκ μέρους του χρήστη.

#### Βήματα Εγκατάστασης OpenSSH

1. Λήψη και μετακίνηση του τελευταίου zip κυκλοφορίας του OpenSSH στον στόχο διακομιστή.
2. Αποσυμπίεση και εκτέλεση του σεναρίου `Install-sshd.ps1`.
3. Προσθήκη κανόνα του τοίχου προστασίας για το άνοιγμα της θύρας 22 και επαλήθευση ότι οι υπηρεσίες SSH λειτουργούν.

Για την επίλυση σφαλμάτων `Επαναφορά σύνδεσης`, οι άδειες πρόσβασης ενδέχεται να χρειαστεί να ενημερωθούν για να επιτραπεί σε όλους την ανάγνωση και εκτέλεση στον κατάλογο του OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Αναφορές

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή την [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
