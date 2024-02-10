# Πρόβλημα Διπλής Αναπήδησης Kerberos

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) **στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Εισαγωγή

Το πρόβλημα "Double Hop" του Kerberos εμφανίζεται όταν ένας επιτιθέμενος προσπαθεί να χρησιμοποιήσει **πιστοποίηση Kerberos μέσω δύο** **αναπηδήσεων**, για παράδειγμα χρησιμοποιώντας **PowerShell**/**WinRM**.

Όταν γίνεται μια **πιστοποίηση** μέσω **Kerberos**, οι **πιστοποιητικά** **δεν αποθηκεύονται** στην **μνήμη**. Επομένως, αν εκτελέσετε το mimikatz δεν θα βρείτε τα πιστοποιητικά του χρήστη στον υπολογιστή, ακόμα κι αν εκτελεί διεργασίες.

Αυτό συμβαίνει επειδή όταν συνδέεστε με το Kerberos ακολουθούνται τα εξής βήματα:

1. Ο χρήστης 1 παρέχει τα διαπιστευτήριά του και ο ελεγκτής του τομέα επιστρέφει ένα **TGT** Kerberos στον χρήστη 1.
2. Ο χρήστης 1 χρησιμοποιεί το **TGT** για να ζητήσει ένα **εισιτήριο υπηρεσίας** για να **συνδεθεί** στον Διακομιστή 1.
3. Ο χρήστης 1 **συνδέεται** στον **Διακομιστή 1** και παρέχει το **εισιτήριο υπηρεσίας**.
4. Ο **Διακομιστής 1** δεν έχει τα **πιστοποιητικά** του χρήστη 1 αποθηκευμένα ούτε το **TGT** του χρήστη 1. Επομένως, όταν ο χρήστης 1 από τον Διακομιστή 1 προσπαθεί να συνδεθεί σε έναν δεύτερο διακομιστή, δεν μπορεί να πιστοποιηθεί.

### Απεριόριστη Αναπηδηση

Εάν η **απεριόριστη αναπηδηση** είναι ενεργοποιημένη στον υπολογιστή, αυτό δεν θα συμβεί, καθώς ο **Διακομιστής** θα **λάβει** ένα **TGT** από κάθε χρήστη που τον προσπελαύνει. Επιπλέον, εάν χρησιμοποιείται απεριόριστη αναπηδηση, πιθανόν να μπορείτε να **θέσετε σε κίνδυνο τον ελεγκτή του τομέα** από αυτό.\
[**Περισσότερες πληροφορίες στη σελίδα απεριόριστης αναπηδησης**](unconstrained-delegation.md).

### CredSSP

Ένας άλλος τρόπος να αποφευχθεί αυτό το πρόβλημα, ο οποίος είναι [**σημαντικά ανασφαλής**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), είναι ο **Credential Security Support Provider (CredSSP)**. Από τη Microsoft:

> Η πιστοποίηση CredSSP αναθέτει τα διαπιστευτήρια του χρήστη από τον τοπικό υπολογιστή σε έναν απομακρυσμένο υπολογιστή. Αυτή η πρακτική αυξάνει τον κίνδυνο ασφαλείας της απομακρυσμένης λειτουργίας. Εάν ο απομακρυσμένος υπολογιστής διατρέχει κίνδυνο και του περάσουν διαπιστευτήρια, τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν για να ελέγξουν τη δικτυακή συνεδρία.

Συνιστάται ιδιαίτερα να απενεργοποιηθεί το **CredSSP** σε συστήματα παραγωγής, ευαίσθητα δίκτυα και παρόμοια περιβάλλοντα λόγω ανησυχιών ασφαλείας. Για να διαπιστωθεί εάν το **CredSSP** είναι ενεργοποιημένο, μπορεί να εκτελεστεί η εντολή `Get-WSManCredSSP`. Αυτή η εντολή επιτρέπει τον **έλεγχο της κατάστασης του CredSSP** και μπορεί ακόμα να εκτελεστεί απομακρυσμένα, εφόσον είναι ενεργοποιημένο το **WinRM**.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Εναλλακτικές λύσεις

### Εκτέλεση Εντολής

Για να αντιμετωπιστεί το πρόβλημα του διπλού hop, παρουσιάζεται μια μέθοδος που εμπλέκει τη χρήση της εντολής `Invoke-Command`. Αυτό δεν επιλύει το πρόβλημα απευθείας, αλλά προσφέρει μια εναλλακτική λύση χωρίς να απαιτεί ειδικές ρυθμίσεις. Η προσέγγιση αυτή επιτρέπει την εκτέλεση μιας εντολής (`hostname`) σε ένα δευτερεύοντα διακομιστή μέσω μιας εντολής PowerShell που εκτελείται από μια αρχική μηχανή επίθεσης ή μέσω μιας προηγουμένως δημιουργημένης PS-Session με τον πρώτο διακομιστή. Ακολουθεί ο τρόπος εκτέλεσης:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Εναλλακτικά, προτείνεται η δημιουργία μιας συνεδρίας PS-Session με τον πρώτο διακομιστή και η εκτέλεση της εντολής `Invoke-Command` χρησιμοποιώντας το `$cred` για την κεντρική διαχείριση των εργασιών.

### Εγγραφή της διαμόρφωσης PSSession

Μια λύση για την απόφυγη του προβλήματος του διπλού hop είναι η χρήση της εντολής `Register-PSSessionConfiguration` με την `Enter-PSSession`. Αυτή η μέθοδος απαιτεί μια διαφορετική προσέγγιση από το `evil-winrm` και επιτρέπει μια συνεδρία που δεν υπόκειται στον περιορισμό του διπλού hop.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Προώθηση θύρας (Port Forwarding)

Για τους τοπικούς διαχειριστές σε έναν ενδιάμεσο στόχο, η προώθηση θύρας επιτρέπει την αποστολή αιτημάτων σε έναν τελικό διακομιστή. Χρησιμοποιώντας το `netsh`, μπορεί να προστεθεί μια κανόνα για την προώθηση θύρας, μαζί με έναν κανόνα της τείχους προστασίας των Windows για να επιτραπεί η προώθηση της θύρας.
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

Η εγκατάσταση του OpenSSH στον πρώτο διακομιστή επιτρέπει μια παράκαμψη για το πρόβλημα του διπλού άλματος, ιδιαίτερα χρήσιμη για σενάρια με jump box. Αυτή η μέθοδος απαιτεί την εγκατάσταση και τη ρύθμιση του OpenSSH για τα Windows μέσω της γραμμής εντολών. Όταν ρυθμιστεί για την Επαλήθευση με κωδικό πρόσβασης, αυτό επιτρέπει στον ενδιάμεσο διακομιστή να λάβει ένα TGT εκ μέρους του χρήστη.

#### Βήματα εγκατάστασης του OpenSSH

1. Κατεβάστε και μετακινήστε το πιο πρόσφατο αρχείο zip κυκλοφορίας του OpenSSH στον στόχο διακομιστή.
2. Αποσυμπιέστε το αρχείο και εκτελέστε το σενάριο `Install-sshd.ps1`.
3. Προσθέστε μια κανόνα του τείχους προκειμένου να ανοίξετε τη θύρα 22 και επαληθεύστε ότι οι υπηρεσίες SSH εκτελούνται.

Για την επίλυση σφαλμάτων `Connection reset`, ίσως χρειαστεί να ενημερωθούν οι άδειες πρόσβασης προκειμένου να επιτραπεί σε όλους την ανάγνωση και την εκτέλεση στον κατάλογο του OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Αναφορές

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
