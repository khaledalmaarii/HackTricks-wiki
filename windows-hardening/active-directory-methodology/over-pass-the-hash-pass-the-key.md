# Υπέρβαση του Hash/Παράδοση του Κλειδιού

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks για το AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Υπέρβαση του Hash/Παράδοση του Κλειδιού (PTK)

Η επίθεση **Υπέρβαση του Hash/Παράδοση του Κλειδιού (PTK)** σχεδιάστηκε για περιβάλλοντα όπου το παραδοσιακό πρωτόκολλο NTLM είναι περιορισμένο και η πιστοποίηση Kerberos έχει προτεραιότητα. Αυτή η επίθεση εκμεταλλεύεται το hash NTLM ή τα κλειδιά AES ενός χρήστη για να ζητήσει εισιτήρια Kerberos, επιτρέποντας την μη εξουσιοδοτημένη πρόσβαση σε πόρους εντός ενός δικτύου.

Για την εκτέλεση αυτής της επίθεσης, το αρχικό βήμα περιλαμβάνει την απόκτηση του hash NTLM ή του κωδικού πρόσβασης του λογαριασμού του στόχου. Μετά την ασφαλή απόκτηση αυτών των πληροφοριών, μπορεί να ληφθεί ένα εισιτήριο παραχώρησης εισιτηρίων (TGT) για τον λογαριασμό, επιτρέποντας στον εισβολέα να έχει πρόσβαση σε υπηρεσίες ή μηχανές στις οποίες ο χρήστης έχει δικαιώματα.

Η διαδικασία μπορεί να ξεκινήσει με τις ακόλουθες εντολές:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Για σενάρια που απαιτούν AES256, η επιλογή `-aesKey [AES key]` μπορεί να χρησιμοποιηθεί. Επιπλέον, το αποκτηθέν εισιτήριο μπορεί να χρησιμοποιηθεί με διάφορα εργαλεία, συμπεριλαμβανομένων των smbexec.py ή wmiexec.py, διευρύνοντας το πεδίο της επίθεσης.

Τυπικά, τα προβλήματα που αντιμετωπίζονται όπως _PyAsn1Error_ ή _Το KDC δεν μπορεί να βρει το όνομα_ λύνονται με την ενημέρωση της βιβλιοθήκης Impacket ή τη χρήση του ονόματος του υπολογιστή αντί για τη διεύθυνση IP, εξασφαλίζοντας συμβατότητα με το Kerberos KDC.

Μια εναλλακτική ακολουθία εντολών χρησιμοποιώντας το Rubeus.exe αποδεικνύει ένα άλλο προσόν αυτής της τεχνικής:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Αυτή η μέθοδος αντικατοπτρίζει την προσέγγιση **Pass the Key**, με έμφαση στην απαγωγή και χρήση του εισιτηρίου απευθείας για σκοπούς πιστοποίησης. Είναι κρίσιμο να σημειωθεί ότι η έναρξη μιας αίτησης TGT ενεργοποιεί το συμβάν `4768: Ζητήθηκε ένα εισιτήριο πιστοποίησης Kerberos (TGT)`, σημαίνοντας μια χρήση RC4-HMAC από προεπιλογή, αν και τα μοντέρνα συστήματα Windows προτιμούν το AES256.

Για να συμμορφωθείτε με τη λειτουργική ασφάλεια και να χρησιμοποιήσετε το AES256, μπορεί να εφαρμοστεί η ακόλουθη εντολή:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Αναφορές

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε τη **εταιρεία σας διαφημισμένη στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στη **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
