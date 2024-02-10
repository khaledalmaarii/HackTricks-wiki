# Παράκαμψη του Hash/Παράδοση του Κλειδιού (PTK)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Η επίθεση **Overpass The Hash/Pass The Key (PTK)** σχεδιάστηκε για περιβάλλοντα όπου ο παραδοσιακός πρωτόκολλο NTLM είναι περιορισμένος και η πιστοποίηση Kerberos έχει προτεραιότητα. Αυτή η επίθεση εκμεταλλεύεται το NTLM hash ή τα κλειδιά AES ενός χρήστη για να ζητήσει εισιτήρια Kerberos, επιτρέποντας την μη εξουσιοδοτημένη πρόσβαση σε πόρους εντός ενός δικτύου.

Για να εκτελεστεί αυτή η επίθεση, το αρχικό βήμα περιλαμβάνει την απόκτηση του NTLM hash ή του κωδικού πρόσβασης του λογαριασμού του στόχου. Αφού αποκτηθεί αυτή η πληροφορία, μπορεί να ληφθεί ένα εισιτήριο παροχής εισιτηρίων (TGT) για τον λογαριασμό, επιτρέποντας στον επιτιθέμενο να έχει πρόσβαση σε υπηρεσίες ή μηχανήματα στα οποία ο χρήστης έχει δικαιώματα.

Η διαδικασία μπορεί να ξεκινήσει με τις παρακάτω εντολές:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Για περιπτώσεις που απαιτείται AES256, μπορεί να χρησιμοποιηθεί η επιλογή `-aesKey [AES κλειδί]`. Επιπλέον, το αποκτηθέν εισιτήριο μπορεί να χρησιμοποιηθεί με διάφορα εργαλεία, όπως το smbexec.py ή το wmiexec.py, διευρύνοντας το πεδίο της επίθεσης.

Συνήθως, τα προβλήματα που αντιμετωπίζονται, όπως το _PyAsn1Error_ ή το _KDC cannot find the name_, λύνονται με την ενημέρωση της βιβλιοθήκης Impacket ή τη χρήση του ονόματος του υπολογιστή αντί για τη διεύθυνση IP, εξασφαλίζοντας τη συμβατότητα με το Kerberos KDC.

Μια εναλλακτική ακολουθία εντολών χρησιμοποιώντας το Rubeus.exe αποδεικνύει μια άλλη πτυχή αυτής της τεχνικής:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Αυτή η μέθοδος αντικατοπτρίζει την προσέγγιση **Pass the Key**, με έμφαση στην κατάληψη και χρήση του εισιτηρίου απευθείας για σκοπούς πιστοποίησης. Είναι σημαντικό να σημειωθεί ότι η έναρξη μιας αίτησης TGT ενεργοποιεί το γεγονός `4768: Ζητήθηκε ένα εισιτήριο πιστοποίησης Kerberos (TGT)`, που υποδηλώνει τη χρήση RC4-HMAC από προεπιλογή, αν και οι σύγχρονα συστήματα Windows προτιμούν το AES256.

Για να συμμορφωθείτε με τη λειτουργική ασφάλεια και να χρησιμοποιήσετε το AES256, μπορεί να εφαρμοστεί η παρακάτω εντολή:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Αναφορές

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
