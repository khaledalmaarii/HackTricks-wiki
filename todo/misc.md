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


Σε μια απάντηση ping TTL:\
127 = Windows\
254 = Cisco\
Τα υπόλοιπα, κάποιο linux

$1$- md5\
$2$ή $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Αν δεν γνωρίζετε τι υπάρχει πίσω από μια υπηρεσία, προσπαθήστε να κάνετε ένα HTTP GET αίτημα.

**Σαρώσεις UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Ένα κενό πακέτο UDP αποστέλλεται σε μια συγκεκριμένη θύρα. Αν η θύρα UDP είναι ανοιχτή, δεν αποστέλλεται καμία απάντηση από τη στοχοθετημένη μηχανή. Αν η θύρα UDP είναι κλειστή, θα πρέπει να αποσταλεί ένα πακέτο ICMP port unreachable από τη στοχοθετημένη μηχανή.\

Η σάρωση UDP port είναι συχνά αναξιόπιστη, καθώς οι τείχοι προστασίας και οι δρομολογητές μπορεί να απορρίψουν τα πακέτα ICMP.\
Αυτό μπορεί να οδηγήσει σε ψευδώς θετικά αποτελέσματα στη σάρωσή σας, και θα βλέπετε τακτικά σάρωσεις UDP port που δείχνουν όλες τις θύρες UDP ανοιχτές σε μια σαρωμένη μηχανή.\
Οι περισσότερες σαρωτές θυρών δεν σαρώνονται όλες οι διαθέσιμες θύρες, και συνήθως έχουν μια προεπιλεγμένη λίστα “ενδιαφερόντων θυρών” που σαρώνονται.

# CTF - Κόλπα

Στο **Windows** χρησιμοποιήστε το **Winzip** για να αναζητήσετε αρχεία.\
**Εναλλακτικά δεδομένα Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Ξεκινήστε με "_begin \<mode> \<filename>_" και περίεργους χαρακτήρες\
**Xxencoding** --> Ξεκινήστε με "_begin \<mode> \<filename>_" και B64\
\
**Vigenere** (ανάλυση συχνότητας) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (μετατόπιση χαρακτήρων) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Κρύψτε μηνύματα χρησιμοποιώντας κενά και tabs

# Characters

%E2%80%AE => RTL Character (γράφει payloads ανάποδα)


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
