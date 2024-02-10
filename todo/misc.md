<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


Σε μια απάντηση ping TTL:\
127 = Windows\
254 = Cisco\
Για τα υπόλοιπα, κάποια είναι Linux

$1$- md5\
$2$or $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Αν δεν γνωρίζετε τι χρησιμοποιείται πίσω από ένα υπηρεσία, προσπαθήστε να κάνετε ένα αίτημα HTTP GET.

**Σάρωση UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Στέλνεται ένα κενό πακέτο UDP σε ένα συγκεκριμένο θύρο. Εάν η θύρα UDP είναι ανοιχτή, δεν στέλνεται απάντηση από τη μηχανή προορισμού. Εάν η θύρα UDP είναι κλειστή, θα πρέπει να σταλεί ένα πακέτο ICMP με μη δυνατή θύρα από τη μηχανή προορισμού.\


Η σάρωση θυρών UDP συχνά δεν είναι αξιόπιστη, καθώς τα τείχη προστασίας και οι δρομολογητές μπορεί να απορρίπτουν τα πακέτα ICMP. Αυτό μπορεί να οδηγήσει σε λανθασμένα θετικά αποτελέσματα στη σάρωσή σας και θα βλέπετε συχνά σάρωση θυρών UDP που δείχνει όλες τις θύρες UDP ανοιχτές σε μια σαρωμένη μηχανή.\
o Οι περισσότεροι σαρωτές θυρών δεν σαρώνουν όλες τις διαθέσιμες θύρες και συνήθως έχουν μια προκαθορισμένη λίστα\
από "ενδιαφέρουσες θύρες" που σαρώνονται.

# CTF - Κόλπα

Στα **Windows** χρησιμοποιήστε το **Winzip** για να αναζητήσετε αρχεία.\
**Εναλλακτικά δεδομένα ροής**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Κρυπτογραφία

**featherduster**\


**Βασική64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Βασική32**(5 —>8) —> A…Z, 2…7\
**Βασική85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Ξεκινά με "_begin \<mode> \<filename>_" και περίεργους χαρακτήρες\
**Xxencoding** --> Ξεκινά με "_begin \<mode> \<filename>_" και B64\
\
**Vigenere** (ανάλυση συχνότητας) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (μετατόπιση χαρακτήρων) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Απόκρυψη μηνυμάτων χρησιμοποιώντας κενά και tab

# Χαρακτήρες

%E2%80%AE => RTL Χαρακτήρας (γράφει payloads ανάποδα)


<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
