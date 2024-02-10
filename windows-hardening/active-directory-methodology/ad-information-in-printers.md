<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


Υπάρχουν αρκετά ιστολόγια στο Διαδίκτυο που **επισημαίνουν τους κινδύνους της αφήνοντας τους εκτυπωτές ρυθμισμένους με LDAP με προεπιλεγμένα/αδύναμα** διαπιστευτήρια σύνδεσης.\
Αυτό συμβαίνει επειδή ένας επιτιθέμενος μπορεί να **εξαπατήσει τον εκτυπωτή για να πιστοποιηθεί έναν ψεύτικο διακομιστή LDAP** (συνήθως ένα `nc -vv -l -p 444` είναι αρκετό) και να καταγράψει τα διαπιστευτήρια του εκτυπωτή **σε καθαρό κείμενο**.

Επίσης, αρκετοί εκτυπωτές θα περιέχουν **αρχεία καταγραφής με ονόματα χρηστών** ή ακόμα και θα μπορούν να **κατεβάσουν όλα τα ονόματα χρηστών** από τον ελεγκτή του τομέα.

Όλες αυτές οι **ευαίσθητες πληροφορίες** και η συνηθισμένη **έλλειψη ασφάλειας** καθιστούν τους εκτυπωτές πολύ ενδιαφέροντες για τους επιτιθέμενους.

Ορισμένα ιστολόγια για το θέμα:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Ρύθμιση Εκτυπωτή
- **Τοποθεσία**: Ο κατάλογος του διακομιστή LDAP βρίσκεται στο: `Δίκτυο > Ρύθμιση LDAP > Ρύθμιση LDAP`.
- **Συμπεριφορά**: Η διεπαφή επιτρέπει τροποποιήσεις στον διακομιστή LDAP χωρίς να ξανακαταχωρίζετε τα διαπιστευτήρια, με σκοπό την ευκολία του χρήστη αλλά προκαλώντας κινδύνους ασφάλειας.
- **Εκμετάλλευση**: Η εκμετάλλευση περιλαμβάνει την ανακατεύθυνση της διεύθυνσης του διακομιστή LDAP σε έναν ελεγχόμενο υπολογιστή και την αξιοποίηση της λειτουργίας "Έλεγχος Σύνδεσης" για την καταγραφή των διαπιστευτηρίων.

## Καταγραφή Διαπιστευτηρίων

**Για περισσότερες λεπτομερείς οδηγίες, ανατρέξτε στην αρχική [πηγή](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Μέθοδος 1: Ακροατής Netcat
Ένας απλός ακροατής netcat μπορεί να είναι αρκετός:
```bash
sudo nc -k -v -l -p 386
```
### Μέθοδος 2: Πλήρης διακομιστής LDAP με το Slapd
Μια πιο αξιόπιστη προσέγγιση περιλαμβάνει τη δημιουργία ενός πλήρους διακομιστή LDAP, επειδή ο εκτυπωτής πραγματοποιεί ένα null bind ακολουθούμενο από μια ερώτηση πριν προσπαθήσει να συνδεθεί με διαπιστευτήρια.

1. **Ρύθμιση διακομιστή LDAP**: Ο οδηγός ακολουθεί τα βήματα από [αυτή την πηγή](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Κύρια βήματα**:
- Εγκατάσταση του OpenLDAP.
- Ρύθμιση του κωδικού διαχειριστή.
- Εισαγωγή βασικών σχημάτων.
- Ορισμός ονόματος τομέα στη βάση δεδομένων LDAP.
- Ρύθμιση του LDAP TLS.
3. **Εκτέλεση υπηρεσίας LDAP**: Αφού ολοκληρωθεί η ρύθμιση, η υπηρεσία LDAP μπορεί να εκτελεστεί χρησιμοποιώντας:
```bash
slapd -d 2
```
## Αναφορές
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
