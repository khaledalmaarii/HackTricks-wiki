# Sub-GHz RF

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

## Πόρτες Γκαράζ

Οι ανοιγόμενες πόρτες γκαράζ συνήθως λειτουργούν σε συχνότητες στο εύρος 300-190 MHz, με τις πιο συνηθισμένες συχνότητες να είναι 300 MHz, 310 MHz, 315 MHz και 390 MHz. Αυτό το εύρος συχνοτήτων χρησιμοποιείται συνήθως για τις ανοιγόμενες πόρτες γκαράζ επειδή είναι λιγότερο κορεσμένο από άλλα εύρη συχνοτήτων και είναι λιγότερο πιθανό να υποστεί παρεμβολές από άλλες συσκευές.

## Πόρτες Αυτοκινήτων

Οι περισσότερες ασύρματες τηλεχειριζόμενες κλειδαριές αυτοκινήτων λειτουργούν είτε στα **315 MHz είτε στα 433 MHz**. Αυτές είναι και οι δύο ραδιοσυχνότητες και χρησιμοποιούνται σε διάφορες εφαρμογές. Η κύρια διαφορά μεταξύ των δύο συχνοτήτων είναι ότι η 433 MHz έχει μεγαλύτερη εμβέλεια από την 315 MHz. Αυτό σημαίνει ότι η 433 MHz είναι καλύτερη για εφαρμογές που απαιτούν μεγαλύτερη εμβέλεια, όπως η απομακρυσμένη ασύρματη κλειδαριά.

Στην Ευρώπη, η συχνότητα 433,92 MHz χρησιμοποιείται συνήθως, ενώ στις ΗΠΑ και στην Ιαπωνία είναι η 315 MHz.

## **Επίθεση Brute-force**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Αν αντί να στέλνετε κάθε κωδικό 5 φορές (στέλνεται έτσι για να εξασφαλιστεί ότι ο δέκτης τον λαμβάνει) τον στείλετε μόνο μία φορά, ο χρόνος μειώνεται σε 6 λεπτά:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

και αν **αφαιρέσετε την περίοδο αναμονής 2 ms** μεταξύ των σημάτων, μπορείτε να μειώσετε τον χρόνο σε 3 λεπτά.

Επιπλέον, χρησιμοποιώντας την Ακολουθία De Bruijn (ένας τρόπος για να μειωθεί ο αριθμός των bits που απαιτούνται για να σταλούν όλοι οι δυνητικοί δυαδικοί αριθμοί για brute force), αυτός ο χρόνος μειώνεται μόνο σε 8 δευτερόλεπτα:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Ένα παράδειγμα αυτής της επίθεσης υλοποιήθηκε στο [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Η απαίτηση **ενός προλόγου θα αποτρέψει την βελτιστοποίηση της Ακολουθίας De Bruijn** και οι **κύλινδροι κωδικοί θα αποτρέψουν αυτήν την επίθ
### Επίθεση Jamming με Ενεργοποίηση Συναγερμού

Κατά τη δοκιμή ενός συστήματος μετά την αγορά που χρησιμοποιεί κώδικες κύλισης σε ένα αυτοκίνητο, **η αποστολή του ίδιου κώδικα δύο φορές** ενεργοποίησε αμέσως τον συναγερμό και τον απενεργοποιητή, παρέχοντας μια μοναδική ευκαιρία **απόρριψης υπηρεσίας**. Ειρωνικά, ο τρόπος **απενεργοποίησης του συναγερμού** και του απενεργοποιητή ήταν να **πατήσει** κανείς το **τηλεχειριστήριο**, παρέχοντας στον επιτιθέμενο τη δυνατότητα να **εκτελεί συνεχώς επιθέσεις DoS**. Ή να συνδυάσει αυτήν την επίθεση με την **προηγούμενη για να αποκτήσει περισσότερους κωδικούς**, καθώς ο θύτης θα ήθελε να σταματήσει την επίθεση όσο το δυνατόν συντομότερα.

## Αναφορές

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
