<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Βασική γραμμή

Μια βασική γραμμή αποτελείται από τη λήψη ενός στιγμιότυπου ορισμένων μερών ενός συστήματος για να **συγκριθεί με μια μελλοντική κατάσταση για να αναδειχθούν οι αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του συστήματος αρχείων για να μπορείτε να ανακαλύψετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί να γίνει επίσης με τους δημιουργηθέντες λογαριασμούς χρηστών, τις εκτελούμενες διεργασίες, τις εκτελούμενες υπηρεσίες και οποιαδήποτε άλλη πληροφορία που δεν θα έπρεπε να αλλάξει πολύ, ή καθόλου.

## Παρακολούθηση Ακεραιότητας Αρχείων

Η Παρακολούθηση Ακεραιότητας Αρχείων (File Integrity Monitoring - FIM) είναι μια κρίσιμη τεχνική ασφαλείας που προστατεύει τα περιβάλλοντα IT και τα δεδομένα με την παρακολούθηση των αλλαγών στα αρχεία. Περιλαμβάνει δύο βασικά βήματα:

1. **Σύγκριση Βασικής Γραμμής:** Δημιουργία μιας βασικής γραμμής χρησιμοποιώντας τα χαρακτηριστικά των αρχείων ή τις κρυπτογραφικές αθροίσεις (όπως MD5 ή SHA-2) για μελλοντικές συγκρίσεις για την ανίχνευση τροποποιήσεων.
2. **Ειδοποίηση Αλλαγής σε Πραγματικό Χρόνο:** Λήψη άμεσων ειδοποιήσεων όταν τα αρχεία ανατίθενται ή τροποποιούνται, συνήθως μέσω επεκτάσεων πυρήνα λειτουργικού συστήματος.

## Εργαλεία

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Αναφορές

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
