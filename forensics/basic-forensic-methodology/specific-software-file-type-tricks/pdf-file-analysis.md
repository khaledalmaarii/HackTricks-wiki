# Ανάλυση αρχείων PDF

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**Για περισσότερες λεπτομέρειες δείτε: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)**

Η μορφή PDF είναι γνωστή για την πολυπλοκότητά της και τη δυνατότητά της να κρύβει δεδομένα, καθιστώντας την ένα εστίασμα για προκλήσεις ανάκτησης αποδεικτικών στοιχείων CTF. Συνδυάζει στοιχεία απλού κειμένου με δυαδικά αντικείμενα, τα οποία μπορεί να είναι συμπιεσμένα ή κρυπτογραφημένα, και μπορεί να περιλαμβάνει σενάρια σε γλώσσες όπως η JavaScript ή η Flash. Για να κατανοήσετε τη δομή του PDF, μπορείτε να ανατρέξετε στο εισαγωγικό υλικό του Didier Stevens [εδώ](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), ή να χρησιμοποιήσετε εργαλεία όπως έναν επεξεργαστή κειμένου ή έναν επεξεργαστή PDF όπως το Origami.

Για λεπτομερή εξερεύνηση ή επεξεργασία των PDF, είναι διαθέσιμα εργαλεία όπως το [qpdf](https://github.com/qpdf/qpdf) και το [Origami](https://github.com/mobmewireless/origami-pdf). Κρυμμένα δεδομένα μέσα σε PDF μπορεί να κρύβονται σε:

* Αόρατα επίπεδα
* Μορφή μεταδεδομένων XMP από την Adobe
* Επιτελεστικές γενιές
* Κείμενο με τον ίδιο χρωματισμό με το φόντο
* Κείμενο πίσω από εικόνες ή επικαλυπτόμενες εικόνες
* Μη εμφανιζόμενα σχόλια

Για προσαρμοσμένη ανάλυση PDF, μπορούν να χρησιμοποιηθούν βιβλιοθήκες Python όπως το [PeepDF](https://github.com/jesparza/peepdf) για τη δημιουργία προσαρμοσμένων σεναρίων ανάλυσης. Επιπλέον, η δυνατότητα του PDF για κρυμμένη αποθήκευση δεδομένων είναι τόσο μεγάλη που πόροι όπως ο οδηγός της NSA για τους κινδύνους και τα αντίμετρα του PDF, αν και δεν φιλοξενείται πλέον στην αρχική του τοποθεσία, παρέχουν αξιόλογες πληροφορίες. Ένα [αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) και μια συλλογή από [κόλπα μορφής PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) από τον Ange Albertini μπορούν να παρέχουν περαιτέρω ανάγνωση για το θέμα.

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλ
