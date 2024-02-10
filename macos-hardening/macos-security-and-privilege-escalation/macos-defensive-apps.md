# Εφαρμογές Άμυνας για macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Θα παρακολουθεί κάθε σύνδεση που πραγματοποιείται από κάθε διεργασία. Ανάλογα με τη λειτουργία (αθόρυβη επιτροπή συνδέσεων, αθόρυβη απόρριψη συνδέσεων και ειδοποίηση), θα **σας εμφανίζει μια ειδοποίηση** κάθε φορά που πραγματοποιείται μια νέα σύνδεση. Έχει επίσης ένα πολύ ωραίο γραφικό περιβάλλον χρήστη για να δείτε όλες αυτές τις πληροφορίες.
* [**LuLu**](https://objective-see.org/products/lulu.html): Το προγραμματιστικό περιβάλλον χρήστη του Objective-See. Αυτό είναι ένα βασικό τείχος προστασίας που θα σας ειδοποιεί για ύποπτες συνδέσεις (έχει ένα γραφικό περιβάλλον χρήστη, αλλά δεν είναι τόσο φανταχτερό όσο αυτό του Little Snitch).

## Εντοπισμός Διατήρησης

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Εφαρμογή του Objective-See που θα αναζητήσει σε διάφορες τοποθεσίες όπου **μπορεί να υπάρχει κακόβουλο λογισμικό** (είναι ένα εργαλείο μιας φοράς, όχι ένα υπηρεσία παρακολούθησης).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Όπως το KnockKnock, παρακολουθεί διεργασίες που δημιουργούν διατήρηση.

## Εντοπισμός Keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Εφαρμογή του Objective-See για τον εντοπισμό **keyloggers** που εγκαθιστούν "event taps" στο πληκτρολόγιο.

## Εντοπισμός Ransomware

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html): Εφαρμογή του Objective-See για τον εντοπισμό **ενεργειών κρυπτογράφησης αρχείων**.

## Εντοπισμός Μικροφώνου και Κάμερας

* [**OverSight**](https://objective-see.org/products/oversight.html): Εφαρμογή του Objective-See για τον εντοπισμό **εφαρμογών που χρησιμοποιούν την κάμερα και το μικρόφωνο**.

## Εντοπισμός Εγχύσεων Διεργασιών

* [**Shield**](https://theevilbit.github.io/shield/): Εφαρμογή που **ανιχνεύει διάφορες τεχνικές εγχύσεων διεργασιών**.
