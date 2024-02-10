# Αριθμός Σειριακού Αριθμού macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


## Βασικές Πληροφορίες

Τα συσκευές Apple μετά το 2010 έχουν σειριακούς αριθμούς που αποτελούνται από **12 αλφαριθμητικούς χαρακτήρες**, με κάθε τμήμα να μεταφέρει συγκεκριμένες πληροφορίες:

- **Πρώτοι 3 χαρακτήρες**: Υποδεικνύουν τη **τοποθεσία κατασκευής**.
- **Χαρακτήρες 4 & 5**: Δηλώνουν το **έτος και την εβδομάδα κατασκευής**.
- **Χαρακτήρες 6 έως 8**: Λειτουργούν ως **μοναδικός αναγνωριστικός αριθμός** για κάθε συσκευή.
- **Τελευταίοι 4 χαρακτήρες**: Καθορίζουν το **μοντέλο της συσκευής**.

Για παράδειγμα, ο σειριακός αριθμός **C02L13ECF8J2** ακολουθεί αυτήν τη δομή.

### **Τοποθεσίες Κατασκευής (Πρώτοι 3 χαρακτήρες)**
Ορισμένοι κωδικοί αντιπροσωπεύουν συγκεκριμένες εργοστάσια:
- **FC, F, XA/XB/QP/G8**: Διάφορες τοποθεσίες στις ΗΠΑ.
- **RN**: Μεξικό.
- **CK**: Κορκ, Ιρλανδία.
- **VM**: Foxconn, Τσεχία.
- **SG/E**: Σιγκαπούρη.
- **MB**: Μαλαισία.
- **PT/CY**: Κορέα.
- **EE/QT/UV**: Ταϊβάν.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Διάφορες τοποθεσίες στην Κίνα.
- **C0, C3, C7**: Συγκεκριμένες πόλεις στην Κίνα.
- **RM**: Ανακατασκευασμένες συσκευές.

### **Έτος Κατασκευής (4ος χαρακτήρας)**
Αυτός ο χαρακτήρας ποικίλει από το 'C' (που αντιπροσωπεύει το πρώτο μισό του 2010) έως το 'Z' (δεύτερο μισό του 2019), με διάφορους χαρακτήρες που υποδηλώνουν διάφορες περιόδους του ημιετούς.

### **Εβδομάδα Κατασκευής (5ος χαρακτήρας)**
Οι αριθμοί 1-9 αντιστοιχούν στις εβδομάδες 1-9. Οι χαρακτήρες C-Y (εξαιρουμένων των φωνηέντων και του 'S') αντιπροσωπεύουν τις εβδομάδες 10-27. Για το δεύτερο μισό του έτους, προστίθεται το 26 σε αυτόν τον αριθμό.

### **Μοναδικός Αναγνωριστικός Αριθμός (Χαρακτήρες 6 έως 8)**
Αυτοί οι τρεις αριθμοί εξασφαλίζουν ότι κάθε συσκευή, ακόμα και του ίδιου μοντέλου και παρτίδας, έχει έναν διακριτό σειριακό αριθμό.

### **Αριθμός Μοντέλου (Τελευταίοι 4 χαρακτήρες)**
Αυτοί οι αριθμοί αναγνωρίζουν το συγκεκριμένο μοντέλο της συσκευής.

### Αναφορά

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μο
