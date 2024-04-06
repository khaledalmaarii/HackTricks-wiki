# Ενδιαφέροντα Κλειδιά Καταχώρησης των Windows

### Ενδιαφέροντα Κλειδιά Καταχώρησης των Windows

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>


### **Έκδοση των Windows και Πληροφορίες Κατόχου**
- Στο **`Software\Microsoft\Windows NT\CurrentVersion`**, θα βρείτε την έκδοση των Windows, το Service Pack, την ώρα εγκατάστασης και το όνομα του κατόχου που έχει καταχωρηθεί με απλό τρόπο.

### **Όνομα Υπολογιστή**
- Το όνομα του υπολογιστή βρίσκεται στο **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Ρύθμιση Ζώνης Ώρας**
- Η ζώνη ώρας του συστήματος αποθηκεύεται στο **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Καταγραφή Χρόνου Πρόσβασης**
- Από προεπιλογή, η καταγραφή του τελευταίου χρόνου πρόσβασης είναι απενεργοποιημένη (**`NtfsDisableLastAccessUpdate=1`**). Για να την ενεργοποιήσετε, χρησιμοποιήστε:
`fsutil behavior set disablelastaccess 0`

### Έκδοση των Windows και Service Packs
- Η **έκδοση των Windows** υποδεικνύει την έκδοση (π.χ., Home, Pro) και την κυκλοφορία της (π.χ., Windows 10, Windows 11), ενώ τα **Service Packs** είναι ενημερώσεις που περιλαμβάνουν διορθώσεις και, μερικές φορές, νέα χαρακτηριστικά.

### Ενεργοποίηση του Χρόνου Τελευταίας Πρόσβασης
- Η ενεργοποίηση της καταγραφής του χρόνου τελευταίας πρόσβασης σας επιτρέπει να δείτε πότε ανοίχθηκαν τα αρχεία τελευταία φορά, κάτι που μπορεί να είναι κρίσιμο για αναλύσεις αποδεικτικών στοιχείων ή για την παρακολούθηση του συστήματος.

### Λεπτομέρειες Πληροφοριών Δικτύου
- Η καταχώρηση κρατάει εκτεταμένα δεδομένα για τις ρυθμίσεις δικτύου, συμπεριλαμβανομένων των **τύπων δικτύων (ασύρματα, καλωδιακά, 3G)** και των **κατηγοριών δικτύου (Δημόσιο, Ιδιωτικό/Οικιακό, Τομέας/Εργασία)**, τα οποία είναι ζωτικής σημασίας για την κατανόηση των ρυθμίσεων ασφαλείας και των δικαιωμάτων του δικτύου.

### Προσωπική Αποθήκευση Πλευράς Πελάτη (CSC)
- Η **CSC** βελτιώνει την πρόσβαση σε αρχεία εκτός σύνδεσης με την αποθήκευση αντιγράφων κοινόχρηστων αρχείων. Διάφορες ρυθμίσεις **CSCFlags
