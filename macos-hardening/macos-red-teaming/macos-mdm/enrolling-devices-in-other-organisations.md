# Εγγραφή Συσκευών σε Άλλους Οργανισμούς

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Εισαγωγή

Όπως [**προαναφέρθηκε**](./#what-is-mdm-mobile-device-management), για να προσπαθήσετε να εγγράψετε μια συσκευή σε έναν οργανισμό, χρειάζεται μόνο ένας αριθμός σειράς που ανήκει σε αυτόν τον Οργανισμό. Αφού η συσκευή εγγραφεί, πολλοί οργανισμοί θα εγκαταστήσουν ευαίσθητα δεδομένα στη νέα συσκευή: πιστοποιητικά, εφαρμογές, κωδικούς πρόσβασης WiFi, ρυθμίσεις VPN [και ούτω καθεξής](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Επομένως, αυτό μπορεί να αποτελέσει μια επικίνδυνη ευκαιρία για επιτιθέμενους εάν η διαδικασία εγγραφής δεν προστατεύεται σωστά.

**Το παρακάτω είναι ένα σύνοψη της έρευνας [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Ελέγξτε το για περαιτέρω τεχνικές λεπτομέρειες!**

## Επισκόπηση του DEP και της Ανάλυσης του MDM Binary

Αυτή η έρευνα εξετάζει τα δυαδικά αρχεία που σχετίζονται με το Device Enrollment Program (DEP) και τη Διαχείριση Συσκευών Mobile (MDM) στο macOS. Οι κύριες συνιστώσες περιλαμβάνουν:

- **`mdmclient`**: Επικοινωνεί με τους διακομιστές MDM και ενεργοποιεί ελέγχους DEP σε εκδόσεις macOS πριν από την 10.13.4.
- **`profiles`**: Διαχειρίζεται τις Προφίλ Διαμόρφωσης και ενεργοποιεί ελέγχους DEP σε εκδόσεις macOS 10.13.4 και μεταγενέστερες.
- **`cloudconfigurationd`**: Διαχειρίζεται τις επικοινωνίες του DEP API και ανακτά προφίλ εγγραφής συσκευής.

Οι ελέγχοι DEP χρησιμοποιούν τις λειτουργίες `CPFetchActivationRecord` και `CPGetActivationRecord` από το ιδιωτικό πλαίσιο Configuration Profiles για να ανακτήσουν το Αρχείο Ενεργοποίησης, με το `CPFetchActivationRecord` να συνεργάζεται με το `cloudconfigurationd` μέσω του XPC.

## Ανάπτυξη του Πρωτοκόλλου Tesla και Ανάλυση του Σχήματος Absinthe

Ο έλεγχος DEP περιλαμβάνει το `cloudconfigurationd` να στέλνει ένα κρυπτογραφημένο, υπογεγραμμένο JSON φορτίο στο _iprofiles.apple.com/macProfile_. Το φορτίο περιλαμβάνει τον αριθμό σειράς της συσκευής και την ενέργεια "RequestProfileConfiguration". Το σχήμα κρυπτογράφησης που χρησιμοποιείται αναφέρεται εσωτερικά ως "Absinthe". Η αποκωδικοποίηση αυτού του σχήματος είναι πολύπλοκη και περιλαμβάνει πολλά βήματα, τα οποία οδήγησαν στην εξερεύνηση εναλλακτικών μεθόδων για την εισαγωγή αυθαίρετων αριθμών σειράς στο αίτημα Εγγραφής Ενεργοποίησης.

## Προϊστάμενοι των Αιτημάτων DEP

Οι προσπάθειες παρεμβολής και τροποποίησης των αιτημάτων DEP προς το _iprofiles.apple.com_ χρησιμοποιώντας εργαλεί
