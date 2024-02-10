# Υπέρυθρη

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πώς λειτουργεί η υπέρυθρη <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Η υπέρυθρη ακτινοβολία είναι αόρατη για τους ανθρώπους**. Το μήκος κύματος της υπέρυθρης ακτινοβολίας είναι από **0,7 έως 1000 μικρομέτρα**. Οι τηλεχειριστήρια χρησιμοποιούν ένα σήμα υπέρυθρης ακτινοβολίας για τη μετάδοση δεδομένων και λειτουργούν στο εύρος μήκους κύματος 0,75..1,4 μικρομέτρων. Ένας μικροελεγκτής στο τηλεχειριστήριο κάνει ένα υπέρυθρο LED να αναβοσβήνει με μια συγκεκριμένη συχνότητα, μετατρέποντας το ψηφιακό σήμα σε υπέρυθρο σήμα.

Για να λαμβάνονται τα υπέρυθρα σήματα χρησιμοποιείται ένας **φωτοδέκτης**. Αυτός **μετατρέπει το υπέρυθρο φως σε παλμούς τάσης**, οι οποίοι είναι ήδη **ψηφιακά σήματα**. Συνήθως, υπάρχει ένα **φίλτρο σκοτεινού φωτός μέσα στον δέκτη**, το οποίο επιτρέπει **μόνο το επιθυμητό μήκος κύματος** και αποκόπτει το θόρυβο.

### Ποικιλία πρωτοκόλλων υπέρυθρης <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Τα πρωτόκολλα υπέρυθρης διαφέρουν σε 3 παράγοντες:

* κωδικοποίηση bit
* δομή δεδομένων
* φορέας συχνότητας - συχνά στο εύρος 36..38 kHz

#### Τρόποι κωδικοποίησης bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Κωδικοποίηση απόστασης παλμών**

Τα bit κωδικοποιούνται με τη διαμόρφωση της διάρκειας του χώρου μεταξύ των παλμών. Το πλάτος του παλμού ίδιο.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Κωδικοποίηση πλάτους παλμών**

Τα bit κωδικοποιούνται με τη διαμόρφωση του πλάτους του παλμού. Το πλάτος του χώρου μετά την έκρηξη του παλμού είναι σταθερό.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Κωδικοποίηση φάσης**

Είναι επίσης γνωστή ως κωδικοποίηση Manchester. Η λογική τιμή καθορίζεται από την πολικότητα της μετάβασης μεταξύ της έκρηξης του παλμού και του χώρου. "Χώρος προς έκρηξη παλμού" υποδηλώνει λογική "0", "έκρηξη παλμού προς χώρο" υποδηλώνει λογική "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Συνδυασμός των προηγούμενω
