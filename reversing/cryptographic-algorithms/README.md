# Κρυπτογραφικοί/Αλγόριθμοι Συμπίεσης

## Κρυπτογραφικοί/Αλγόριθμοι Συμπίεσης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Αναγνώριση Αλγορίθμων

Εάν καταλήξετε σε κώδικα **που χρησιμοποιεί δεξιές και αριστερές μετατοπίσεις, XOR και πολλές αριθμητικές πράξεις**, είναι πολύ πιθανό ότι πρόκειται για την υλοποίηση ενός **κρυπτογραφικού αλγορίθμου**. Εδώ θα παρουσιαστούν ορισμένοι τρόποι για να **αναγνωρίσετε τον αλγόριθμο που χρησιμοποιείται χωρίς να χρειάζεται να αναστρέψετε κάθε βήμα**.

### Συναρτήσεις API

**CryptDeriveKey**

Εάν χρησιμοποιείται αυτή η συνάρτηση, μπορείτε να βρείτε ποιος **αλγόριθμος χρησιμοποιείται** ελέγχοντας την τιμή της δεύτερης παραμέτρου:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Ελέγξτε εδώ τον πίνακα των πιθανών αλγορίθμων και των αντιστοιχισμένων τιμών τους: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Συμπιέζει και αποσυμπιέζει έναν δοσμένο πίνακα δεδομένων.

**CryptAcquireContext**

Από [τα έγγραφα](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Η συνάρτηση **CryptAcquireContext** χρησιμοποιείται για να αποκτήσει ένα χειριστή για ένα συγκεκριμένο δοχείο κλειδιών εντός ενός συγκεκριμένου παρόχου κρυπτογραφικών υπηρεσιών (CSP). **Αυτός ο χειριστής που επιστρέφεται χρησιμοποιείται σε κλήσεις συναρτήσεων CryptoAPI** που χρησιμοποιούν τον επιλεγμένο CSP.

**CryptCreateHash**

Ξεκινά τον υπολογισμό του κατακερματισμού ενός ρεύματος δεδομένων. Εάν χρησιμοποιείται αυτή η συνάρτηση, μπορείτε να βρείτε ποιος **αλγόριθμος χρησιμοποιείται** ελέγχοντας την τιμή της δεύτερης παραμέτρου:

![](<../../.gitbook/assets/image (376).png>)

\
Ελέγξτε εδώ τον πίνακα των πιθανών αλγορίθμων και των αντιστοιχισμένων τιμών τους: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Σταθερές κώδικα

Μερικές φορές είναι πολύ εύκολο να αναγνωρίσετε έναν αλγόριθμο χάρη στο γεγονός ότι χρειάζεται να χρησιμοποιήσει μια ειδική και μοναδική τιμή.

![](<../../.gitbook/assets/image (370).png>)

Εά
## RSA **(Ασύμμετρη Κρυπτογραφία)**

### Χαρακτηριστικά

* Πιο πολύπλοκο από τους συμμετρικούς αλγορίθμους
* Δεν υπάρχουν σταθερές! (η προσαρμογή προσαρμοσμένων υλοποιήσεων είναι δύσκολη)
* Ο KANAL (ένας κρυπτοαναλυτής) αποτυγχάνει να εμφανίσει υποδείξεις για το RSA καθώς βασίζεται σε σταθερές.

### Αναγνώριση με συγκρίσεις

![](<../../.gitbook/assets/image (383).png>)

* Στη γραμμή 11 (αριστερά) υπάρχει το `+7) >> 3` που είναι το ίδιο με τη γραμμή 35 (δεξιά): `+7) / 8`
* Η γραμμή 12 (αριστερά) ελέγχει αν `modulus_len < 0x040` και στη γραμμή 36 (δεξιά) ελέγχει αν `inputLen+11 > modulusLen`

## MD5 & SHA (κατακερματισμός)

### Χαρακτηριστικά

* 3 συναρτήσεις: Init, Update, Final
* Παρόμοιες συναρτήσεις αρχικοποίησης

### Αναγνώριση

**Init**

Μπορείτε να αναγνωρίσετε και τα δύο ελέγχοντας τις σταθερές. Σημειώστε ότι η sha\_init έχει 1 σταθερά που η MD5 δεν έχει:

![](<../../.gitbook/assets/image (385).png>)

**Μετασχηματισμός MD5**

Σημειώστε τη χρήση περισσότερων σταθερών

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (κατακερματισμός)

* Μικρότερο και πιο αποδοτικό καθώς η λειτουργία του είναι να εντοπίζει ατύχημα αλλαγές στα δεδομένα
* Χρησιμοποιεί πίνακες αναζήτησης (ώστε να μπορείτε να αναγνωρίσετε σταθερές)

### Αναγνώριση

Ελέγξτε τις **σταθερές του πίνακα αναζήτησης**:

![](<../../.gitbook/assets/image (387).png>)

Ένας αλγόριθμος κατακερματισμού CRC φαίνεται όπως εξής:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Συμπίεση)

### Χαρακτηριστικά

* Δεν υπάρχουν αναγνωρίσιμες σταθερές
* Μπορείτε να δοκιμάσετε να γράψετε τον αλγόριθμο σε Python και να αναζητήσετε παρόμοια πράγματα στο διαδίκτυο

### Αναγνώριση

Το γράφημα είναι αρκετά μεγάλο:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Ελέγξτε **3 συγκρίσεις για να το αναγνωρίσετε**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
