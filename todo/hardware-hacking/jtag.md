<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# JTAGenum

Το [**JTAGenum** ](https://github.com/cyphunk/JTAGenum)είναι ένα εργαλείο που μπορεί να χρησιμοποιηθεί με ένα Raspberry PI ή ένα Arduino για να εντοπίσει τα JTAG pins ενός άγνωστου chip.\
Στο **Arduino**, συνδέστε τα **pin από 2 έως 11 στα 10 pins που ανήκουν πιθανώς σε ένα JTAG**. Φορτώστε το πρόγραμμα στο Arduino και θα προσπαθήσει να δοκιμάσει όλα τα pins για να βρει αν κάποιο ανήκει στο JTAG και ποιο είναι κάθε ένα.\
Στο **Raspberry PI** μπορείτε να χρησιμοποιήσετε μόνο τα **pin από 1 έως 6** (6 pins, οπότε θα πάτε πιο αργά ελέγχοντας κάθε πιθανό JTAG pin).

## Arduino

Στο Arduino, μετά τη σύνδεση των καλωδίων (pin 2 έως 11 στα JTAG pins και το Arduino GND στο baseboard GND), **φορτώστε το πρόγραμμα JTAGenum στο Arduino** και στο Serial Monitor στείλτε ένα **`h`** (εντολή για βοήθεια) και θα πρέπει να δείτε τη βοήθεια:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Διαμορφώστε **"No line ending" και 115200baud**.\
Στείλτε την εντολή s για να ξεκινήσετε τη σάρωση:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Εάν έχετε επαφή με ένα JTAG, θα βρείτε ένα ή περισσότερες **γραμμές που ξεκινούν με FOUND!** που υποδηλώνουν τα pins του JTAG.


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
