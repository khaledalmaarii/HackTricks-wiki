<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# CBC

Εάν το **cookie** είναι **μόνο** το **όνομα χρήστη** (ή το πρώτο μέρος του cookie είναι το όνομα χρήστη) και θέλετε να προσομοιώσετε το όνομα χρήστη "**admin**". Τότε, μπορείτε να δημιουργήσετε το όνομα χρήστη **"bdmin"** και να **δοκιμάσετε όλα τα πιθανά** πρώτα bytes του cookie.

# CBC-MAC

Το **Cipher block chaining message authentication code** (**CBC-MAC**) είναι μια μέθοδος που χρησιμοποιείται στην κρυπτογραφία. Λειτουργεί παίρνοντας ένα μήνυμα και κρυπτογραφώντας το μπλοκ προς μπλοκ, όπου η κρυπτογράφηση κάθε μπλοκ συνδέεται με το προηγούμενο. Αυτή η διαδικασία δημιουργεί μια **αλυσίδα μπλοκ**, εξασφαλίζοντας ότι η αλλαγή ακόμα και ενός μόνο bit του αρχικού μηνύματος θα οδηγήσει σε μια μη προβλέψιμη αλλαγή στο τελευταίο μπλοκ κρυπτογραφημένων δεδομένων. Για να γίνει ή να αναιρεθεί μια τέτοια αλλαγή, απαιτείται το κλειδί κρυπτογράφησης, εξασφαλίζοντας την ασφάλεια.

Για να υπολογίσετε το CBC-MAC του μηνύματος m, κρυπτογραφείτε το m σε λειτουργία CBC με μηδενικό διάνυσμα αρχικοποίησης και κρατάτε το τελευταίο μπλοκ. Ο παρακάτω σχεδιασμός απεικονίζει τον υπολογισμό του CBC-MAC ενός μηνύματος που αποτελείται από μπλοκ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) χρησιμοποιώντας ένα μυστικό κλειδί k και έναν κρυπτογράφο μπλοκ E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Ευπάθεια

Με το CBC-MAC συνήθως το **IV που χρησιμοποιείται είναι 0**.\
Αυτό είναι ένα πρόβλημα επειδή 2 γνωστά μηνύματα (`m1` και `m2`) ανεξάρτητα θα δημιουργήσουν 2 υπογραφές (`s1` και `s2`). Έτσι:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Έπειτα ένα μήνυμα που αποτελείται από τη σύζευξη των m1 και m2 (m3) θα δημιουργήσει 2 υπογραφές (s31 και s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Το οποίο είναι δυνατό να υπολογιστεί χωρίς να γνωρίζετε το κλειδί της κρυπτογράφησης.**

Φανταστείτε ότι κρυπτογραφείτε το όνομα **Administrator** σε μπλοκ των **8bytes**:

* `Administ`
* `rator\00\00\00`

Μπορείτε να δημιουργήσετε ένα όνομα χρήστη με το όνομα **Administ** (m1) και να ανακτήσετε την υπογραφή (s1).\
Έπειτα, μπορείτε να δημιουργήσετε ένα όνομα χρήστη με το αποτέλεσμα του `rator\00\00\00 XOR s1`. Αυτό θα δημιουργήσει `E(m2 XOR s1 XOR 0)`
