{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}


# CBC

Εάν το **cookie** είναι **μόνο** το **όνομα χρήστη** (ή το πρώτο μέρος του cookie είναι το όνομα χρήστη) και θέλετε να παριστάνετε το όνομα χρήστη "**admin**". Τότε, μπορείτε να δημιουργήσετε το όνομα χρήστη **"bdmin"** και να **bruteforce** το **πρώτο byte** του cookie.

# CBC-MAC

Το **Cipher block chaining message authentication code** (**CBC-MAC**) είναι μια μέθοδος που χρησιμοποιείται στην κρυπτογραφία. Λειτουργεί παίρνοντας ένα μήνυμα και κρυπτογραφώντας το μπλοκ προς μπλοκ, όπου η κρυπτογράφηση κάθε μπλοκ συνδέεται με αυτό πριν από αυτό. Αυτή η διαδικασία δημιουργεί μια **αλυσίδα μπλοκ**, εξασφαλίζοντας ότι η αλλαγή ακόμη και ενός μόνο bit του αρχικού μηνύματος θα οδηγήσει σε μια μη προβλέψιμη αλλαγή στο τελευταίο μπλοκ κρυπτογραφημένων δεδομένων. Για να γίνει ή να αναστραφεί μια τέτοια αλλαγή, απαιτείται το κλειδί κρυπτογράφησης, εξασφαλίζοντας την ασφάλεια.

Για να υπολογίσετε το CBC-MAC του μηνύματος m, κρυπτογραφείτε το m σε λειτουργία CBC με μηδενικό διάνυσμα αρχικοποίησης και κρατάτε το τελευταίο μπλοκ. Το ακόλουθο σχήμα επισημαίνει τον υπολογισμό του CBC-MAC ενός μηνύματος που αποτελείται από μπλοκ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) χρησιμοποιώντας ένα μυστικό κλειδί k και ένα block cipher E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Ευπάθεια

Με το CBC-MAC συνήθως το **IV που χρησιμοποιείται είναι 0**.\
Αυτό είναι ένα πρόβλημα επειδή 2 γνωστά μηνύματα (`m1` και `m2`) ανεξάρτητα θα δημιουργήσουν 2 υπογραφές (`s1` και `s2`). Έτσι:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Στη συνέχεια ένα μήνυμα που αποτελείται από το m1 και το m2 που ενωμένα (m3) θα δημιουργήσει 2 υπογραφές (s31 και s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Το οποίο είναι δυνατό να υπολογιστεί χωρίς να γνωρίζετε το κλειδί της κρυπτογράφησης.**

Φανταστείτε ότι κρυπτογραφείτε το όνομα **Διαχειριστής** σε μπλοκ **8bytes**:

* `Administ`
* `rator\00\00\00`

Μπορείτε να δημιουργήσετε ένα όνομα χρήστη που ονομάζεται **Administ** (m1) και να ανακτήσετε την υπογραφή (s1).\
Στη συνέχεια, μπορείτε να δημιουργήσετε ένα όνομα χρήστη που ονομάζεται το αποτέλεσμα του `rator\00\00\00 XOR s1`. Αυτό θα δημιουργήσει `E(m2 XOR s1 XOR 0)` που είναι s32.\
τώρα, μπορείτε να χρησιμοποιήσετε το s32 ως την υπογραφή του πλήρους ονόματος **Διαχειριστής**.

### Σύνοψη

1. Αποκτήστε την υπογραφή του ονόματος χρήστη **Administ** (m1) που είναι s1
2. Αποκτήστε την υπογραφή του ονόματος χρήστη **rator\x00\x00\x00 XOR s1 XOR 0** είναι s32**.**
3. Ορίστε το cookie σε s32 και θα είναι ένα έγκυρο cookie για τον χρήστη **Διαχειριστής**.

# Επίθεση Ελέγχου IV

Εάν μπορείτε να ελέγξετε το χρησιμοποιούμενο IV, η επίθεση θα μπορούσε να είναι πολύ εύκολη.\
Αν τα cookies είναι απλώς το κρυπτογραφημένο όνομα χρήστη, για να παριστάνετε τον χρήστη "**διαχειριστής**" μπορείτε να δημιουργήσετε τον χρήστη "**Διαχειριστής**" και θα λάβετε το cookie του.\
Τώρα, αν μπορείτε να ελέγξετε το IV, μπορείτε να αλλάξετε το πρώτο Byte του IV έτσι ώστε **IV\[0] XOR "A" == IV'\[0] XOR "a"** και να αναδημιουργήσετε το cookie για τον χρήστη **Διαχειριστής**. Αυτό το cookie θα είναι έγκυρο για να **παριστάνετε** τον χρήστη **διαχειριστή** με το αρχικό **IV**.

## Αναφορές

Περισσότερες πληροφορίες στο [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
