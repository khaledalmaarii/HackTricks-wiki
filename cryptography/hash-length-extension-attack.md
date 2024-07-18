{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
{% endhint %}


# Σύνοψη της επίθεσης

Φανταστείτε ένα διακομιστή που **υπογράφει** κάποια **δεδομένα** με το **προσάρτημα** ενός **μυστικού** σε κάποια γνωστά καθαρά δεδομένα και στη συνέχεια κάνει hash αυτά τα δεδομένα. Αν γνωρίζετε:

* **Το μήκος του μυστικού** (αυτό μπορεί επίσης να αναζητηθεί με brute force από ένα δεδομένο εύρος μήκους)
* **Τα καθαρά δεδομένα**
* **Τον αλγόριθμο (και την ευπάθειά του σε αυτήν την επίθεση)**
* **Το padding είναι γνωστό**
* Συνήθως χρησιμοποιείται ένα προεπιλεγμένο, οπότε αν πληρούνται τα άλλα 3 απαιτήματα, αυτό επίσης είναι
* Το padding διαφέρει ανάλογα με το μήκος του μυστικού+δεδομένων, γι' αυτό χρειάζεται το μήκος του μυστικού

Τότε, είναι δυνατό για έναν **εισβολέα** να **προσθέσει** **δεδομένα** και να **δημιουργήσει** ένα έγκυρο **υπογραφή** για τα **προηγούμενα δεδομένα + τα προσαρτημένα δεδομένα**.

## Πώς;

Βασικά, οι ευάλωτοι αλγόριθμοι δημιουργούν τα hashes με το να **κάνουν hash ενός τμήματος δεδομένων** και στη συνέχεια, **από** το **προηγούμενα** δημιουργημένο **hash** (κατάσταση), **προσθέτουν το επόμενο τμήμα δεδομένων** και το **κάνουν hash**.

Έτσι, φανταστείτε ότι το μυστικό είναι "μυστικό" και τα δεδομένα είναι "δεδομένα", το MD5 του "μυστικόδεδομένα" είναι 6036708eba0d11f6ef52ad44e8b74d5b.\
Αν ένας εισβολέας θέλει να προσθέσει τη συμβολοσειρά "προσάρτημα" μπορεί:

* Να δημιουργήσει ένα MD5 από 64 "Α"
* Να αλλάξει την κατάσταση του προηγουμένως αρχικοποιημένου hash σε 6036708eba0d11f6ef52ad44e8b74d5b
* Να προσθέσει τη συμβολοσειρά "προσάρτημα"
* Να ολοκληρώσει το hash και το τελικό hash θα είναι ένα **έγκυρο για το "μυστικό" + "δεδομένα" + "padding" + "προσάρτημα"**

## **Εργαλείο**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Αναφορές

Μπορείτε να βρείτε αυτήν την επίθεση καλά εξηγημένη στο [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
{% endhint %}
