# Hash Length Extension Attack

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark-web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξει αν μια εταιρεία ή οι πελάτες της έχουν **παραβιαστεί** από **stealer malwares**.

Ο κύριος στόχος του WhiteIntel είναι να καταπολεμήσει τις καταλήψεις λογαριασμών και τις επιθέσεις ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τη μηχανή τους **δωρεάν** στο:

{% embed url="https://whiteintel.io" %}

***

## Summary of the attack

Φανταστείτε έναν διακομιστή που **υπογράφει** κάποια **δεδομένα** προσθέτοντας ένα **μυστικό** σε κάποια γνωστά δεδομένα καθαρού κειμένου και στη συνέχεια κατακερματίζοντας αυτά τα δεδομένα. Αν γνωρίζετε:

* **Το μήκος του μυστικού** (αυτό μπορεί επίσης να βρεθεί με brute force από μια δεδομένη περιοχή μήκους)
* **Τα δεδομένα καθαρού κειμένου**
* **Ο αλγόριθμος (και είναι ευάλωτος σε αυτή την επίθεση)**
* **Η προσθήκη είναι γνωστή**
* Συνήθως χρησιμοποιείται μια προεπιλεγμένη, οπότε αν πληρούνται οι άλλες 3 απαιτήσεις, αυτό ισχύει επίσης
* Η προσθήκη ποικίλλει ανάλογα με το μήκος του μυστικού + δεδομένα, γι' αυτό χρειάζεται το μήκος του μυστικού

Τότε, είναι δυνατό για έναν **επιτιθέμενο** να **προσθέσει** **δεδομένα** και να **δημιουργήσει** μια έγκυρη **υπογραφή** για τα **προηγούμενα δεδομένα + προστιθέμενα δεδομένα**.

### How?

Βασικά, οι ευάλωτοι αλγόριθμοι δημιουργούν τους κατακερματισμούς πρώτα **κατακερματίζοντας ένα μπλοκ δεδομένων**, και στη συνέχεια, **από** τον **προηγουμένως** δημιουργημένο **κατακερματισμό** (κατάσταση), **προσθέτουν το επόμενο μπλοκ δεδομένων** και **το κατακερματίζουν**.

Τότε, φανταστείτε ότι το μυστικό είναι "secret" και τα δεδομένα είναι "data", το MD5 του "secretdata" είναι 6036708eba0d11f6ef52ad44e8b74d5b.\
Αν ένας επιτιθέμενος θέλει να προσθέσει τη συμβολοσειρά "append" μπορεί να:

* Δημιουργήσει ένα MD5 από 64 "A"s
* Αλλάξει την κατάσταση του προηγουμένως αρχικοποιημένου κατακερματισμού σε 6036708eba0d11f6ef52ad44e8b74d5b
* Προσθέσει τη συμβολοσειρά "append"
* Ολοκληρώσει τον κατακερματισμό και ο προκύπτων κατακερματισμός θα είναι **έγκυρος για "secret" + "data" + "padding" + "append"**

### **Tool**

{% embed url="https://github.com/iagox86/hash_extender" %}

### References

Μπορείτε να βρείτε αυτή την επίθεση καλά εξηγημένη στο [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark-web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξει αν μια εταιρεία ή οι πελάτες της έχουν **παραβιαστεί** από **stealer malwares**.

Ο κύριος στόχος του WhiteIntel είναι να καταπολεμήσει τις καταλήψεις λογαριασμών και τις επιθέσεις ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τη μηχανή τους **δωρεάν** στο:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
