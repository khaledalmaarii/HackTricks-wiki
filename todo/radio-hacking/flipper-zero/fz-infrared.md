# FZ - Infrared

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

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργεί το Infrared, ελέγξτε:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Ο Flipper χρησιμοποιεί έναν ψηφιακό δέκτη σήματος IR TSOP, ο οποίος **επιτρέπει την παγίδευση σημάτων από IR τηλεχειριστήρια**. Υπάρχουν μερικά **smartphones** όπως η Xiaomi, που έχουν επίσης θύρα IR, αλλά να έχετε υπόψη ότι **οι περισσότεροι από αυτούς μπορούν μόνο να μεταδίδουν** σήματα και είναι **ανίκανοι να τα λάβουν**.

Ο δέκτης υπερύθρων του Flipper είναι **αρκετά ευαίσθητος**. Μπορείτε ακόμη και να **πιάσετε το σήμα** ενώ βρίσκεστε **κάπου ενδιάμεσα** του τηλεχειριστηρίου και της τηλεόρασης. Δεν είναι απαραίτητο να στοχεύετε το τηλεχειριστήριο απευθείας στη θύρα IR του Flipper. Αυτό είναι χρήσιμο όταν κάποιος αλλάζει κανάλια ενώ στέκεται κοντά στην τηλεόραση, και εσείς και ο Flipper είστε σε κάποια απόσταση.

Καθώς η **αποκωδικοποίηση του σήματος υπερύθρων** συμβαίνει στην **πλευρά του λογισμικού**, ο Flipper Zero υποστηρίζει δυνητικά την **λήψη και μετάδοση οποιωνδήποτε κωδικών IR τηλεχειριστηρίου**. Στην περίπτωση **άγνωστων** πρωτοκόλλων που δεν μπορούν να αναγνωριστούν - **καταγράφει και αναπαράγει** το ακατέργαστο σήμα ακριβώς όπως το έλαβε.

## Actions

### Universal Remotes

Ο Flipper Zero μπορεί να χρησιμοποιηθεί ως **καθολικό τηλεχειριστήριο για τον έλεγχο οποιασδήποτε τηλεόρασης, κλιματιστικού ή κέντρου πολυμέσων**. Σε αυτή τη λειτουργία, ο Flipper **δοκιμάζει** όλους τους **γνωστούς κωδικούς** όλων των υποστηριζόμενων κατασκευαστών **σύμφωνα με το λεξικό από την κάρτα SD**. Δεν χρειάζεται να επιλέξετε ένα συγκεκριμένο τηλεχειριστήριο για να απενεργοποιήσετε την τηλεόραση ενός εστιατορίου.

Αρκεί να πατήσετε το κουμπί τροφοδοσίας στη λειτουργία Καθολικού Τηλεχειριστηρίου, και ο Flipper θα **στείλει διαδοχικά τις εντολές "Power Off"** όλων των τηλεοράσεων που γνωρίζει: Sony, Samsung, Panasonic... και ούτω καθεξής. Όταν η τηλεόραση λάβει το σήμα της, θα αντιδράσει και θα απενεργοποιηθεί.

Αυτή η δοκιμή βίας απαιτεί χρόνο. Όσο μεγαλύτερο είναι το λεξικό, τόσο περισσότερο χρόνο θα χρειαστεί για να ολοκληρωθεί. Είναι αδύνατο να μάθετε ποιο σήμα ακριβώς αναγνώρισε η τηλεόραση, καθώς δεν υπάρχει ανατροφοδότηση από την τηλεόραση.

### Learn New Remote

Είναι δυνατόν να **καταγράψετε ένα σήμα υπερύθρων** με τον Flipper Zero. Εάν **βρει το σήμα στη βάση δεδομένων**, ο Flipper θα γνωρίζει αυτόματα **ποια συσκευή είναι αυτή** και θα σας επιτρέψει να αλληλεπιδράσετε μαζί της.\
Εάν δεν το βρει, ο Flipper μπορεί να **αποθηκεύσει** το **σήμα** και θα σας επιτρέψει να το **αναπαράγετε**.

## References

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
