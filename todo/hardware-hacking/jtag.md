# JTAG

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)είναι ένα εργαλείο που μπορεί να χρησιμοποιηθεί με ένα Raspberry PI ή ένα Arduino για να βρει και να δοκιμάσει τα JTAG pins από ένα άγνωστο τσιπ.\
Στο **Arduino**, συνδέστε τα **pins από 2 έως 11 σε 10pins που ενδέχεται να ανήκουν σε JTAG**. Φορτώστε το πρόγραμμα στο Arduino και θα προσπαθήσει να βρει όλα τα pins για να δει αν κάποιο από αυτά ανήκει σε JTAG και ποιο είναι το καθένα.\
Στο **Raspberry PI** μπορείτε να χρησιμοποιήσετε μόνο **pins από 1 έως 6** (6pins, οπότε θα προχωρήσετε πιο αργά δοκιμάζοντας κάθε πιθανό JTAG pin).

### Arduino

Στο Arduino, μετά τη σύνδεση των καλωδίων (pin 2 έως 11 σε JTAG pins και Arduino GND στη βάση GND), **φορτώστε το πρόγραμμα JTAGenum στο Arduino** και στο Serial Monitor στείλτε ένα **`h`** (εντολή για βοήθεια) και θα πρέπει να δείτε τη βοήθεια:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Ρυθμίστε **"No line ending" και 115200baud**.\
Στείλτε την εντολή s για να ξεκινήσετε τη σάρωση:

![](<../../.gitbook/assets/image (774).png>)

Αν επικοινωνείτε με ένα JTAG, θα βρείτε μία ή περισσότερες **γραμμές που αρχίζουν με FOUND!** υποδεικνύοντας τα pins του JTAG.

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
