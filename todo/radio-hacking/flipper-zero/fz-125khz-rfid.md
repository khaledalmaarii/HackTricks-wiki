# FZ - 125kHz RFID

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Εισαγωγή

Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργούν οι ετικέτες 125kHz, ελέγξτε:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Ενέργειες

Για περισσότερες πληροφορίες σχετικά με αυτούς τους τύπους ετικετών [**διαβάστε αυτή την εισαγωγή**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Ανάγνωση

Προσπαθεί να **διαβάσει** τις πληροφορίες της κάρτας. Στη συνέχεια, μπορεί να **εξομοιώσει** αυτές.

{% hint style="warning" %}
Σημειώστε ότι ορισμένα διαλείμματα προσπαθούν να προστατευτούν από την αντιγραφή κλειδιών στέλνοντας μια εντολή εγγραφής πριν από την ανάγνωση. Εάν η εγγραφή είναι επιτυχής, αυτή η ετικέτα θεωρείται ψεύτικη. Όταν ο Flipper εξομοιώνει RFID, δεν υπάρχει τρόπος για τον αναγνώστη να τη διακρίνει από την αυθεντική, οπότε δεν προκύπτουν τέτοια προβλήματα.
{% endhint %}

### Προσθήκη Χειροκίνητα

Μπορείτε να δημιουργήσετε **ψεύτικες κάρτες στο Flipper Zero υποδεικνύοντας τα δεδομένα** που εισάγετε χειροκίνητα και στη συνέχεια να τις εξομοιώσετε.

#### IDs στις κάρτες

Ορισμένες φορές, όταν αποκτάτε μια κάρτα, θα βρείτε το ID (ή μέρος του) γραμμένο στην κάρτα ορατό.

* **EM Marin**

Για παράδειγμα, σε αυτή την κάρτα EM-Marin είναι δυνατό να **διαβάσετε τα τελευταία 3 από 5 bytes καθαρά**.\
Τα άλλα 2 μπορούν να βρεθούν με brute-force αν δεν μπορείτε να τα διαβάσετε από την κάρτα.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

Το ίδιο συμβαίνει σε αυτή την κάρτα HID όπου μόνο 2 από 3 bytes μπορούν να βρεθούν εκτυπωμένα στην κάρτα.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### Εξομοίωση/Εγγραφή

Αφού **αντιγράψετε** μια κάρτα ή **εισάγετε** το ID **χειροκίνητα**, είναι δυνατό να **εξομοιώσετε** αυτήν με το Flipper Zero ή να **εγγράψετε** την σε μια πραγματική κάρτα.

## Αναφορές

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
