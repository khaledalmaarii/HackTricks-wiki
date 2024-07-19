# macOS Defensive Apps

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Θα παρακολουθεί κάθε σύνδεση που γίνεται από κάθε διαδικασία. Ανάλογα με τη λειτουργία (σιωπηλή επιτρεπόμενη σύνδεση, σιωπηλή άρνηση σύνδεσης και ειδοποίηση) θα **σας δείξει μια ειδοποίηση** κάθε φορά που καθορίζεται μια νέα σύνδεση. Έχει επίσης μια πολύ ωραία GUI για να δείτε όλες αυτές τις πληροφορίες.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall του Objective-See. Αυτό είναι ένα βασικό firewall που θα σας ειδοποιεί για ύποπτες συνδέσεις (έχει GUI αλλά δεν είναι τόσο εντυπωσιακή όσο αυτή του Little Snitch).

## Persistence detection

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Εφαρμογή του Objective-See που θα αναζητήσει σε διάφορες τοποθεσίες όπου **το malware θα μπορούσε να επιμένει** (είναι ένα εργαλείο μιας χρήσης, όχι υπηρεσία παρακολούθησης).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Όπως το KnockKnock παρακολουθώντας διαδικασίες που δημιουργούν επιμονή.

## Keyloggers detection

* [**ReiKey**](https://objective-see.org/products/reikey.html): Εφαρμογή του Objective-See για να βρείτε **keyloggers** που εγκαθιστούν "event taps" πληκτρολογίου.
