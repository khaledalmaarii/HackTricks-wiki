# FZ - iButton

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

## Εισαγωγή

Για περισσότερες πληροφορίες σχετικά με το τι είναι ένα iButton, ελέγξτε:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Σχεδίαση

Το **μπλε** μέρος της παρακάτω εικόνας είναι πώς θα πρέπει να **τοποθετήσετε το πραγματικό iButton** ώστε το Flipper να μπορεί να **το διαβάσει.** Το **πράσινο** μέρος είναι πώς πρέπει να **αγγίξετε τον αναγνώστη** με το Flipper zero για να **εξομοιώσετε σωστά ένα iButton**.

<figure><img src="../../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Ανάγνωση

Στη λειτουργία Ανάγνωσης, το Flipper περιμένει το κλειδί iButton να αγγίξει και είναι ικανό να επεξεργαστεί οποιονδήποτε από τους τρεις τύπους κλειδιών: **Dallas, Cyfral, και Metakom**. Το Flipper θα **καταλάβει τον τύπο του κλειδιού μόνο του**. Το όνομα του πρωτοκόλλου του κλειδιού θα εμφανίζεται στην οθόνη πάνω από τον αριθμό ID.

### Προσθήκη χειροκίνητα

Είναι δυνατόν να **προσθέσετε χειροκίνητα** ένα iButton τύπου: **Dallas, Cyfral, και Metakom**

### **Εξομοίωση**

Είναι δυνατόν να **εξομοιώσετε** αποθηκευμένα iButtons (διαβασμένα ή προστιθέμενα χειροκίνητα).

{% hint style="info" %}
Εάν δεν μπορείτε να κάνετε τις αναμενόμενες επαφές του Flipper Zero να αγγίξουν τον αναγνώστη, μπορείτε να **χρησιμοποιήσετε το εξωτερικό GPIO:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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
