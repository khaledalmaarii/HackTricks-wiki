# macOS Apple Events

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

## Basic Information

**Apple Events** είναι μια δυνατότητα στο macOS της Apple που επιτρέπει στις εφαρμογές να επικοινωνούν μεταξύ τους. Είναι μέρος του **Apple Event Manager**, ο οποίος είναι ένα συστατικό του λειτουργικού συστήματος macOS υπεύθυνο για την διαχείριση της επικοινωνίας μεταξύ διεργασιών. Αυτό το σύστημα επιτρέπει σε μια εφαρμογή να στείλει ένα μήνυμα σε μια άλλη εφαρμογή για να ζητήσει να εκτελέσει μια συγκεκριμένη ενέργεια, όπως το άνοιγμα ενός αρχείου, την ανάκτηση δεδομένων ή την εκτέλεση μιας εντολής.

Ο daemon mina είναι `/System/Library/CoreServices/appleeventsd` που καταχωρεί την υπηρεσία `com.apple.coreservices.appleevents`.

Κάθε εφαρμογή που μπορεί να λάβει γεγονότα θα ελέγχει με αυτόν τον daemon παρέχοντας το Apple Event Mach Port της. Και όταν μια εφαρμογή θέλει να στείλει ένα γεγονός σε αυτήν, η εφαρμογή θα ζητήσει αυτό το port από τον daemon.

Οι εφαρμογές που είναι σε sandbox απαιτούν δικαιώματα όπως `allow appleevent-send` και `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` προκειμένου να μπορούν να στέλνουν γεγονότα. Σημειώστε ότι τα δικαιώματα όπως `com.apple.security.temporary-exception.apple-events` θα μπορούσαν να περιορίσουν ποιος έχει πρόσβαση για να στέλνει γεγονότα, τα οποία θα χρειαστούν δικαιώματα όπως `com.apple.private.appleevents`.

{% hint style="success" %}
It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
