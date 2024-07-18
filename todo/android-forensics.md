# Ανάλυση Android

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

## Κλειδωμένη Σ συσκευή

Για να ξεκινήσετε την εξαγωγή δεδομένων από μια συσκευή Android, πρέπει να είναι ξεκλειδωμένη. Αν είναι κλειδωμένη μπορείτε να:

* Ελέγξετε αν η συσκευή έχει ενεργοποιημένη την αποσφαλμάτωση μέσω USB.
* Ελέγξετε για μια πιθανή [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
* Δοκιμάστε με [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Απόκτηση Δεδομένων

Δημιουργήστε ένα [android backup χρησιμοποιώντας adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) και εξάγετε το χρησιμοποιώντας το [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Αν έχετε πρόσβαση root ή φυσική σύνδεση στη διεπαφή JTAG

* `cat /proc/partitions` (αναζητήστε τη διαδρομή στη μνήμη flash, γενικά η πρώτη καταχώρηση είναι _mmcblk0_ και αντιστοιχεί σε ολόκληρη τη μνήμη flash).
* `df /data` (Ανακαλύψτε το μέγεθος μπλοκ του συστήματος).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (εκτελέστε το με τις πληροφορίες που συγκεντρώθηκαν από το μέγεθος μπλοκ).

### Μνήμη

Χρησιμοποιήστε το Linux Memory Extractor (LiME) για να εξάγετε τις πληροφορίες RAM. Είναι μια επέκταση πυρήνα που πρέπει να φορτωθεί μέσω adb.

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
