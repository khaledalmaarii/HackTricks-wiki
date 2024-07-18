# Ανάλυση Android

{% hint style="success" %}
Μάθε & εξάσκησε το Hacking στο AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε το Hacking στο GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Κλειδωμένη Συσκευή

Για να ξεκινήσετε την εξαγωγή δεδομένων από μια συσκευή Android πρέπει να είναι ξεκλείδωτη. Αν είναι κλειδωμένη μπορείτε:

* Να ελέγξετε αν η συσκευή έχει ενεργοποιημένη την αποσφαλμάτωση μέσω USB.
* Να ελέγξετε για πιθανή [επίθεση με αποτυπώματα](https://www.usenix.org/legacy/event/woot10/tech/full\_papers/Aviv.pdf)
* Να δοκιμάσετε με [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Απόκτηση Δεδομένων

Δημιουργήστε ένα [αντίγραφο ασφαλείας Android χρησιμοποιώντας το adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) και εξάγετε το χρησιμοποιώντας το [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Αν υπάρχει ριζική πρόσβαση ή φυσική σύνδεση στη διεπαφή JTAG

* `cat /proc/partitions` (αναζητήστε τη διαδρομή προς τη μνήμη flash, συνήθως η πρώτη καταχώρηση είναι _mmcblk0_ και αντιστοιχεί στην ολόκληρη μνήμη flash).
* `df /data` (Ανακαλύψτε το μέγεθος του τμήματος του συστήματος).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (εκτελέστε το με τις πληροφορίες που συγκεντρώθηκαν από το μέγεθος του τμήματος).

### Μνήμη

Χρησιμοποιήστε το Linux Memory Extractor (LiME) για να εξάγετε τις πληροφορίες RAM. Είναι μια επέκταση πυρήνα που πρέπει να φορτωθεί μέσω adb. 

{% hint style="success" %}
Μάθε & εξάσκησε το Hacking στο AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε το Hacking στο GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
