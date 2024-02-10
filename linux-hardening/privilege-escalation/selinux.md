<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# SELinux σε Εμπορεύματα

[Εισαγωγή και παράδειγμα από τα redhat docs](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[Το SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) είναι ένα **σύστημα επισήμανσης**. Κάθε **διεργασία** και κάθε **αντικείμενο συστήματος αρχείου έχει μια ετικέτα**. Οι πολιτικές του SELinux καθορίζουν κανόνες για το τι μπορεί να κάνει μια ετικέτα διεργασίας με όλες τις άλλες ετικέτες στο σύστημα.

Οι μηχανές εμπορευμάτων εκκινούν **διεργασίες εμπορευμάτων με μια μόνο περιορισμένη ετικέτα SELinux**, συνήθως `container_t`, και στη συνέχεια ορίζουν το εμπόρευμα μέσα στο εμπόρευμα να έχει ετικέτα `container_file_t`. Οι κανόνες της πολιτικής SELinux ουσιαστικά λένε ότι οι **διεργασίες `container_t` μπορούν μόνο να διαβάζουν/γράφουν/εκτελούν αρχεία με ετικέτα `container_file_t`**. Εάν μια διεργασία εμπορεύματος δραπετεύσει από το εμπόρευμα και προσπαθήσει να γράψει σε περιεχόμενο στον κεντρικό υπολογιστή, το πυρήνας του Linux απορρίπτει την πρόσβαση και επιτρέπει μόνο στη διεργασία εμπορεύματος να γράψει σε περιεχόμενο με ετικέτα `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Χρήστες SELinux

Υπάρχουν χρήστες SELinux εκτός από τους κανονικούς χρήστες του Linux. Οι χρήστες SELinux ανήκουν σε μια πολιτική SELinux. Κάθε χρήστης Linux αντιστοιχίζεται σε έναν χρήστη SELinux ως μέρος της πολιτικής. Αυτό επιτρέπει στους χρήστες Linux να κληρονομούν τους περιορισμούς και τους κανόνες ασφαλείας που έχουν τεθεί στους χρήστες SELinux.
