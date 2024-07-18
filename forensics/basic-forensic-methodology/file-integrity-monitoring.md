{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


# Βάση

Μια βάση αποτελείται από τη λήψη ενός στιγμιότυπου ορισμένων τμημάτων ενός συστήματος για να **συγκριθεί με μελλοντική κατάσταση για να τονίσει αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του συστήματος αρχείων για να μπορείτε να ανακαλύψετε ποια αρχεία τροποποιήθηκαν.\
Αυτό μπορεί επίσης να γίνει με τους λογαριασμούς χρηστών που δημιουργήθηκαν, τις διεργασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο που δεν πρέπει να αλλάξει πολύ, ή καθόλου.

## Παρακολούθηση Ακεραιότητας Αρχείων

Η Παρακολούθηση Ακεραιότητας Αρχείων (File Integrity Monitoring - FIM) είναι μια κρίσιμη τεχνική ασφαλείας που προστατεύει τα περιβάλλοντα IT και τα δεδομένα παρακολουθώντας τις αλλαγές στα αρχεία. Περιλαμβάνει δύο βασικά βήματα:

1. **Σύγκριση Βάσης:** Δημιουργία μιας βάσης χρησιμοποιώντας τα χαρακτηριστικά των αρχείων ή κρυπτογραφικούς ελέγχους (όπως MD5 ή SHA-2) για μελλοντικές συγκρίσεις για την ανίχνευση τροποποιήσεων.
2. **Ειδοποίηση Αλλαγής σε Πραγματικό Χρόνο:** Λάβετε άμεσες ειδοποιήσεις όταν τα αρχεία προσπελαύνονται ή τροποποιούνται, συνήθως μέσω επεκτάσεων πυρήνα OS.

## Εργαλεία

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Αναφορές

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
