# Άλλα Κόλπα στον Ιστό

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### Κεφαλίδα Κεντρικού Σέρβερ

Πολλές φορές το back-end εμπιστεύεται την **κεφαλίδα Host** για να εκτελέσει κάποιες ενέργειες. Για παράδειγμα, θα μπορούσε να χρησιμοποιήσει την τιμή της ως το **domain για να στείλει επαναφορά κωδικού πρόσβασης**. Έτσι, όταν λάβετε ένα email με ένα σύνδεσμο για επαναφορά κωδικού πρόσβασης, το domain που χρησιμοποιείται είναι αυτό που έχετε βάλει στην κεφαλίδα Host. Έπειτα, μπορείτε να ζητήσετε την επαναφορά κωδικού πρόσβασης άλλων χρηστών και να αλλάξετε το domain σε ένα που ελέγχετε εσείς για να κλέψετε τους κωδικούς επαναφοράς τους. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Σημειώστε ότι είναι δυνατόν να μην χρειάζεται καν να περιμένετε τον χρήστη να κάνει κλικ στον σύνδεσμο επαναφοράς κωδικού για να λάβετε το τεκμήριο, καθώς ίσως ακόμα και **φίλτρα ανεπιθύμητων μηνυμάτων ή άλλες μεσολαβητικές συσκευές/ρομπότ θα κάνουν κλικ για να το αναλύσουν**.
{% endhint %}

### Λογικές Τιμές Συνεδρίας

Κάποιες φορές, όταν ολοκληρώνετε κάποια επαλήθευση σωστά, το back-end θα **προσθέσει απλώς μια λογική τιμή "True" σε ένα ασφαλείας γνώρισμα της συνεδρίας σας**. Έπειτα, ένα διαφορετικό σημείο θα γνωρίζει αν περάσατε με επιτυχία αυτόν τον έλεγχο.\
Ωστόσο, αν **περάσετε τον έλεγχο** και η συνεδρία σας είναι εξοπλισμένη με την τιμή "True" στο ασφαλές γνώρισμα, μπορείτε να προσπαθήσετε να **έχετε πρόσβαση σε άλλους πόρους** που **εξαρτώνται από το ίδιο γνώρισμα** αλλά που **δεν θα έπρεπε να έχετε άδειες** για πρόσβαση. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Λειτουργικότητα Εγγραφής

Δοκιμάστε να εγγραφείτε ως ήδη υπάρχων χρήστης. Δοκιμάστε επίσης να χρησιμοποιήσετε ισοδύναμους χαρακτήρες (τελείες, πολλά κενά και Unicode).

### Πάρτε τον Έλεγχο των Emails

Εγγραφείτε σε ένα email, πριν το επιβεβαιώσετε αλλάξτε το email, έπειτα, αν το νέο email επιβεβαίωσης σταλεί στο πρώτο εγγεγραμμένο email, μπορείτε να πάρετε τον έλεγχο οποιουδήποτε email. Ή αν μπορείτε να ενεργοποιήσετε το δεύτερο email επιβεβαίωσης του πρώτου, μπορείτε επίσης να πάρετε τον έλεγχο οποιουδήποτε λογαριασμού.

### Πρόσβαση στο Εσωτερικό servicedesk εταιρειών που χρησιμοποιούν το atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Μέθοδος TRACE

Οι προγραμματιστές μπορεί να ξεχάσουν να απενεργοποιήσουν διάφορες επιλογές αποσφαλμάτωσης στο περιβάλλον παραγωγής. Για παράδειγμα, η μέθοδος HTTP `TRACE` σχεδιάστηκε για διαγνωστικούς σκοπούς. Εάν είναι ενεργοποιημένη, ο web server θα ανταποκρίνεται σε αιτήσεις που χρησιμοποιούν τη μέθοδο `TRACE` αντηχώντας στην απάντηση την ακριβή αίτηση που λήφθηκε. Αυτή η συμπεριφορά συνήθως είναι αβλαβής, αλλά περιστασιακά οδηγεί σε αποκάλυψη πληροφοριών, όπως το όνομα εσωτερικών κεφαλίδων πιστοποίησης που μπορεί να προστεθούν σε αιτήσεις από αντίστροφους διακομιστές.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
