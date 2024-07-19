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


Υπάρχουν αρκετά blogs στο Διαδίκτυο που **τονίζουν τους κινδύνους του να αφήνεις εκτυπωτές ρυθμισμένους με LDAP με προεπιλεγμένα/αδύναμα** διαπιστευτήρια σύνδεσης.\
Αυτό συμβαίνει επειδή ένας επιτιθέμενος θα μπορούσε να **παραπλανήσει τον εκτυπωτή να πιστοποιηθεί σε έναν κακόβουλο LDAP server** (συνήθως ένα `nc -vv -l -p 444` είναι αρκετό) και να καταγράψει τα **διαπιστευτήρια του εκτυπωτή σε καθαρό κείμενο**.

Επίσης, αρκετοί εκτυπωτές θα περιέχουν **αρχεία καταγραφής με ονόματα χρηστών** ή θα μπορούσαν ακόμη και να είναι σε θέση να **κατεβάσουν όλα τα ονόματα χρηστών** από τον Domain Controller.

Όλες αυτές οι **ευαίσθητες πληροφορίες** και η κοινή **έλλειψη ασφάλειας** καθιστούν τους εκτυπωτές πολύ ενδιαφέροντες για τους επιτιθέμενους.

Ορισμένα blogs σχετικά με το θέμα:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Ρύθμιση Εκτυπωτή
- **Τοποθεσία**: Η λίστα των LDAP servers βρίσκεται στο: `Network > LDAP Setting > Setting Up LDAP`.
- **Συμπεριφορά**: Η διεπαφή επιτρέπει τροποποιήσεις στους LDAP servers χωρίς να χρειάζεται επανακαταχώρηση διαπιστευτηρίων, στοχεύοντας στην ευκολία του χρήστη αλλά θέτοντας σε κίνδυνο την ασφάλεια.
- **Εκμετάλλευση**: Η εκμετάλλευση περιλαμβάνει την ανακατεύθυνση της διεύθυνσης του LDAP server σε έναν ελεγχόμενο υπολογιστή και την αξιοποίηση της δυνατότητας "Δοκιμή Σύνδεσης" για την καταγραφή διαπιστευτηρίων.

## Καταγραφή Διαπιστευτηρίων

**Για πιο λεπτομερή βήματα, ανατρέξτε στην αρχική [πηγή](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Μέθοδος 1: Netcat Listener
Ένας απλός netcat listener μπορεί να είναι αρκετός:
```bash
sudo nc -k -v -l -p 386
```
Ωστόσο, η επιτυχία αυτής της μεθόδου ποικίλλει.

### Μέθοδος 2: Πλήρης LDAP Server με Slapd
Μια πιο αξιόπιστη προσέγγιση περιλαμβάνει τη ρύθμιση ενός πλήρους LDAP server, καθώς ο εκτυπωτής εκτελεί μια null bind ακολουθούμενη από ένα query πριν προσπαθήσει την πιστοποίηση διαπιστευτηρίων.

1. **Ρύθμιση LDAP Server**: Ο οδηγός ακολουθεί βήματα από [αυτή την πηγή](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Κύρια Βήματα**:
- Εγκατάσταση OpenLDAP.
- Ρύθμιση κωδικού πρόσβασης διαχειριστή.
- Εισαγωγή βασικών σχημάτων.
- Ρύθμιση ονόματος τομέα στη βάση δεδομένων LDAP.
- Ρύθμιση LDAP TLS.
3. **Εκτέλεση Υπηρεσίας LDAP**: Μόλις ρυθμιστεί, η υπηρεσία LDAP μπορεί να εκτελείται χρησιμοποιώντας:
```bash
slapd -d 2
```
## Αναφορές
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


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
