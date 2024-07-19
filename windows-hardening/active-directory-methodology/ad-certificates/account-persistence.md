# AD CS Account Persistence

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

**Αυτή είναι μια μικρή περίληψη των κεφαλαίων επιμονής μηχανής της καταπληκτικής έρευνας από [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## **Κατανόηση της κλοπής διαπιστευτηρίων ενεργών χρηστών με πιστοποιητικά – PERSIST1**

Σε ένα σενάριο όπου ένα πιστοποιητικό που επιτρέπει την αυθεντικοποίηση τομέα μπορεί να ζητηθεί από έναν χρήστη, ένας επιτιθέμενος έχει την ευκαιρία να **ζητήσει** και να **κλέψει** αυτό το πιστοποιητικό για να **διατηρήσει την επιμονή** σε ένα δίκτυο. Από προεπιλογή, το πρότυπο `User` στο Active Directory επιτρέπει τέτοιες αιτήσεις, αν και μπορεί μερικές φορές να είναι απενεργοποιημένο.

Χρησιμοποιώντας ένα εργαλείο που ονομάζεται [**Certify**](https://github.com/GhostPack/Certify), μπορεί κανείς να αναζητήσει έγκυρα πιστοποιητικά που επιτρέπουν μόνιμη πρόσβαση:
```bash
Certify.exe find /clientauth
```
Είναι επισημασμένο ότι η δύναμη ενός πιστοποιητικού έγκειται στην ικανότητά του να **αυθεντικοποιεί ως ο χρήστης** στον οποίο ανήκει, ανεξάρτητα από οποιεσδήποτε αλλαγές κωδικών πρόσβασης, εφόσον το πιστοποιητικό παραμένει **έγκυρο**.

Τα πιστοποιητικά μπορούν να ζητηθούν μέσω γραφικής διεπαφής χρησιμοποιώντας `certmgr.msc` ή μέσω της γραμμής εντολών με `certreq.exe`. Με το **Certify**, η διαδικασία για να ζητηθεί ένα πιστοποιητικό απλοποιείται ως εξής:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Μετά από επιτυχημένο αίτημα, ένα πιστοποιητικό μαζί με το ιδιωτικό του κλειδί δημιουργείται σε μορφή `.pem`. Για να το μετατρέψετε σε αρχείο `.pfx`, το οποίο είναι χρήσιμο σε συστήματα Windows, χρησιμοποιείται η εξής εντολή:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Το αρχείο `.pfx` μπορεί στη συνέχεια να μεταφορτωθεί σε ένα στοχοθετημένο σύστημα και να χρησιμοποιηθεί με ένα εργαλείο που ονομάζεται [**Rubeus**](https://github.com/GhostPack/Rubeus) για να ζητήσει ένα Ticket Granting Ticket (TGT) για τον χρήστη, επεκτείνοντας την πρόσβαση του επιτιθέμενου για όσο διάστημα το πιστοποιητικό είναι **έγκυρο** (συνήθως ένα έτος):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Ένα σημαντικό προειδοποιητικό μήνυμα κοινοποιείται σχετικά με το πώς αυτή η τεχνική, σε συνδυασμό με μια άλλη μέθοδο που περιγράφεται στην ενότητα **THEFT5**, επιτρέπει σε έναν επιτιθέμενο να αποκτήσει μόνιμα το **NTLM hash** ενός λογαριασμού χωρίς να αλληλεπιδρά με την Υπηρεσία Υποσυστήματος Τοπικής Ασφάλειας (LSASS), και από ένα μη ανυψωμένο περιβάλλον, παρέχοντας μια πιο διακριτική μέθοδο για μακροχρόνια κλοπή διαπιστευτηρίων.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Μια άλλη μέθοδος περιλαμβάνει την εγγραφή του λογαριασμού μηχανής ενός συμβιβασμένου συστήματος για ένα πιστοποιητικό, χρησιμοποιώντας το προεπιλεγμένο πρότυπο `Machine` που επιτρέπει τέτοιες ενέργειες. Εάν ένας επιτιθέμενος αποκτήσει ανυψωμένα δικαιώματα σε ένα σύστημα, μπορεί να χρησιμοποιήσει τον λογαριασμό **SYSTEM** για να ζητήσει πιστοποιητικά, παρέχοντας μια μορφή **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
This access enables the attacker to authenticate to **Kerberos** as the machine account and utilize **S4U2Self** to obtain Kerberos service tickets for any service on the host, effectively granting the attacker persistent access to the machine.

## **Extending Persistence Through Certificate Renewal - PERSIST3**

Η τελική μέθοδος που συζητείται περιλαμβάνει την εκμετάλλευση της **ισχύος** και των **περιόδων ανανέωσης** των προτύπων πιστοποιητικών. Με την **ανανεώση** ενός πιστοποιητικού πριν από την λήξη του, ένας επιτιθέμενος μπορεί να διατηρήσει την αυθεντικοποίηση στο Active Directory χωρίς την ανάγκη για επιπλέον εγγραφές εισιτηρίων, οι οποίες θα μπορούσαν να αφήσουν ίχνη στον διακομιστή Αρχής Πιστοποίησης (CA).

Αυτή η προσέγγιση επιτρέπει μια μέθοδο **εκτεταμένης επιμονής**, ελαχιστοποιώντας τον κίνδυνο ανίχνευσης μέσω λιγότερων αλληλεπιδράσεων με τον διακομιστή CA και αποφεύγοντας τη δημιουργία αντικειμένων που θα μπορούσαν να ειδοποιήσουν τους διαχειριστές για την εισβολή.

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
