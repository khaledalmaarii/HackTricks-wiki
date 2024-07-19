# Unconstrained Delegation

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

## Unconstrained delegation

Αυτή είναι μια δυνατότητα που μπορεί να ρυθμίσει ένας Διαχειριστής Τομέα σε οποιονδήποτε **Υπολογιστή** μέσα στον τομέα. Έτσι, κάθε φορά που ένας **χρήστης συνδέεται** στον Υπολογιστή, ένα **αντίγραφο του TGT** αυτού του χρήστη θα **σταλεί μέσα στο TGS** που παρέχεται από τον DC **και θα αποθηκευτεί στη μνήμη στο LSASS**. Έτσι, αν έχετε δικαιώματα Διαχειριστή στη μηχανή, θα μπορείτε να **dump τα εισιτήρια και να προσποιηθείτε τους χρήστες** σε οποιαδήποτε μηχανή.

Έτσι, αν ένας διαχειριστής τομέα συνδεθεί σε έναν Υπολογιστή με ενεργοποιημένη τη δυνατότητα "Unconstrained Delegation", και έχετε τοπικά δικαιώματα διαχειριστή σε αυτή τη μηχανή, θα μπορείτε να dump το εισιτήριο και να προσποιηθείτε τον Διαχειριστή Τομέα οπουδήποτε (domain privesc).

Μπορείτε να **βρείτε αντικείμενα Υπολογιστή με αυτό το χαρακτηριστικό** ελέγχοντας αν το [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) χαρακτηριστικό περιέχει [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Μπορείτε να το κάνετε αυτό με ένα φίλτρο LDAP του ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, το οποίο είναι αυτό που κάνει το powerview:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

Φορτώστε το εισιτήριο του Διαχειριστή (ή του θύματος χρήστη) στη μνήμη με **Mimikatz** ή **Rubeus για ένα** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Περισσότερες πληροφορίες σχετικά με την Unconstrained delegation στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Αν ένας επιτιθέμενος είναι σε θέση να **συμβιβάσει έναν υπολογιστή που επιτρέπεται για "Unconstrained Delegation"**, θα μπορούσε να **παραπλανήσει** έναν **Print server** να **συνδεθεί αυτόματα** σε αυτόν **αποθηκεύοντας ένα TGT** στη μνήμη του διακομιστή.\
Έτσι, ο επιτιθέμενος θα μπορούσε να εκτελέσει μια **επίθεση Pass the Ticket για να προσποιηθεί** τον λογαριασμό υπολογιστή του Print server.

Για να κάνετε έναν εκτυπωτή server να συνδεθεί σε οποιαδήποτε μηχανή μπορείτε να χρησιμοποιήσετε [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Αν το TGT προέρχεται από έναν ελεγκτή τομέα, μπορείτε να εκτελέσετε μια[ **DCSync attack**](acl-persistence-abuse/#dcsync) και να αποκτήσετε όλους τους κατακερματισμούς από τον DC.\
[**Περισσότερες πληροφορίες σχετικά με αυτήν την επίθεση στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Ακολουθούν άλλοι τρόποι για να προσπαθήσετε να επιβάλετε μια αυθεντικοποίηση:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Mitigation

* Περιορίστε τις συνδέσεις DA/Admin σε συγκεκριμένες υπηρεσίες
* Ορίστε "Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να ανατεθεί" για προνομιακούς λογαριασμούς.

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
