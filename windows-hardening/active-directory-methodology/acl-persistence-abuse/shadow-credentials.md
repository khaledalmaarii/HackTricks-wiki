# Σκιώδεις Διαπιστευτήρια

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) **στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Εισαγωγή <a href="#3f17" id="3f17"></a>

**Ελέγξτε την αρχική ανάρτηση για [όλες τις πληροφορίες σχετικά με αυτήν την τεχνική](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Συνοπτικά: αν μπορείτε να γράψετε στην ιδιότητα **msDS-KeyCredentialLink** ενός χρήστη/υπολογιστή, μπορείτε να ανακτήσετε το **NT hash αυτού του αντικειμένου**.

Στην ανάρτηση, περιγράφεται μια μέθοδος για τη δημιουργία δημόσιων-ιδιωτικών κλειδιών για την απόκτηση ενός μοναδικού **Service Ticket** που περιλαμβάνει το NTLM hash του στόχου. Αυτή η διαδικασία περιλαμβάνει τον κρυπτογραφημένο NTLM_SUPPLEMENTAL_CREDENTIAL μέσα στο Privilege Attribute Certificate (PAC), το οποίο μπορεί να αποκρυπτογραφηθεί.

### Απαιτήσεις

Για να εφαρμόσετε αυτήν την τεχνική, πρέπει να πληρούνται ορισμένες προϋποθέσεις:
- Χρειάζεται τουλάχιστον ένας Windows Server 2016 Domain Controller.
- Ο Domain Controller πρέπει να έχει εγκατεστημένο ένα ψηφιακό πιστοποιητικό επαλήθευσης του διακομιστή.
- Το Active Directory πρέπει να είναι στο επίπεδο λειτουργίας του Windows Server 2016.
- Απαιτείται ένας λογαριασμός με εξουσιοδοτημένα δικαιώματα για την τροποποίηση της ιδιότητας msDS-KeyCredentialLink του στοχευμένου αντικειμένου.

## Κατάχρηση

Η κατάχρηση του Key Trust για αντικείμενα υπολογιστών περιλαμβάνει βήματα πέρα ​​από την απόκτηση ενός Ticket Granting Ticket (TGT) και του NTLM hash. Οι επιλογές περιλαμβάνουν:
1. Δημιουργία ενός **RC4 silver ticket** για να λειτουργήσει ως προνομιούχος χρήστης στον επιθυμητό κεντρικό υπολογιστή.
2. Χρήση του TGT με το **S4U2Self** για εμψύχωση **προνομιούχων χρηστών**, απαιτώντας τροποποιήσεις στο Service Ticket για να προστεθεί μια κλάση υπηρεσίας στο όνομα της υπηρεσίας.

Ένα σημαντικό πλεονέκτημα της κατάχρησης του Key Trust είναι η περιορισμένη χρήση του ιδιωτικού κλειδιού που δημιουργεί ο επιτιθέμενος, αποφεύγοντας την ανάθεση σε πιθανά ευάλωτους λογαριασμούς και χωρίς να απαιτείται η δημιουργία ενός λογαριασμού υπολογιστή, που μπορεί να είναι δύσκολο να αφαιρεθεί.

## Εργαλεία

### [**Whisker**](https://github.com/eladshamir/Whisker)

Βασίζεται στο DSInternals και παρέχει μια διεπαφή C# για αυτήν την επίθεση. Το Whisker και η αντίστοιχη Python έκδοσή του, **pyWhisker**, επιτρέπουν την επεξεργασία της ιδιότητας `msDS-KeyCredentialLink` για τον έλεγχο των λογαριασμών Active Directory. Αυτά τα εργαλεία υποστηρίζουν διάφορες λειτουργίες όπως προσθήκη, λίστα, αφαίρεση και εκκαθάριση κλειδιών διαπιστευτηρίων από το στοχευμένο αντικείμενο.

Οι λειτουργίες του **Whisker** περιλαμβάνουν:
- **Add**: Δημιουργεί ένα ζευγάρι κλειδιών και προσθέτει ένα κλειδί διαπιστευτηρίου.
- **List**: Εμφανίζει όλες τις καταχωρήσεις κλειδιών διαπιστευτηρίων.
- **Remove**: Διαγράφει ένα συγκεκριμένο κλειδί διαπιστευτηρίου.
- **Clear**: Διαγράφει όλα τα κλειδιά διαπιστευτηρίων, προκαλώντας πιθανή διαταραχή της νόμιμης χρήσης του WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Επεκτείνει τη λειτουργικότητα του Whisker σε συστήματα βασισμένα σε **UNIX**, εκμεταλλευόμενο το Impacket και το PyDSInternals για πλήρεις δυνατότητες εκμετάλλευσης, συμπεριλαμβανομένης της λίστας, προσθήκης και αφαίρεσης KeyCredentials, καθώς και την εισαγωγή και εξαγωγή τους σε μορφή JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Το ShadowSpray στοχεύει να **εκμεταλλευτεί τα δικαιώματα GenericWrite/GenericAll που ευρέως ομάδες χρηστών μπορεί να έχουν πάνω σε αντικείμενα του τομέα** για να εφαρμόσει ευρέως τα ShadowCredentials. Περιλαμβάνει την είσοδο στον τομέα, τον έλεγχο του επιπέδου λειτουργικότητας του τομέα, την απαρίθμηση των αντικειμένων του τομέα και την προσπάθεια προσθήκης KeyCredentials για την απόκτηση TGT και την αποκάλυψη του NT hash. Οι επιλογές καθαρισμού και οι τακτικές αναδρομικής εκμετάλλευσης ενισχύουν τη χρησιμότητά του.


## Αναφορές

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
