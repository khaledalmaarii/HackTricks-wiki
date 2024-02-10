# BloodHound & Άλλα Εργαλεία Αναγνώρισης AD

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) είναι από το Sysinternal Suite:

> Ένα προηγμένο εργαλείο προβολής και επεξεργασίας του Active Directory (AD). Μπορείτε να χρησιμοποιήσετε το AD Explorer για να περιηγηθείτε εύκολα σε μια βάση δεδομένων AD, να ορίσετε αγαπημένες τοποθεσίες, να προβάλετε τις ιδιότητες και τα χαρακτηριστικά αντικειμένων χωρίς να ανοίγετε παράθυρα διαλόγου, να επεξεργαστείτε άδειες, να προβάλετε το σχήμα ενός αντικειμένου και να εκτελέσετε προηγμένες αναζητήσεις που μπορείτε να αποθηκεύσετε και να επαναλάβετε.

### Snapshots

Το AD Explorer μπορεί να δημιουργήσει αντίγραφα ασφαλείας μιας AD, ώστε να μπορείτε να το ελέγξετε εκτός σύνδεσης.\
Μπορεί να χρησιμοποιηθεί για να ανακαλύψετε ευπάθειες εκτός σύνδεσης ή για να συγκρίνετε διάφορες καταστάσεις της βάσης δεδομένων AD στον χρόνο.

Θα χρειαστείτε το όνομα χρήστη, τον κωδικό πρόσβασης και την κατεύθυνση για να συνδεθείτε (απαιτείται οποιοσδήποτε χρήστης AD).

Για να πάρετε ένα αντίγραφο ασφαλείας του AD, πηγαίνετε στο `File` --> `Create Snapshot` και εισαγάγετε ένα όνομα για το αντίγραφο ασφαλείας.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) είναι ένα εργαλείο που εξάγει και συνδυάζει διάφορα αρχεία από ένα περιβάλλον AD. Οι πληροφορίες μπορούν να παρουσιαστούν σε ένα **ειδικά μορφοποιημένο** αναφορά Microsoft Excel που περιλαμβάνει προβολές περίληψης με μετρήσεις για να διευκολύνει την ανάλυση και να παρέχει μια ολιστική εικόνα της τρέχουσας κατάστασης του περιβάλλοντος AD στον στόχο.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Από [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> Το BloodHound είναι μια εφαρμογή ιστού με μια σελίδα Javascript, χτισμένη πάνω στο [Linkurious](http://linkurio.us/), μεταγλωττισμένη με το [Electron](http://electron.atom.io/), με μια βάση δεδομένων [Neo4j](https://neo4j.com/) που τροφοδοτείται από έναν συλλέκτη δεδομένων C#.

Το BloodHound χρησιμοποιεί τη θεωρία γράφων για να αποκαλύψει τις κρυφές και συχνά απροσδόκητες σχέσεις μέσα σε ένα περιβάλλον Active Directory ή Azure. Οι επιτιθέμενοι μπορούν να χρησιμοποιήσουν το BloodHound για να εντοπίσουν εύκολα πολύπλοκα μονοπάτια επίθεσης που αλλιώς θα ήταν αδύνατο να εντοπιστούν γρήγορα. Οι υπερασπιστές μπορούν να χρησιμοποιήσουν το BloodHound για να εντοπίσουν και να εξαλείψουν αυτά τα ίδια μονοπάτια επίθεσης. Τόσο οι ομάδες ασφαλείας όσο και οι επιθέτες μπορούν να χρησιμοποιήσουν το BloodHound για να αποκτήσουν εύκολα μια βαθύτερη κατανόηση των σχέσεων προνομίων σε ένα περιβάλλον Active Directory ή Azure.

Έτσι, το [Bloodhound](https://github.com/BloodHoundAD/BloodHound) είναι ένα εκπληκτικό εργαλείο που μπορεί να απαριθμήσει αυτόματα έναν τομέα, να αποθηκεύσει όλες τις πληροφορίες, να βρει πιθανά μονοπάτια ανέλιξης προνομίων και να εμφανίσει όλες τις πληροφορίες χρησιμοποιώντας γραφήματα.

Το Bloodhound αποτελείται από 2 κύρια μέρη: **ingestors** και την **εφαρμογή οπτικοποίησης**.

Οι **ingestors** χρησιμοποιούνται για να **απαριθμήσουν τον τομέα και να εξάγουν όλες τις πληροφορίες** σε ένα μορφότυπο που η εφαρμογή οπτικοποίησης θα κατανοήσει.

Η **εφαρμογή οπτικοποίησης χρησιμοποιεί το neo4j** για να εμφανίσει πώς σχετίζονται όλες οι πληροφορίες και να εμφανίσει διάφορους τρόπους ανέλιξης προνομίων στον τομέα.

### Εγκατάσταση
Μετά τη δημιουργία του BloodHound CE, ολόκληρο το έργο ενημερώθηκε για ευκολία χρήσης με το Docker. Ο ευκολότερος τρόπος για να ξεκινήσετε είναι να χρησιμοποιήσετε την προδιαμορφωμένη διαμόρφωση Docker Compose.

1. Εγκαταστήστε το Docker Compose. Αυτό πρέπει να περιλαμβάνεται στην εγκατάσταση του [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Εκτελέστε:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Εντοπίστε τον τυχαία δημιουργημένο κωδικό πρόσβασης στην έξοδο του τερματικού του Docker Compose.
4. Σε έναν περιηγητή, μεταβείτε στη διεύθυνση http://localhost:8080/ui/login. Συνδεθείτε με ένα όνομα χρήστη admin και τον τυχαία δημιουργημένο κωδικό πρόσβασης από τα αρχεία καταγραφής.

Μετά από αυτό, θα πρέπει να αλλάξετε τον τυχαία δημιουργημένο κωδικό πρόσβασης και θα έχετε έτοιμη τη νέα διεπαφή, από την οποία μπορείτε να κατεβάσετε απευθείας τους ingestors.

### SharpHound

Έχουν αρκετές επιλογές, αλλά αν θέλετε να εκτελέσετε το SharpHound από έναν υπολογιστή που είναι ενταγμένος στον τομέα, χρησιμοποιώντας τον τρέχοντα χρήστη σας και εξάγοντας όλες τις πληροφορίες, μπορείτε να κάνετε τα εξής:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Μπορείτε να διαβάσετε περισσότερα για τη **CollectionMethod** και την επανάληψη της συνεδρίας [εδώ](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Εάν επιθυμείτε να εκτελέσετε το SharpHound χρησιμοποιώντας διαφορετικές πιστοποιήσεις, μπορείτε να δημιουργήσετε μια συνεδρία CMD netonly και να εκτελέσετε το SharpHound από εκεί:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Μάθε περισσότερα για το Bloodhound στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) είναι ένα εργαλείο για την εύρεση **ευπαθειών** στο Active Directory που σχετίζονται με το **Group Policy**. \
Πρέπει να **εκτελέσετε το group3r** από έναν υπολογιστή εντός του τομέα χρησιμοποιώντας **οποιονδήποτε χρήστη του τομέα**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **αξιολογεί την ασφάλεια ενός περιβάλλοντος AD** και παρέχει ένα ωραίο **αναφορά** με γραφήματα.

Για να το εκτελέσετε, μπορείτε να εκτελέσετε το δυαδικό αρχείο `PingCastle.exe` και θα ξεκινήσει μια **διαδραστική συνεδρία** που παρουσιάζει ένα μενού επιλογών. Η προεπιλεγμένη επιλογή που πρέπει να χρησιμοποιήσετε είναι **`healthcheck`**, η οποία θα δημιουργήσει μια βασική **επισκόπηση** του **domain**, και θα βρει **λανθασμένες ρυθμίσεις** και **ευπάθειες**.&#x20;

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
