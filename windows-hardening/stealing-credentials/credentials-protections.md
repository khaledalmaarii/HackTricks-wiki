# Windows Credentials Protections

## Credentials Protections

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

## WDigest

Το [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) πρωτόκολλο, που εισήχθη με τα Windows XP, έχει σχεδιαστεί για αυθεντικοποίηση μέσω του Πρωτοκόλλου HTTP και είναι **ενεργοποιημένο από προεπιλογή στα Windows XP μέχρι τα Windows 8.0 και Windows Server 2003 έως Windows Server 2012**. Αυτή η προεπιλεγμένη ρύθμιση έχει ως αποτέλεσμα **την αποθήκευση κωδικών πρόσβασης σε απλό κείμενο στο LSASS** (Local Security Authority Subsystem Service). Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει το Mimikatz για να **εξάγει αυτά τα διαπιστευτήρια** εκτελώντας:
```bash
sekurlsa::wdigest
```
Για να **απενεργοποιήσετε ή να ενεργοποιήσετε αυτή τη δυνατότητα**, τα _**UseLogonCredential**_ και _**Negotiate**_ κλειδιά μητρώου μέσα στο _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ πρέπει να ρυθμιστούν σε "1". Εάν αυτά τα κλειδιά είναι **απουσία ή ρυθμισμένα σε "0"**, το WDigest είναι **απενεργοποιημένο**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection

Αρχής γενομένης από το **Windows 8.1**, η Microsoft ενίσχυσε την ασφάλεια του LSA για να **μπλοκάρει μη εξουσιοδοτημένες αναγνώσεις μνήμης ή εισαγωγές κώδικα από μη αξιόπιστες διεργασίες**. Αυτή η βελτίωση εμποδίζει τη συνήθη λειτουργία εντολών όπως το `mimikatz.exe sekurlsa:logonpasswords`. Για να **επιτρέψετε αυτήν την ενισχυμένη προστασία**, η τιμή _**RunAsPPL**_ στο _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ θα πρέπει να ρυθμιστεί σε 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Είναι δυνατή η παράκαμψη αυτής της προστασίας χρησιμοποιώντας τον οδηγό Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, μια δυνατότητα αποκλειστική για **Windows 10 (Enterprise και Education εκδόσεις)**, ενισχύει την ασφάλεια των διαπιστευτηρίων μηχανής χρησιμοποιώντας **Virtual Secure Mode (VSM)** και **Virtualization Based Security (VBS)**. Εκμεταλλεύεται τις επεκτάσεις εικονικοποίησης CPU για να απομονώσει βασικές διαδικασίες εντός ενός προστατευμένου χώρου μνήμης, μακριά από την προσέγγιση του κύριου λειτουργικού συστήματος. Αυτή η απομόνωση διασφαλίζει ότι ακόμη και ο πυρήνας δεν μπορεί να έχει πρόσβαση στη μνήμη στο VSM, προστατεύοντας αποτελεσματικά τα διαπιστευτήρια από επιθέσεις όπως το **pass-the-hash**. Η **Local Security Authority (LSA)** λειτουργεί εντός αυτού του ασφαλούς περιβάλλοντος ως trustlet, ενώ η διαδικασία **LSASS** στο κύριο OS λειτουργεί απλώς ως επικοινωνιακός σύνδεσμος με την LSA του VSM.

Από προεπιλογή, **Credential Guard** δεν είναι ενεργό και απαιτεί χειροκίνητη ενεργοποίηση εντός ενός οργανισμού. Είναι κρίσιμο για την ενίσχυση της ασφάλειας κατά εργαλείων όπως το **Mimikatz**, τα οποία περιορίζονται στην ικανότητά τους να εξάγουν διαπιστευτήρια. Ωστόσο, οι ευπάθειες μπορούν να εκμεταλλευτούν μέσω της προσθήκης προσαρμοσμένων **Security Support Providers (SSP)** για να συλλάβουν διαπιστευτήρια σε καθαρό κείμενο κατά τις προσπάθειες σύνδεσης.

Για να επαληθεύσετε την κατάσταση ενεργοποίησης του **Credential Guard**, μπορεί να ελεγχθεί το κλειδί μητρώου _**LsaCfgFlags**_ κάτω από _**HKLM\System\CurrentControlSet\Control\LSA**_. Μια τιμή "**1**" υποδηλώνει ενεργοποίηση με **UEFI lock**, "**2**" χωρίς κλείδωμα, και "**0**" δηλώνει ότι δεν είναι ενεργοποιημένο. Αυτός ο έλεγχος μητρώου, αν και είναι ισχυρός δείκτης, δεν είναι το μόνο βήμα για την ενεργοποίηση του Credential Guard. Λεπτομερείς οδηγίες και ένα σενάριο PowerShell για την ενεργοποίηση αυτής της δυνατότητας είναι διαθέσιμα online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Για μια ολοκληρωμένη κατανόηση και οδηγίες σχετικά με την ενεργοποίηση του **Credential Guard** στα Windows 10 και την αυτόματη ενεργοποίησή του σε συμβατά συστήματα του **Windows 11 Enterprise και Education (έκδοση 22H2)**, επισκεφθείτε την [τεκμηρίωση της Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Περισσότερες λεπτομέρειες σχετικά με την υλοποίηση προσαρμοσμένων SSP για την καταγραφή διαπιστευτηρίων παρέχονται [σε αυτόν τον οδηγό](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 και Windows Server 2012 R2** εισήγαγαν πολλές νέες δυνατότητες ασφαλείας, συμπεριλαμβανομένου του _**Restricted Admin mode για RDP**_. Αυτή η λειτουργία σχεδιάστηκε για να ενισχύσει την ασφάλεια μειώνοντας τους κινδύνους που σχετίζονται με τις επιθέσεις [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Παραδοσιακά, όταν συνδέεστε σε έναν απομακρυσμένο υπολογιστή μέσω RDP, τα διαπιστευτήριά σας αποθηκεύονται στη στοχοθετημένη μηχανή. Αυτό συνιστά σημαντικό κίνδυνο ασφαλείας, ειδικά όταν χρησιμοποιείτε λογαριασμούς με αυξημένα δικαιώματα. Ωστόσο, με την εισαγωγή του _**Restricted Admin mode**_, αυτός ο κίνδυνος μειώνεται σημαντικά.

Όταν ξεκινάτε μια σύνδεση RDP χρησιμοποιώντας την εντολή **mstsc.exe /RestrictedAdmin**, η αυθεντικοποίηση στον απομακρυσμένο υπολογιστή πραγματοποιείται χωρίς να αποθηκεύονται τα διαπιστευτήριά σας σε αυτόν. Αυτή η προσέγγιση διασφαλίζει ότι, σε περίπτωση μόλυνσης από κακόβουλο λογισμικό ή αν ένας κακόβουλος χρήστης αποκτήσει πρόσβαση στον απομακρυσμένο διακομιστή, τα διαπιστευτήριά σας δεν θα διακυβευτούν, καθώς δεν αποθηκεύονται στον διακομιστή.

Είναι σημαντικό να σημειωθεί ότι στο **Restricted Admin mode**, οι προσπάθειες πρόσβασης σε πόρους δικτύου από τη συνεδρία RDP δεν θα χρησιμοποιούν τα προσωπικά σας διαπιστευτήρια. Αντίθετα, χρησιμοποιείται η **ταυτότητα της μηχανής**.

Αυτή η δυνατότητα σηματοδοτεί ένα σημαντικό βήμα προς τα εμπρός στην ασφάλιση των απομακρυσμένων συνδέσεων επιφάνειας εργασίας και στην προστασία ευαίσθητων πληροφοριών από την έκθεση σε περίπτωση παραβίασης ασφαλείας.

![](../../.gitbook/assets/RAM.png)

Για περισσότερες λεπτομέρειες επισκεφθείτε [αυτή την πηγή](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Τα Windows ασφαλίζουν τα **διαπιστευτήρια τομέα** μέσω της **Τοπικής Αρχής Ασφαλείας (LSA)**, υποστηρίζοντας τις διαδικασίες σύνδεσης με πρωτόκολλα ασφαλείας όπως το **Kerberos** και το **NTLM**. Μια βασική δυνατότητα των Windows είναι η ικανότητά τους να αποθηκεύουν στην κρυφή μνήμη τις **τελευταίες δέκα συνδέσεις τομέα** για να διασφαλίσουν ότι οι χρήστες μπορούν να έχουν πρόσβαση στους υπολογιστές τους ακόμη και αν ο **διακομιστής τομέα είναι εκτός σύνδεσης**—ένα πλεονέκτημα για τους χρήστες φορητών υπολογιστών που συχνά βρίσκονται μακριά από το δίκτυο της εταιρείας τους.

Ο αριθμός των αποθηκευμένων συνδέσεων είναι ρυθμιζόμενος μέσω ενός συγκεκριμένου **κλειδιού μητρώου ή πολιτικής ομάδας**. Για να δείτε ή να αλλάξετε αυτή τη ρύθμιση, χρησιμοποιείται η εξής εντολή:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Η πρόσβαση σε αυτές τις αποθηκευμένες διαπιστεύσεις ελέγχεται αυστηρά, με μόνο τον λογαριασμό **SYSTEM** να έχει τις απαραίτητες άδειες για να τις δει. Οι διαχειριστές που χρειάζονται πρόσβαση σε αυτές τις πληροφορίες πρέπει να το κάνουν με δικαιώματα χρήστη SYSTEM. Οι διαπιστεύσεις αποθηκεύονται στο: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** μπορεί να χρησιμοποιηθεί για την εξαγωγή αυτών των αποθηκευμένων διαπιστεύσεων χρησιμοποιώντας την εντολή `lsadump::cache`.

Για περισσότερες λεπτομέρειες, η αρχική [πηγή](http://juggernaut.wikidot.com/cached-credentials) παρέχει εκτενή πληροφορίες.

## Protected Users

Η συμμετοχή στην **ομάδα Protected Users** εισάγει αρκετές βελτιώσεις ασφαλείας για τους χρήστες, εξασφαλίζοντας υψηλότερα επίπεδα προστασίας κατά της κλοπής και κακής χρήσης διαπιστεύσεων:

* **Credential Delegation (CredSSP)**: Ακόμα και αν η ρύθμιση Πολιτικής Ομάδας για **Allow delegating default credentials** είναι ενεργοποιημένη, οι διαπιστεύσεις κειμένου απλού των Protected Users δεν θα αποθηκευτούν.
* **Windows Digest**: Από **Windows 8.1 και Windows Server 2012 R2**, το σύστημα δεν θα αποθηκεύει τις διαπιστεύσεις κειμένου απλού των Protected Users, ανεξάρτητα από την κατάσταση του Windows Digest.
* **NTLM**: Το σύστημα δεν θα αποθηκεύει τις διαπιστεύσεις κειμένου απλού των Protected Users ή τις μονοκατευθυντικές συναρτήσεις NT (NTOWF).
* **Kerberos**: Για τους Protected Users, η πιστοποίηση Kerberos δεν θα δημιουργεί **DES** ή **RC4 keys**, ούτε θα αποθηκεύει διαπιστεύσεις κειμένου απλού ή μακροχρόνιες κλειδαριές πέρα από την αρχική απόκτηση του Ticket-Granting Ticket (TGT).
* **Offline Sign-In**: Οι Protected Users δεν θα έχουν έναν αποθηκευμένο επαληθευτή που θα δημιουργείται κατά την είσοδο ή την ξεκλείδωμα, πράγμα που σημαίνει ότι η offline είσοδος δεν υποστηρίζεται για αυτούς τους λογαριασμούς.

Αυτές οι προστασίες ενεργοποιούνται τη στιγμή που ένας χρήστης, ο οποίος είναι μέλος της **ομάδας Protected Users**, συνδέεται στη συσκευή. Αυτό εξασφαλίζει ότι κρίσιμα μέτρα ασφαλείας είναι σε εφαρμογή για την προστασία από διάφορες μεθόδους παραβίασης διαπιστεύσεων.

Για περισσότερες λεπτομερείς πληροφορίες, ανατρέξτε στην επίσημη [τεκμηρίωση](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Πίνακας από** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

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
