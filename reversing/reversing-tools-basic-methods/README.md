# Εργαλεία Αναστροφής & Βασικές Μέθοδοι

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Εργαλεία Αναστροφής Βασισμένα στο ImGui

Λογισμικό:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm αποσυνταγματοποιητής / Μεταγλωττιστής Wat

Online:

* Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **αποσυνταγματοποίηση** από wasm (δυαδικό) σε wat (καθαρό κείμενο)
* Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **μεταγλώττιση** από wat σε wasm
* Μπορείτε επίσης να δοκιμάσετε να χρησιμοποιήσετε το [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) για αποσυνταγματοποίηση

Λογισμικό:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET αποσυνταγματοποιητής

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας αποσυνταγματοποιητής που **αποσυνταγματοποιεί και εξετάζει πολλές μορφές**, συμπεριλαμβανομένων των **βιβλιοθηκών** (.dll), των **αρχείων μεταδεδομένων των Windows** (.winmd) και των **εκτελέσιμων αρχείων** (.exe). Αφού αποσυνταγματοποιηθεί, μια συναρμολόγηση μπορεί να αποθηκευτεί ως ένα έργο Visual Studio (.csproj).

Το πλεονέκτημα εδώ είναι ότι αν ένας χαμένος πηγαίος κώδικας απαιτεί ανάκτηση από έναν κληρονομικό συναρμολόγηση, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει βολική πλοήγηση σε ολόκληρο τον αποσυνταγματοποιημένο κώδικα, κάνοντάς το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα πλήρες μοντέλο πρόσθετων και μια API που επεκτείνει το εργαλείο για να ταιριάζει με τις ακριβείς ανάγκες σας, το .NET reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας ρίξουμε μια ματιά στην πληθώρα υπηρεσιών αναστροφής που παρέχει αυτό το εργαλείο:

* Παρέχει μια εικόνα για το πώς ρέει τα δεδομένα μέσω μιας βιβλιοθήκης ή ενός στοιχείου
* Παρέχει εικόνα για την υλοποίηση και χρήση των γλωσσών και πλαισίων του .NET
* Βρίσκει μη τεκμηριωμένη και μη εκτεθειμένη λειτουργικότητα για να αξιοποιήσετε περισσότερα από τις APIs και τις τεχνολογίες που χρησιμοποιούνται.
* Βρίσκει εξαρτήσεις και διαφορετικές συναρμογές
* Εντοπίζει την ακριβή τοποθεσία των σφαλμάτων στον κώδικά σας, σε συστατικά τρίτων και βιβλιοθήκες.
* Κάνει αποσφαλμάτωση στην πηγή όλου του κώδικα .NET με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Πρόσθετο ILSpy για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το έχετε σε οποιοδήποτε λειτουργικό σύστημα (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στις **Επεκτάσεις** και **αναζητήστε το ILSpy**).\
Αν χρειάζεστε να **αποσυνταγματοποιήσετε**, **τροποποιήσετε** και **επανασυνταγματοποιήσετε** ξανά, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή μια ενεργά συντηρούμενη παρακλάδια του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια λειτουργία).

### Καταγραφή DNSpy

Για να κάνετε το **DNSpy να καταγράφει κάποιες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το απόσπασμα:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Αποσφαλμάτωση με το DNSpy

Για να αποσφαλματώσετε κώδικα χρησιμοποιώντας το DNSpy πρέπει να:

Πρώτα, αλλάξτε τα **Χαρακτηριστικά Συναρμολόγησης** που σχετίζονται με τη **αποσφαλμάτωση**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Προς:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Και κάντε κλικ στο **compile**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Στη συνέχεια αποθηκεύστε το νέο αρχείο μέσω _**File >> Save module...**_:

![](<../../.gitbook/assets/image (279).png>)

Αυτό είναι απαραίτητο επειδή αν δεν το κάνετε αυτό, κατά τη διάρκεια της **εκτέλεσης** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και είναι δυνατόν να μην επιτευχθεί ποτέ ένα **σημείο διακοπής** κατά την αποσφαλμάτωση ή να μην υπάρχουν κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή σας .NET τρέχει μέσω του **IIS**, μπορείτε να την **επανεκκινήσετε** με:
```
iisreset /noforce
```
Στη συνέχεια, για να ξεκινήσετε την εντοπισμό σφαλμάτων, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και εντός της **Καρτέλας Εντοπισμού Σφαλμάτων** επιλέξτε **Σύνδεση σε Διεργασία...**:

![](<../../.gitbook/assets/image (280).png>)

Στη συνέχεια, επιλέξτε **w3wp.exe** για να συνδεθείτε στο **IIS server** και κάντε κλικ στο **σύνδεση**:

![](<../../.gitbook/assets/image (281).png>)

Τώρα που είμαστε στη διαδικασία εντοπισμού σφαλμάτων, είναι καιρός να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Κάντε κλικ πρώτα σε _Debug >> Διακοπή Όλων_ και στη συνέχεια κάντε κλικ σε _**Debug >> Παράθυρα >> Modules**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Κάντε κλικ σε οποιοδήποτε module στα **Modules** και επιλέξτε **Άνοιγμα Όλων των Modules**:

![](<../../.gitbook/assets/image (284).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Εξερευνητή Συναρτήσεων** και κάντε κλικ σε **Ταξινόμηση Συναρτήσεων**:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Χρησιμοποιώντας το IDA

* **Φορτώστε το rundll32** (64bit στο C:\Windows\System32\rundll32.exe και 32 bit στο C:\Windows\SysWOW64\rundll32.exe)
* Επιλέξτε τον **Αποσφαλματωτή Windbg**
* Επιλέξτε "**Διακοπή στη φόρτωση/εκφόρτωση βιβλιοθήκης**"

![](<../../.gitbook/assets/image (135).png>)

* Διαμορφώστε τις **παραμέτρους** της εκτέλεσης βάζοντας το **μονοπάτι προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![](<../../.gitbook/assets/image (136).png>)

Στη συνέχεια, όταν ξεκινήσετε τον εντοπισμό σφαλμάτων, η εκτέλεση θα σταματά όταν φορτώνεται κάθε DLL, έτσι όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα σταματήσει.

Αλλά, πώς μπορείτε να φτάσετε στον κώδικα του DLL που φορτώθηκε; Χρησιμοποιώντας αυτήν τη μέθοδο, δεν ξέρω πώς.

### Χρησιμοποιώντας x64dbg/x32dbg

* **Φορτώστε το rundll32** (64bit στο C:\Windows\System32\rundll32.exe και 32 bit στο C:\Windows\SysWOW64\rundll32.exe)
* **Αλλάξτε τη γραμμή εντολών** (_Αρχείο --> Αλλαγή Γραμμής Εντολών_) και ορίστε το μονοπάτι του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Αλλάξτε _Επιλογές --> Ρυθμίσεις_ και επιλέξτε "**Είσοδος DLL**".
* Στη συνέχεια **ξεκινήστε την εκτέλεση**, ο αποσφαλματωτής θα σταματήσει σε κάθε κύρια dll, σε κάποιο σημείο θα **σταματήσετε στην είσοδο της dll** σας. Από εκεί, απλά αναζητήστε τα σημεία όπου θέλετε να τοποθετήσετε ένα σημείο διακοπής.

Σημειώστε ότι όταν η εκτέλεση σταματάει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτώντας στην **κορυφή του παραθύρου win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Έτσι, κοιτώντας αυτό μπορείτε να δείτε πότε η εκτέλεση σταμάτησε στην dll που θέλετε να εντοπίσετε.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να βρείτε πού αποθηκεύονται σημαντικές τιμές μέσα στη μνήμη ενός τρέχοντος παιχνιδιού και να τις αλλάξετε. Περισσότερες πληροφορίες στο:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Αποσφαλμάτωση ενός shellcode με το blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) θα **εκχωρήσει** το **shellcode** μέσα σε ένα χώρο μνήμης, θα **εμφανίσει** τη **διεύθυνση μνήμης** όπου εκχωρήθηκε το shellcode και θα **σταματήσει** την εκτέλεση.\
Στη συνέχεια, πρέπει να **συνδέσετε έναν αποσφαλματή** (Ida ή x64dbg) στη διαδικασία και να τοποθετήσετε ένα **σημείο διακοπής στην υποδειγμένη διεύθυνση μνήμης** και να **συνεχίσετε** την εκτέλεση. Με αυτόν τον τρόπο θα αποσφαλματίζετε το shellcode.

Η σελίδα κυκλοφορίας του github περιέχει zip που περιέχουν τις συνταγμένες κυκλοφορίες: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον ακόλουθο σύνδεσμο. Για να το συντάξετε, απλά **δημιουργήστε ένα έργο C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε την κατασκευή**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Αποσφαλμάτωση ενός shellcode με το jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)είναι πολύ παρόμοιο με το blobrunner. Θα **εκχωρήσει** το **shellcode** μέσα σε ένα χώρο μνήμης και θα ξεκινήσει ένα **αιώνιο βρόχο**. Στη συνέχεια πρέπει να **συνδέσετε τον αποσφαλματή** στη διαδικασία, **να ξεκινήσετε, να περιμένετε 2-5 δευτερόλεπτα και να πατήσετε σταμάτημα** και θα βρεθείτε μέσα στον **αιώνιο βρόχο**. Μεταβείτε στην επόμενη εντολή του αιώνιου βρόχου καθώς θα είναι μια κλήση στο shellcode, και τελικά θα βρεθείτε να εκτελείτε το shellcode.

![](<../../.gitbook/assets/image (397).png>)

Μπορείτε να κατεβάσετε μια συνταγμένη έκδοση του [jmp2it μέσα στη σελίδα κυκλοφορίας](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode χρησιμοποιώντας το Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Χρησιμοποιώντας το Cutter μπορείτε να εξομοιώσετε το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να "Ανοίξετε Αρχείο" και "Ανοίξετε Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο το αποκώδισε σωστά, αλλά όταν το άνοιξα ως shellcode δεν το έκανε:

![](<../../.gitbook/assets/image (400).png>)

Για να ξεκινήσετε την εξομοίωση στο σημείο που θέλετε, ορίστε ένα bp εκεί και φαίνεται ότι το Cutter θα ξεκινήσει αυτόματα την εξομοίωση από εκεί:

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

Μπορείτε να δείτε τη στοίβα για παράδειγμα μέσα σε ένα αποσπώμενο hex dump:

![](<../../.gitbook/assets/image (402).png>)

### Αποκωδικοποίηση shellcode και λήψη εκτελούμενων συναρτήσεων

Θα πρέπει να δοκι
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg διαθέτει επίσης ένα γραφικό εκκινητή, όπου μπορείτε να επιλέξετε τις επιλογές που θέλετε και να εκτελέσετε το shellcode

![](<../../.gitbook/assets/image (398).png>)

Η επιλογή **Create Dump** θα ανακτήσει το τελικό shellcode εάν γίνει οποιαδήποτε αλλαγή δυναμικά στο shellcode στη μνήμη (χρήσιμο για να κατεβάσετε το αποκωδικοποιημένο shellcode). Το **start offset** μπορεί να είναι χρήσιμο για να ξεκινήσετε το shellcode σε συγκεκριμένη θέση. Η επιλογή **Debug Shell** είναι χρήσιμη για να εκτελέσετε αποσφαλματωμένο το shellcode χρησιμοποιώντας το τερματικό scDbg (ωστόσο θεωρώ ότι οποιαδήποτε από τις προηγούμενα εξηγημένες επιλογές είναι καλύτερη για αυτό το θέμα, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση χρησιμοποιώντας το CyberChef

Μεταφορτώστε το αρχείο shellcode σας ως είσοδο και χρησιμοποιήστε την ακόλουθη συνταγή για να αποσυναρμολογήσετε τον κώδικα: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator **τροποποιεί όλες τις οδηγίες για `mov`** (ναι, πραγματικά καλό). Χρησιμοποιεί επίσης διακοπές για να αλλάξει τις ροές εκτέλεσης. Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργεί:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Εάν έχετε τύχη, το [demovfuscator](https://github.com/kirschju/demovfuscator) θα αποκωδικοποιήσει το δυαδικό αρχείο. Έχει αρκετές εξαρτήσεις
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Εάν παίζετε ένα **CTF, αυτή η μέθοδος για την εύρεση της σημαίας** μπορεί να είναι πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου** αναζητήστε τις συναρτήσεις με το `::main` όπως στο:

![](<../../.gitbook/assets/image (612).png>)

Σε αυτήν την περίπτωση το δυαδικό αρχείο ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα κύρια συνάρτηση.\
Έχοντας το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Διαδίκτυο** για να μάθετε για τις **εισόδους** και **εξόδους** τους.

## **Delphi**

Για δυαδικά αρχεία που έχουν συνταχθεί με Delphi μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Εάν πρέπει να αναστρέψετε ένα δυαδικό αρχείο Delphi, θα σας πρότεινα να χρησιμοποιήσετε το πρόσθετο IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Απλά πατήστε **ATL+f7** (εισαγωγή πρόσθετου python στο IDA) και επιλέξτε το πρόσθετο python.

Αυτό το πρόσθετο θα εκτελέσει το δυαδικό αρχείο και θα επιλύσει δυναμικά τα ονόματα των συναρτήσεων στην έναρξη της αποσφαλμάτωσης. Μετά την έναρξη της αποσφαλμάτωσης, πατήστε ξανά το κουμπί Έναρξης (το πράσινο ή f9) και θα ενεργοποιηθεί ένα σημείο αναστολής στην αρχή του πραγματικού κώδικα.

Είναι επίσης πολύ ενδιαφέρον επειδή εάν πατήσετε ένα κουμπί στη γραφική εφαρμογή, το αποσφαλματωτής θα σταματήσει στη συνάρτηση που εκτελείται από αυτό το κουμπί.

## Golang

Εάν πρέπει να αναστρέψετε ένα δυαδικό αρχείο Golang, θα σας πρότεινα να χρησιμοποιήσετε το πρόσθετο IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Απλά πατήστε **ATL+f7** (εισαγωγή πρόσθετου python στο IDA) και επιλέξτε το πρόσθετο python.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

## Συνταγμένο Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να αντλήσετε τον κώδικα Python από ένα δυαδικό αρχείο Python που έχει συνταχθεί ως ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Εάν έχετε το **δυαδικό** ενός παιχνιδιού GBA μπορείτε να χρησιμοποιήσετε διαφορετικά εργαλεία για να το **εμμονήσετε** και να το **αποσφαλματώσετε**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Λήψη της εκδοσης αποσφαλμάτωσης_) - Περιλαμβάνει έναν αποσφαλματωτή με διεπαφή
* [**mgba** ](https://mgba.io)- Περιλαμβάνει έναν αποσφαλματωτή CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Πρόσθετο Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Πρόσθετο Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Επιλογές --> Ρύθμιση Εξομοίωσης --> Ελέγχους**_\*\* \*\* μπορείτε να δείτε πώς να πατήσετε τα κουμπιά του Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Όταν πατιούνται, κάθε **κλειδί έχει μια τιμή** για να το αναγνωρίσετε:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Έτσι, σε αυτον τον τύπο προγράμματος, το ενδιαφέρον θα είναι **πώς το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνάρτηση που συναντάται συχνά: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN\_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε εκείνη τη συνάρτηση, μετά από μερικές λειτουργίες εκκίνησης (χωρίς καμία σημασία):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Βρέθηκε αυτός ο κώδικας:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **τελευταία Keys** και δεν είναι το τρέχον κλειδί, επίσης ονομάζεται αφήνοντας ένα κουμπί (το τρέχον κλειδί αποθηκεύεται στο **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε το **uVar1** (το μέρος όπου βρίσκεται η **τιμή του πατημένου κουμπιού**) με μερικές τιμές:

* Αρχικά, συγκρίνεται με τη **τιμή 4** (κουμπί **SELECT**): Στην πρόκληση αυτό το κουμπί καθαρίζει την οθόνη
* Στη συνέχεια, συγκρίνεται με τη **τιμή 8** (κουμπί **START**): Στην πρόκληση αυτό ελέγχει αν ο κώδικας είναι έγκυρος για να λάβετε τη σημαία.
* Σε αυτήν την περίπτωση η μεταβλητή **`DAT_030000d8`** συγκρίνεται με 0xf3 και αν η τιμή είναι ίδια εκτελείται κάποιος κώδικας.
* Σε οποιεσδήποτε άλλες περιπτώσεις, ελέγχεται μια μεταβλητή cont (`DAT_030000d4`). Είναι μια μεταβλητή cont επειδή προστίθεται 1 αμέσως μετά την εισαγωγή του κώδικα.\
Αν είναι λιγότερο από 8 κάτι που περιλαμβάνει την **προσθήκη** τιμών στο **`DAT_030000d8`** γίνεται (βασικά προσθέτει τις τιμές των πλήκτρων που πατήθηκαν σε αυτήν τη μεταβλητή όσο η μεταβλητή cont είναι μικρότερη από 8).

Έτσι, σε αυτήν την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε μια συνδυασμό με μήκος μικρότερο από 8 ώστε το αποτέλεσμα της πρόσθεσης να είναι 0xf3.**
