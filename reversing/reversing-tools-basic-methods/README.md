# Εργαλεία αναστροφής και βασικές μέθοδοι

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές σάρωσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από APIs έως web εφαρμογές και συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Εργαλεία αναστροφής βασισμένα στο ImGui

Λογισμικό:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm αποσυνταγματοποιητής / μεταγλωττιστής Wat

Online:

* Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για να **αποσυνταγματοποιήσετε** από wasm (δυαδικό) σε wat (καθαρό κείμενο)
* Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για να **μεταγλωττίσετε** από wat σε wasm
* μπορείτε επίσης να δοκιμάσετε να χρησιμοποιήσετε το [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) για αποσυνταγματοποίηση

Λογισμικό:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net αποσυνταγματοποιητής

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας αποσυνταγματοποιητής που **αποσυνταγματοποιεί και εξετάζει πολλές μορφές**, συμπεριλαμβανομένων των **βιβλιοθηκών** (.dll), των **αρχείων μεταδεδομένων των Windows** (.winmd) και των **εκτελέσιμων αρχείων** (.exe). Μόλις αποσυνταγματοποιηθεί, μια συλλογή μπορεί να αποθηκευτεί ως ένα έργο Visual Studio (.csproj).

Το πλεονέκτημα εδώ είναι ότι εάν ένας χαμένος πηγαίος κώδικας απαιτεί αποκατάσταση από μια παλαιότερη συλλογή, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει βολική πλοήγηση σε όλον τον αποσυνταγματοποιημένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για ανάλυση αλγορίθμων Xamarin.

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Με έναν εκτεταμένο μοντέλο πρόσθετων και μια API που επεκτείνει το εργαλείο για να ταιριάζει με τις ακριβείς ανάγκες σας, το .NET reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας ρίξουμε μια ματιά στην πληθώρα υπηρεσιών ανάπτυξης ανάποδης μηχανικής που παρέχει αυτό το εργαλείο:

* Παρέχει μια εικόνα για το πώς ρέει οι δεδομένα μέσα από μια βιβλιοθήκη ή ένα συστατικό
* Παρέχει μια εικόνα για την υλοποίηση και χρήση των γλωσσών και πλαισίων του .NET
* Βρίσκει μη τεκμηριωμένη και μη αποκαλυπτόμενη λειτουργικότητα για να αξιοποιήσει περισσότερα από τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
* Βρίσκει εξαρτήσεις και διάφορες συλλογές
* Εντοπίζει την ακριβή τοποθεσία των σφαλμάτων στον κώδικά σας, σε συστατικά τρίτων και σε βιβλιοθήκες.
* Αποσφαλματώνει τον πηγ
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Αποσφαλμάτωση με το DNSpy

Για να αποσφαλματώσετε κώδικα χρησιμοποιώντας το DNSpy, πρέπει να ακολουθήσετε τα παρακάτω βήματα:

Πρώτα, αλλάξτε τα **χαρακτηριστικά συναρτήσεων** που σχετίζονται με την **αποσφαλμάτωση**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Προς: 

Αυτό είναι το περιεχόμενο από ένα βιβλίο για χάκινγκ σχετικά με τεχνικές χάκινγκ. Το παρακάτω περιεχόμενο είναι από το αρχείο /hive/hacktricks/reversing/reversing-tools-basic-methods/README.md. Μεταφράστε το σχετικό αγγλικό κείμενο στα ελληνικά και επιστρέψτε τη μετάφραση διατηρώντας ακριβώς την ίδια σύνταξη markdown και html. Μην μεταφράζετε πράγματα όπως κώδικας, ονόματα τεχνικών χάκινγκ, όροι χάκινγκ, ονόματα πλατφορμών cloud/SaaS (όπως Workspace, aws, gcp...), ο όρος 'διαρροή', pentesting και ετικέτες markdown. Επίσης, μην προσθέτετε κανένα επιπλέον περιεχόμενο εκτός από τη μετάφραση και τη σύνταξη markdown.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Και κάντε κλικ στο **compile**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο στο _**File >> Save module...**_:

![](<../../.gitbook/assets/image (279).png>)

Αυτό είναι απαραίτητο επειδή αν δεν το κάνετε αυτό, κατά τη διάρκεια της **εκτέλεσης** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και είναι δυνατόν να μην εκτελεστεί ποτέ ένα **σημείο διακοπής** κατά την αποσφαλμάτωση ή να μην υπάρχουν κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή .Net σας **τρέχει** από τον **IIS**, μπορείτε να τον **επανεκκινήσετε** με:
```
iisreset /noforce
```
Στη συνέχεια, για να ξεκινήσετε την αποσφαλμάτωση, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και εντός της **Καρτέλας Αποσφαλμάτωσης** επιλέξτε **Σύνδεση σε Διεργασία...**:

![](<../../.gitbook/assets/image (280).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **σύνδεση**:

![](<../../.gitbook/assets/image (281).png>)

Τώρα που αποσφαλματώνουμε τη διαδικασία, είναι ώρα να την σταματήσουμε και να φορτώσουμε όλα τα αρθρώματα. Πρώτα κάντε κλικ στο _Αποσφαλμάτωση >> Διάλειμμα Όλων_ και στη συνέχεια κάντε κλικ στο _**Αποσφαλμάτωση >> Παράθυρα >> Αρθρώματα**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Κάντε κλικ σε οποιοδήποτε αρθρώματα στα **Αρθρώματα** και επιλέξτε **Άνοιγμα Όλων των Αρθρωμάτων**:

![](<../../.gitbook/assets/image (284).png>)

Κάντε δεξί κλικ σε οποιοδήποτε αρθρώματα στο **Εξερευνητή Συναρμολογήσεων** και κάντε κλικ στο **Ταξινόμηση Συναρμολογήσεων**:

![](<../../.gitbook/assets/image (285).png>)

## Αποσυμπιεστής Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Αποσφαλμάτωση DLLs

### Χρησιμοποιώντας το IDA

* **Φορτώστε το rundll32** (64bit στο C:\Windows\System32\rundll32.exe και 32bit στο C:\Windows\SysWOW64\rundll32.exe)
* Επιλέξτε τον αποσφαλματωτή **Windbg**
* Επιλέξτε "**Παύση κατά τη φόρτωση/αφόρτωση βιβλιοθηκών**"

![](<../../.gitbook/assets/image (135).png>)

* Διαμορφώστε τις **παραμέτρους** της εκτέλεσης βάζοντας το **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![](<../../.gitbook/assets/image (136).png>)

Στη συνέχεια, όταν ξεκινήσετε την αποσφαλμάτωση, η εκτέλεση θα σταματήσει όταν φορτώνεται κάθε DLL, έπειτα, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα σταματήσει.

Αλλά, πώς μπορείτε να φτάσετε στον κώδικα του DLL που φορτώθηκε; Χρησιμοποιώντας αυτήν τη μέθοδο, δεν ξέρω πώς.

### Χρησιμοποιώντας το x64dbg/x32dbg

* **Φορτώστε το rundll32** (64bit στο C:\Windows\System32\rundll32.exe και 32bit στο C:\Windows\SysWOW64\rundll32.exe)
* **Αλλάξτε τη γραμμή εντολών** ( _Αρχείο --> Αλλαγή Γραμμής Εντολών_ ) και ορίστε τη διαδρομή του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Αλλάξτε _Επιλογές --> Ρυθμίσεις_ και επιλέξτε "**Είσοδος DLL**".
* Στη συνέχεια, **ξεκινήστε την εκτέλεση**, ο αποσφαλματωτής θα σταματήσει σε κάθε κύρια DLL, σε κάποιο σημείο θα **σταματήσετε στην είσοδο DLL του dll** σας. Από εκεί, απλά αναζητήστε τα σημεία όπου θέλετε να τοποθετήσετε ένα σημείο διακοπής.

Προσέξτε ότι όταν η εκτέλεση σταματάει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας στην **κορυφή του παραθύρου win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Έτσι, κοιτάζοντας αυτό, μπορείτε να δείτε πότε η εκτέλεση σταματήθηκε στο dll που θέλετε να αποσφαλματώσετε.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να βρείτε πού αποθηκεύονται στη μνήμη ενός τρέχοντος παιχνιδιού σημαντικές τιμές και να τις αλλάξετε. Περισσότερες πληροφορίες στο:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Αποσφαλμάτωση ενός shellcode με το blobrunner

[**Blobrunner**](https://github.com/OALabs/B
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
Το scDbg διαθέτει επίσης ένα γραφικό εκκινητή όπου μπορείτε να επιλέξετε τις επιλογές που θέλετε και να εκτελέσετε το shellcode.

![](<../../.gitbook/assets/image (398).png>)

Η επιλογή **Create Dump** θα αποθηκεύσει το τελικό shellcode αν γίνει οποιαδήποτε αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για να κατεβάσετε το αποκωδικοποιημένο shellcode). Το **start offset** μπορεί να είναι χρήσιμο για να ξεκινήσετε το shellcode από ένα συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για να εκτελέσετε αποσφαλματωμένο το shellcode χρησιμοποιώντας το τερματικό του scDbg (ωστόσο, θεωρώ ότι οι προηγούμενες επιλογές είναι καλύτερες για αυτό το θέμα, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση χρησιμοποιώντας το CyberChef

Μεταφορτώστε το αρχείο shellcode σας ως είσοδο και χρησιμοποιήστε την παρακάτω συνταγή για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator **τροποποιεί όλες τις εντολές για `mov`** (ναι, πραγματικά καλό). Χρησιμοποιεί επίσης διακοπές για να αλλάξει τη ροή εκτέλεσης. Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργεί:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Αν έχετε τύχη, το [demovfuscator](https://github.com/kirschju/demovfuscator) θα αποκωδικοποιήσει το δυαδικό αρχείο. Έχει αρκετές εξαρτήσεις.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Εάν παίζετε ένα **CTF, αυτή η παρακάμψη για να βρείτε τη σημαία** μπορεί να είναι πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τις διεπαφές προς τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

Για να βρείτε το **σημείο εισόδου** αναζητήστε τις συναρτήσεις με το `::main` όπως στο παράδειγμα:

![](<../../.gitbook/assets/image (612).png>)

Σε αυτήν την περίπτωση το δυαδικό αρχείο ονομάζεται authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα κύρια συνάρτηση.\
Έχοντας το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Διαδίκτυο** για να μάθετε για τις **εισόδους** και **εξόδους** τους.

## **Delphi**

Για μεταγλωττισμένα δυαδικά αρχεία Delphi μπορείτε να χρησιμοποιήσετε [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Εάν πρέπει να αναστρέψετε ένα δυαδικό αρχείο Delphi, σας προτείνω να χρησιμοποιήσετε το πρόσθετο IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Απλά πατήστε **ATL+f7** (εισαγωγή πρόσθετου python στο IDA) και επιλέξτε το πρόσθετο python.

Αυτό το πρόσθετο θα εκτελέσει το δυαδικό αρχείο και θα επιλύσει δυναμικά τα ονόματα των συναρτήσεων στην αρχή της αποσφαλμάτωσης. Αφού ξεκινήσετε την αποσφαλμάτωση, πατήστε ξανά το κουμπί Έναρξη (το πράσινο ή f9) και θα εμφανιστεί ένα σημείο αναστολής στην αρχή του πραγματικού κώδικα.

Είναι επίσης πολύ ενδιαφέρον επειδή εάν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο αποσφαλματωτής θα σταματήσει στη συνάρτηση που εκτελείται από αυτό το κουμπί.

## Golang

Εάν πρέπει να αναστρέψετε ένα δυαδικό αρχείο Golang, σας προτείνω να χρησιμοποιήσετε το πρόσθετο IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Απλά πατήστε **ATL+f7** (εισαγωγή πρόσθετου python στο IDA) και επιλέξτε το πρόσθετο python.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

## Μεταγλωττισμένο Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο δυαδικό αρχείο ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Εάν έχετε το **δυαδικό** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **εξομοιώσετε** και να το **αποσφαλματώσετε**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Λήψη της έκδοσης αποσφαλμάτωσης_) - Περιέχει έναν αποσφαλματωτή με διεπαφή
* [**mgba** ](https://mgba.io)- Περιέχει έναν αποσφαλματωτή γραμμής εντολών
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Πρόσθετο Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Πρόσθετο Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Επιλογές --> Ρύθμιση Εξομοίωσης --> Χειρισμός**_\*\* \*\* μπορείτε να δείτε πώς να πατήσετε τα κουμπιά του Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

Όταν πατηθεί, κάθε **πλήκτρο έχει μια τιμή** για να το αναγνωρίσει:
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
Έτσι, σε αυτού του είδους τα προγράμματα, ένα ενδιαφέρον μέρος θα είναι **πώς το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνάρτηση που συναντάται συχνά: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN\_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη συνάρτηση, μετά από μερικές αρχικοποιήσεις λειτουργιών (χωρίς καμία σημασία):
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
Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **τελευταία κλειδιά** και δεν είναι το τρέχον κλειδί, που αποθηκεύεται στο **`uVar1`**.
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
Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε την **uVar1** (το μέρος όπου βρίσκεται η **τιμή του πατημένου κουμπιού**) με ορισμένες τιμές:

* Αρχικά, συγκρίνεται με την **τιμή 4** (**κουμπί SELECT**): Στην πρόκληση αυτό το κουμπί καθαρίζει την οθόνη.
* Στη συνέχεια, συγκρίνεται με την **τιμή 8** (**κουμπί START**): Στην πρόκληση αυτό ελέγχει αν ο κώδικας είναι έγκυρος για να λάβει τη σημαία.
* Σε αυτήν την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με 0xf3 και αν η τιμή είναι ίδια, εκτελείται κάποιος κώδικας.
* Σε οποιαδήποτε άλλη περίπτωση, ελέγχεται μια μεταβλητή cont (`DAT_030000d4`). Είναι μια μεταβλητή cont επειδή προσθέτει 1 αμέσως μετά την εισαγωγή του κώδικα.\
Αν είναι μικρότερο από 8, γίνεται κάτι που συνεπάγεται την **προσθήκη** τιμών στη μεταβλητή \*\*`DAT_030000d8` \*\* (βασικά προσθέτει τις τιμές των πατημένων πλήκτρων σε αυτήν τη μεταβλητή όσο η μεταβλητή cont είναι μικρότερη από 8).

Έτσι, σε αυτήν την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, χρειαζόταν να **πατήσετε μια συνδυασμό με μήκος μικρότερο από 8 ώστε η τελική πρόσθεση να είναι 0xf3**.

**Αναφορά για αυτό το εγχειρίδιο:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Μαθήματα

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Αποκωδικοποίηση δυαδικού)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνειά σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από διεπαφές προς ιστοσελίδες και συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
