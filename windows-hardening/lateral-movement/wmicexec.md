# WmicExec

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Jinsi Inavyofanya Kazi Imeelezwa

Mchakato unaweza kufunguliwa kwenye mwenyeji ambapo jina la mtumiaji na nywila au hash inajulikana kupitia matumizi ya WMI. Amri zinatekelezwa kwa kutumia WMI na Wmiexec, ikitoa uzoefu wa kabla ya kuingiliana wa shell.

**dcomexec.py:** Kwa kutumia vituo tofauti vya DCOM, skripti hii inatoa shell ya nusu-ya kuingiliana kama wmiexec.py, ikitumia hasa kitu cha DCOM cha ShellBrowserWindow. Kwa sasa inasaidia MMC20. Maombi, Vioo vya Shell, na Vitu vya Kivinjari cha Shell. (chanzo: [Machapisho ya Kuhack](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Misingi ya WMI

### Jina la Nafasi

Iliyopangwa kwa muundo wa muundo wa saraka, chombo cha juu cha WMI ni \root, chini yake kuna saraka zaidi, inayojulikana kama nafasi, zilizoandaliwa.
Amri za kuorodhesha nafasi:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Madarasa ndani ya jina la nafasi zinaweza kuorodheshwa kwa kutumia:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Madarasa**

Kujua jina la darasa la WMI, kama vile win32\_process, na eneo la kuhifadhiwa ni muhimu kwa operesheni yoyote ya WMI.
Amri za kuorodhesha madarasa yanayoanza na `win32`:
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

Njia, ambazo ni kazi moja au zaidi za kutekelezeka za darasa za WMI, zinaweza kutekelezwa.
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
## Uorodhishaji wa WMI

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
Kwa wachomaji, WMI ni chombo kikali cha kuhesabu data nyeti kuhusu mifumo au uwanja.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Uchunguzi wa Mbali wa WMI kwa Mikono**

Uthibitisho wa siri wa waendeshaji wa ndani kwenye mashine ya mbali na watumiaji walioingia inaweza kufikiwa kupitia uchunguzi maalum wa WMI. `wmic` pia inasaidia kusoma kutoka kwenye faili ya maandishi ili kutekeleza amri kwenye nodi nyingi kwa wakati mmoja.

Kutekeleza mchakato kwa mbali kupitia WMI, kama vile kupeleka wakala wa Empire, muundo wa amri ifuatayo hutumiwa, na utekelezaji mafanikio unaonyeshwa na thamani ya kurudi ya "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Hii mchakato inaonyesha uwezo wa WMI kwa utekelezaji wa mbali na uchambuzi wa mfumo, ikionyesha umuhimu wake kwa utawala wa mfumo na upimaji wa kuingilia.

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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
