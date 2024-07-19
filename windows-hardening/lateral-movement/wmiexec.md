# WmiExec

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

## Kako to funkcioniše

Procesi se mogu otvoriti na hostovima gde su korisničko ime i ili lozinka ili hash poznati putem WMI. Komande se izvršavaju koristeći WMI putem Wmiexec, pružajući polu-interaktivno iskustvo ljuske.

**dcomexec.py:** Korišćenjem različitih DCOM krajnjih tačaka, ovaj skript nudi polu-interaktivnu ljusku sličnu wmiexec.py, posebno koristeći ShellBrowserWindow DCOM objekat. Trenutno podržava MMC20. Application, Shell Windows i Shell Browser Window objekte. (izvor: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Osnovi

### Namespace

Strukturiran u hijerarhiji sličnoj direktorijumu, WMI-jev najviši kontejner je \root, pod kojim su organizovani dodatni direktorijumi, koji se nazivaju namespaces.
Komande za listanje namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klase unutar imenskog prostora mogu se nabrojati koristeći:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klase**

Poznavanje imena WMI klase, kao što je win32\_process, i imena prostora u kojem se nalazi je ključno za svaku WMI operaciju.  
Komande za listanje klasa koje počinju sa `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Pozivanje klase:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Методи

Методи, који су једна или више извршних функција WMI класа, могу се извршити.
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
## WMI Enumeracija

### WMI Status Usluge

Komande za proveru da li je WMI usluga operativna:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informacije o sistemu i procesima

Prikupljanje informacija o sistemu i procesima putem WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Za napadače, WMI je moćan alat za enumeraciju osetljivih podataka o sistemima ili domenima.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Daljinsko pretraživanje WMI za specifične informacije, kao što su lokalni administratori ili prijavljeni korisnici, je izvodljivo uz pažljivo konstruisanje komandi.

### **Ručno daljinsko WMI pretraživanje**

Diskretno identifikovanje lokalnih administratora na udaljenoj mašini i prijavljenih korisnika može se postići kroz specifične WMI upite. `wmic` takođe podržava čitanje iz tekstualne datoteke za izvršavanje komandi na više čvorova istovremeno.

Da bi se daljinski izvršio proces preko WMI, kao što je implementacija Empire agenta, koristi se sledeća struktura komande, pri čemu uspešno izvršenje označava povratna vrednost "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ovaj proces ilustruje WMI-ovu sposobnost za daljinsko izvršavanje i enumeraciju sistema, ističući njenu korisnost kako za administraciju sistema, tako i za pentesting.

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
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
