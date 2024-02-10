# WmicExec

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## How It Works Explained

Processes can be opened on hosts where the username and either password or hash are known through the use of WMI. Commands are executed using WMI by Wmiexec, providing a semi-interactive shell experience.

**dcomexec.py:** Utilizing different DCOM endpoints, this script offers a semi-interactive shell akin to wmiexec.py, specifically leveraging the ShellBrowserWindow DCOM object. It currently supports MMC20. Application, Shell Windows, and Shell Browser Window objects. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Fundamentals

### Namespace

Structured in a directory-style hierarchy, WMI's top-level container is \root, under which additional directories, referred to as namespaces, are organized.
Commands to list namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
### wmicexec

#### tlhIngan Hol

ghItlhvam: `wmic /namespace:\\root\cimv2 /class:__NAMESPACE`

#### English

Classes within a namespace can be listed using: `wmic /namespace:\\root\cimv2 /class:__NAMESPACE`
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Qa'Hom**

Qa'Hom WMI class name, 'win32\_process', je crucial for any WMI operation. 
Commands to list classes beginning with `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocation of a class:

Klingon Translation:
### Invocation of a class:

Klingon Translation:
### Invocation of a class:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### tIv

tIv, vaj 'ej wa' executable functions WMI classes, 'e' vItlhutlh.
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
## WMI Enumeration

### WMI Service Status

Commands to verify if the WMI service is operational:

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:list
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:value
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:htable
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:csv
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:xml
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:rawxml
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:table
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:htable
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:csv
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:xml
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:rawxml
```

```
wmic /node:"<target>" /user:"<username>" /password:"<password>" /namespace:"\\root\cimv2" path Win32_Service where "Name='winmgmt'" get State /format:table
```
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### System and Process Information

Gathering system and process information through WMI:

### qo' vIghro'wI' je 'ej Qap

WMI laH vIghro'wI' je 'ej Qap jImej.
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
ghobta'pu' WMI, jang vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'chugh vItlhutlhlaHbe'lu'
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Manual Remote WMI Querying**

Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

### **Manual Remote WMI Querying**

Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

### **Manual Remote WMI Querying**

Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

### **Manual Remote WMI Querying**

Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

To remotely execute a process over WMI, such as deploying an Empire agent, the following command structure is employed, with successful execution indicated by a return value of "0":

To remotely execute a process over WMI, such as deploying an Empire agent, the following command structure is employed, with successful execution indicated by a return value of "0":

To remotely execute a process over WMI, such as deploying an Empire agent, the following command structure is employed, with successful execution indicated by a return value of "0":

To remotely execute a process over WMI, such as deploying an Empire agent, the following command structure is employed, with successful execution indicated by a return value of "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
vaj wMI vItlhutlh remote execution je system enumeration, 'ej highlighting 'oH utility system administration je penetration testing.

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
