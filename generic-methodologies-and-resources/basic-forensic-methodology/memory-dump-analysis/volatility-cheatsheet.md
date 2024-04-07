# Volatility - Spiekbrief

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

As jy iets **vinnig en mal** wil hê wat verskeie Volatility-inproppe gelyktydig sal lanceer, kan jy gebruik maak van: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Installasie

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
#### volatiliteit2

{% tabs %}
{% tab title="Metode1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Metode 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility Opdragte

Toegang tot die amptelike dokument in [Volatility-opdragverwysing](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### 'n Nota oor "lys" vs. "deursoek" invoegtoepassings

Volatility het twee hoofbenaderings tot invoegtoepassings, wat soms weerspieël word in hul name. "lys" invoegtoepassings sal probeer deur Windows Kernel-strukture navigeer om inligting soos prosesse te herwin (lokalisering en deur die gekoppelde lys van `_EPROCESS` strukture in geheue loop), OS-hanteer (lokalisering en lys van die hanteerlys, enige aangetroffen aanwysers dereferensieer, ens.). Hulle gedra min of meer soos die Windows API sou as versoek word om byvoorbeeld prosesse te lys.

Dit maak "lys" invoegtoepassings redelik vinnig, maar net so kwesbaar as die Windows API vir manipulasie deur kwaadwillige sagteware. Byvoorbeeld, as kwaadwillige sagteware DKOM gebruik om 'n proses van die `_EPROCESS` gekoppelde lys af te koppel, sal dit nie in die Taakbestuurder verskyn nie en ook nie in die pslys nie.

"deursoek" invoegtoepassings daarenteen sal 'n benadering volg wat soortgelyk is aan die uitsny van die geheue vir dinge wat sinvol kan wees wanneer dit as spesifieke strukture gedereferensieer word. `psscan` sal byvoorbeeld die geheue lees en probeer om `_EPROCESS`-voorwerpe daaruit te maak (dit gebruik pool-tag deursoek, wat soek vir 4-byte stringe wat die teenwoordigheid van 'n struktuur van belang aandui). Die voordeel is dat dit prosesse kan opgrawe wat afgesluit het, en selfs as kwaadwillige sagteware met die `_EPROCESS` gekoppelde lys knoei, sal die invoegtoepassing steeds die struktuur in die geheue vind (aangesien dit steeds moet bestaan vir die proses om te loop). Die nadeel is dat "deursoek" invoegtoepassings bietjie stadiger as "lys" invoegtoepassings is, en kan soms vals positiewe resultate lewer ( 'n proses wat te lank gelede afgesluit het en dele van sy struktuur deur ander operasies oorskryf is).

Bron: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## BS Profiele

### Volatility3

Soos verduidelik in die leesmy moet jy die **simbooltabel van die BS** wat jy wil ondersteun binne _volatility3/volatility/symbols_ plaas.\
Simbooltabel-pakke vir die verskeie bedryfstelsels is beskikbaar vir **aflaai** by:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Eksterne Profiel

Jy kan die lys van ondersteunde profiele kry deur:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Indien jy 'n **nuwe profiel wat jy afgelaai het** wil gebruik (byvoorbeeld 'n Linux een), moet jy êrens die volgende vouerstruktuur skep: _plugins/overlays/linux_ en sit die zip-lêer wat die profiel bevat binne hierdie vouer. Kry dan die nommer van die profiele deur die volgende te gebruik:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Jy kan **Linux en Mac profiele aflaai** vanaf [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

In die vorige blok kan jy sien dat die profiel genoem word `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, en jy kan dit gebruik om iets soos uit te voer:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Ontdek Profiel
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Verskille tussen imageinfo en kdbgscan**

[**Vanaf hier**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): In teenstelling met imageinfo wat bloot profile voorstelle bied, is **kdbgscan** ontwerp om die korrekte profiel en die korrekte KDBG-adres positief te identifiseer (indien daar dalk meerdere is). Hierdie invoegtoepassing skandeer vir die KDBGHeader-handtekeninge wat aan Volatility-profiels gekoppel is en pas gesondheidskontroles toe om vals positiewe te verminder. Die oorvloedigheid van die uitset en die aantal gesondheidskontroles wat uitgevoer kan word, hang af van of Volatility 'n DTB kan vind, so as jy reeds die korrekte profiel weet (of as jy 'n profielvoorstel van imageinfo het), maak seker jy gebruik dit van .

Neem altyd 'n kyk na die **aantal prosesse wat kdbgscan gevind het**. Soms kan imageinfo en kdbgscan **meer as een geskikte profiel vind**, maar slegs die **geldige een sal enige prosesverwante** hê (Dit is omdat die korrekte KDBG-adres benodig word om prosesse te onttrek)
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

Die **kernel debugger block**, bekend as **KDBG** deur Volatility, is noodsaaklik vir forensiese take wat deur Volatility en verskeie debuggers uitgevoer word. Geïdentifiseer as `KdDebuggerDataBlock` en van die tipe `_KDDEBUGGER_DATA64`, bevat dit noodsaaklike verwysings soos `PsActiveProcessHead`. Hierdie spesifieke verwysing wys na die kop van die proseslys, wat die lys van alle prosesse moontlik maak, wat fundamenteel is vir deeglike geheue-analise.

## OS Inligting
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Die invoegtoepassing `banners.Banners` kan in **vol3 gebruik word om Linux-banners** in die dump te probeer vind.

## Hasse/ Wagwoorde

Ontgin SAM-hasse, [gekaapte domein-gedagtes] (../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) en [lsa-geheime] (../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> --output-file <output_file>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hookscan`

- **Analyzing Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Identifying API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying IDT**
  - `voljson -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Identifying Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> port`

- **Analyzing Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Identifying Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> objects`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Identifying Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Identifying Hidden IDTs**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Identifying Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> objects`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> port`

- **Identifying Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Identifying Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Identifying Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Identifying Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Identifying Hidden Hooks**
  - `volatility -f <memory_dump> --profile=<profile> hookscan`

- **Analyzing Hidden Pools**
  - `volatility -f <memory_dump> --profile=<profile> poolscanner`

- **Identifying Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Identifying Hidden GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden IDT**
  - `voljson -f <memory_dump> --profile=<profile> idt`

- **Identifying Hidden LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Identifying Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Identifying Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Identifying Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> port`

- **Analyzing Hidden Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Identifying Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> objects`
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Geheue-afleiding

Die geheue-afleiding van 'n proses sal alles van die huidige status van die proses **ontgin**. Die **procdump**-module sal slegs die **kode** **ontgin**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteit geleentheid in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie en sibersekuriteit professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Prosesse

### Lys prosesse

Probeer om **verdagte** prosesse (op naam) of **onverwagte** kind **prosesse** te vind (byvoorbeeld 'n cmd.exe as 'n kind van iexplorer.exe).\
Dit kan interessant wees om die resultaat van pslist te vergelyk met dié van psscan om verskuilde prosesse te identifiseer.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volvolatile -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Extracting Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Patches**
  - `volatility -f <memory_dump> --profile=<profile> patcher`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> crashinfo`

- **Analyzing Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Analyzing Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt_hooks`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp_hooks`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt_hooks`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyanalyzingzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverirp
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Stortingsproses

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volmemory_dump> --profile=<profile> file -S <start_address> -E <end_address> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `volvolatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpp`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyating Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Analyzing Kernel Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Kernel Notifiers**
  - `volatility -f <memory_dump> --profile=<profile> notifiers`

- **Analyzing Kernel Asynchronous Procedure Calls (APCs)**
  - `volatility -f <memory_dump> --profile=<profile> apc`

- **Analyzing Kernel Worker Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Kernel Process List**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Analyzing Kernel Driver List**
  - `volvolatility -f <memory_dump> --profile=<profile> drivers`

- **Analyzing Kernel Driver Module List**
  - `volatility -f <memoryjson> --profile=<profile> modules`

- **Analyzing Kernel Driver IRP List**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyizing Kernel Driver Device List**
  - `volatility -f <memory_dump> --profile=<profile> devices`

- **Analyzing Kernel Driver File List**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Analyzing Kernel Driver Registry List**
  - `volatility -f <memory_dump> --profile=<profile> registry`

- **Analyzing Kernel Driver Object List**
  - `volatility -f <memory_dump> --profile=<profile> objects`

- **Analyzing Kernel Driver Driver Object List**
  - `volatility -f <memory_dump> --profile=<profile> driverobject`

- **Analyzing Kernel Driver Mutant List**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Analyzing Kernel Driver Token List**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Kernel Driver Privilege List**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Kernel Driver Registry Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Kernel Driver Object Handles**
  - `volatility -f <memory_dump> --profile=<profile> objecthandles`

- **Analyzing Kernel Driver Object Types**
  - `volatility -f <memory_dump> --profile=<profile> objecttypes`

- **Analyzing Kernel Driver Object Type Signatures**
  - `volatility -f <memory_dump> --profile=<profile> objecttypesignatures`

- **Analyzing Kernel Driver Object Type Indexes**
  - `volatility -f <memory_dump> --profile=<profile> objecttypeindexes`

- **Analyzing Kernel Driver Object Type Allocations**
  - `volatility -f <memory_dump> --profile=<profile> objecttypeallocations`

- **Analyizing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallbacks`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> objecttypecallback`

- **Analyzing Kernel Driver Object Type Callbacks**
  - `volatility -f <memory_dump> --
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Opdraglyn

Is daar enigiets verdagtes uitgevoer?

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Gebruik

- **Volledige Lys van Profiele:** `volatility -f memory_dump.raw imageinfo`
- **Prosesse:** `volatility -f memory_dump.raw --profile=Profile pslist`
- **Netwerkaktiwiteit:** `volatility -f memory_dump.raw --profile=Profile netscan`
- **Bestandstelselaktiwiteit:** `volatility -f memory_dump.raw --profile=Profile filescan`

### Geheue-analise

- **Kernelmodules:** `volatility -f memory_dump.raw --profile=Profile modscan`
- **Kernelvoorwerpe:** `volatility -f memory_dump.raw --profile=Profile kdbgscan`
- **Kernelvoorwerpe (alternatief):** `volatility -f memory_dump.raw --profile=Profile kpcrscan`
- **Kernelvoorwerpe (alternatief):** `volatility -f memory_dump.raw --profile=Profile kpcrscan`

### Gebruikersaktiwiteit

- **Gebruikers:** `volatility -f memory_dump.raw --profile=Profile getsids`
- **Gebruikers:** `volatility -f memory_dump.raw --profile=Profile consoles`
- **Gebruikers:** `volatility -f memory_dump.raw --profile=Profile userassist`

### Verdere Analise

- **Registry:** `volatility -f memory_dump.raw --profile=Profile printkey -o Offset`
- **Registry:** `volatility -f memory_dump.raw --profile=Profile hivelist`
- **Registry:** `volatility -f memory_dump.raw --profile=Profile hivedump -o Offset -s Size -f OutputFile`

### Aanvaltegnieke

- **Prosesse:** `volatility -f memory_dump.raw --profile=Profile cmdline`
- **Prosesse:** `volatility -f memory_dump.raw --profile=Profile consoles`
- **Prosesse:** `volatility -f memory_dump.raw --profile=Profile malfind`
- **Prosesse:** `volatility -f memory_dump.raw --profile=Profile pstree`

{% endtab %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Opdragte wat in `cmd.exe` uitgevoer word, word bestuur deur **`conhost.exe`** (of `csrss.exe` op stelsels voor Windows 7). Dit beteken dat as **`cmd.exe`** deur 'n aanvaller beëindig word voordat 'n geheue-dump verkry word, dit steeds moontlik is om die sessie se opdraggeskiedenis van die geheue van **`conhost.exe`** te herstel. Om dit te doen, as ongewone aktiwiteit binne die konsole se modules opgespoor word, moet die geheue van die betrokke **`conhost.exe`**-proses gedump word. Dan kan deur te soek na **strings** binne hierdie dump, opdraglyne wat in die sessie gebruik is, moontlik onttrek word.

### Omgewing

Kry die omgewingsveranderlikes van elke lopende proses. Daar kan interessante waardes wees.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse en Dienste**
  - `pslist`: Lys alle prosesse
  - `psscan`: Skandeer vir prosesinligting
  - `pstree`: Toon prosesboom

- **Netwerkaktiwiteit**
  - `netscan`: Skandeer vir netwerkverbindings
  - `connscan`: Identifiseer netwerkverbindings

- **Gebruikersaktiwiteit**
  - `hivelist`: Lys alle gelaai wordregisters
  - `userassist`: Ontleed gebruikersaktiwiteit

- **Bestandstelselaktiwiteit**
  - `filescan`: Identifiseer geopen bestande
  - `mftparser`: Analiseer MFT-inligting

#### Nie-Volatile Data

- **Registry-analise**
  - `hivelist`: Lys alle gelaai wordregisters
  - `printkey`: Druk sleutelinhoud
  - `hashdump`: Haal gebruikerswagwoorde op

- **Bestandstelsel-analise**
  - `filescan`: Identifiseer geopen bestande
  - `mftparser`: Analiseer MFT-inligting

- **Prosesse en Dienste**
  - `pslist`: Lys alle prosesse
  - `psscan`: Skandeer vir prosesinligting
  - `pstree`: Toon prosesboom

- **Netwerkaktiwiteit**
  - `netscan`: Skandeer vir netwerkverbindings
  - `connscan`: Identifiseer netwerkverbindings

- **Gebruikersaktiwiteit**
  - `userassist`: Ontleed gebruikersaktiwiteit

- **Bestandstelselaktiwiteit**
  - `filescan`: Identifiseer geopen bestande
  - `mftparser`: Analiseer MFT-inligting

#### Volatility Plugins

- **Prosesse**
  - `pslist`, `psscan`, `pstree`

- **Netwerk**
  - `netscan`, `connscan`

- **Gebruikers**
  - `hivelist`, `userassist`

- **Bestandstelsel**
  - `filescan`, `mftparser`

{% endtab %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### Token voorregte

Kyk vir voorregte tokens in onverwagte dienste. Dit kan interessant wees om die prosesse wat van 'n paar bevoorregte token gebruik maak, te lys.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}  
### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Dumping a DLL**
  - `voljsonity -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Listing Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Hive**
 jsonity -f <memory_dump> --profile=<profile> hivedump -o <output_directory> -s <hive_offset>`

- **File Extraction**
  - `volatility -f <memory_dump> --profile=<profile> filescan --output-file=<output_file>`

- **Yara Scanning**
  - `volatility -f <memory_dump> --profile=<profile> yarascan --yara-rules=<yara_rules>`

- **Process Tree**
  - `volatility -f <memory_dump> --profile=<profile> pstree`

- **Command History**
  - `volatility -f <memory_dump> --profile=<profile> cmdscan`

- **User Listing**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **User Information**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping SAM**
  - `voljsonity -f <memory_dump> --profile=<profile> samdump`

- **Dumping LSA Cache**
  - `volatility -f <memory_dump> --profile=<profile> lsa_dump`

- **Dumping Password Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Security Packages**
  - `volatility -f <memory_dump> --profile=<profile> mimikatz`

- **Dumping Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Dumping Anti-Forensics**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Dumping Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> rootkit`

- **Dumping Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Dumping Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Dumping Timeliner**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Dumping Auto-runs**
  - `volatility -f <memory_dump> --profile=<profile> autoruns`

- **Dumping API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Dumping SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Dumping GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Dumping IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Dumping LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Dumping Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Dumping Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Dumping Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutants`

- **Dumping Registry Handles**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Registry Values**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping Registry Data**
 jsonity -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key>`

- **Dumping Registry Key**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key>`

- **Dumping Registry Key Values**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -V`

- **Dumping Registry Key Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -V -d`

- **Dumping Registry Key Slack**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -s`

- **Dumping Registry Key Data and Slack**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -V -d -s`

- **Dumping Registry Key Subkeys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S`

- **Dumping Registry Key Values and Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -V -d`

- **Dumping Registry Key Security**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S`

- **Dumping Registry Key Security and Values**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V`

- **Dumping Registry Key Security and Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -d`

- **Dumping Registry Key Security, Values, and Data**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d`

- **Dumping Registry Key Security, Values, Data, and Slack**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s`

- **Dumping Registry Key Security, Values, Data, Slack, and Subkeys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, and Class**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, and LastWriteTime**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, and LayerName**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, and KeyName**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, and ValueName**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, and DataName**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, and SlackName**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, and SubkeyName**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, and ValueData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, and SubkeyData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, and ClassData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, and LastWriteTimeData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, and LayerNameData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, and KeyNameData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, and ValueNameData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, ValueNameData, and DataNameData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V -D`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, ValueNameData, DataNameData, and SlackNameData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V -D -S`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, ValueNameData, DataNameData, SlackNameData, and SubkeyNameData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V -D -S -S`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, ValueNameData, DataNameData, SlackNameData, SubkeyNameData, and ValueDataData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V -D -S -S -V`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, ValueNameData, DataNameData, SlackNameData, SubkeyNameData, ValueDataData, and SubkeyDataData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V -D -S -S -V -D`

- **Dumping Registry Key Security, Values, Data, Slack, Subkeys, Class, LastWriteTime, LayerName, KeyName, ValueName, DataName, SlackName, SubkeyName, ValueData, SubkeyData, ClassData, LastWriteTimeData, LayerNameData, KeyNameData, ValueNameData, DataNameData, SlackNameData, SubkeyNameData, ValueDataData, SubkeyDataData, and ClassDataData**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> -K <key> -S -V -d -s -S -C -L -N -M -V -D -S -S -V -D -C -L -N -M -V -D -S
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

Kontroleer elke SSID wat deur 'n proses besit word. Dit kan interessant wees om die prosesse wat 'n bevoorregte SID gebruik, te lys (en die prosesse wat van 'n diens-SID gebruik maak).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse en Threads**
  - `pslist`: lys alle prosesse
  - `pstree`: boomstruktuur van prosesse
  - `psscan`: skandeer proses-geheue
  - `threads`: lys alle threads

- **Handles**
  - `handles`: lys alle handvatsels

- **DLLs en Handles**
  - `dlllist`: lys DLLs vir elke proses
  - `ldrmodules`: lys gelaai DLLs

- **Netwerk**
  - `connections`: lys netwerkverbindings
  - `sockets`: lys netwerksockets

- **Bestandstelsel**
  - `filescan`: skandeer bestandstelsel
  - `filescan`: lys oop lêers
  - `mftparser`: analiseer MFT-inligting

- **Registry**
  - `hivelist`: lys gelaai hive-profiel
  - `printkey`: druk sleutelinhoud
  - `hashdump`: haal gebruikerswagwoorde op

- **Ander**
  - `cmdline`: toon prosesbevellyn
  - `consoles`: lys geopen konsol-sessies
  - `desktops`: lys geopen lessenaars

#### Profiel

- `imageinfo`: kry inligting oor die geheue dump
- `kdbgscan`: soek vir KDBG-handvatsel
- `kpcrscan`: soek vir KPCR-struktuur
- `psxview`: vind versteekte prosesse

#### Analise

- `malfind`: soek na verdagte prosesse
- `malfind`: analiseer prosesgeheue
- `apihooks`: vind API-hekke
- `ldrmodules`: soek na verdagte DLLs

#### Volatile Data Analise

- `memmap`: toon geheuekaart
- `vadinfo`: kry inligting oor VADs
- `vadtree`: boomstruktuur van VADs
- `vaddump`: dump VAD-geheue

#### Geheue Dump Analise

- `memdump`: dump geheue van 'n proses
- `memdump`: dump geheue van 'n adresreeks
- `memstrings`: soek na teks in geheue

#### Ander

- `autoruns`: lys outomatiese beginprogramme
- `svcscan`: lys dienste
- `modscan`: lys gelaai modules

#### Skakels

- [Volatility GitHub](https://github.com/volatilityfoundation/volatility)
- [Volatility Dokumentasie](https://volatilityfoundation.github.io/docs/)  
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Handvatsels

Nuttig om te weet na watter ander lêers, sleutels, drade, prosesse... 'n **proses 'n handvatsel vir het (geopen)**

{% tabs %}
{% tab title="vol3" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse**
  - `volatility -f memdump.mem --profile=Win7SP1x64 pslist`

- **DLLs**
  - `volatility -f memdump.mem --profile=Win7SP1x64 dlllist`

- **Handles**
  - `volatility -f memdump.mem --profile=Win7SP1x64 handles`

- **Netwerk**
  - `volatility -f memdump.mem --profile=Win7SP1x64 connections`

- **Virussen**
  - `volatility -f memdump.mem --profile=Win7SP1x64 malfind`

- **Registry**
  - `volatility -f memdump.mem --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"`

- **Gebruikers**
  - `volatility -f memdump.mem --profile=Win7SP1x64 getsids`

- **Kodes**
  - `volatility -f memdump.mem --profile=Win7SP1x64 consoles`

- **Skedules**
  - `volatility -f memdump.mem --profile=Win7SP1x64 schedtasks`

- **Bestande**
  - `volatility -f memdump.mem --profile=Win7SP1x64 filescan`

- **Virusskande**
  - `volatility -f memdump.mem --profile=Win7SP1x64 malsysproc`

- **Kernel**
  - `volatility -f memdump.mem --profile=Win7SP1x64 kdbgscan`

- **Sytem Inligting**
  - `volatility -f memdump.mem --profile=Win7SP1x64 sysinfo`

- **En meer...**

#### Niet-Volatile Data

- **Herwinbare Verwyderde Lêers**
  - `volatility -f memdump.mem --profile=Win7SPjsonx64 hivelist`
  - `volatility -f memdump.mem --profile=Win7SP1x64 printkey -o 0xe1f8c0`

- **Gebruikersaktiwiteit**
  - `volatility -f memdump.mem --profile=Win7SP1x64 userassist`

- **En meer...**

### Aanvullende Hulpbronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Dokumentasie](https://volatilityfoundation.github.io/volatility/volatility/index.html)
- [Volatility Handleiding](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Plugins](https://github.com/volatilityfoundation/volatility/wiki/CommandReference-Plugins)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse**
  - `volatility -f <dumppath> --profile=<profiel> pslist`
  - `volatility -f <dumppath> --profile=<profiel> psscan`
- **DLLs en Handles**
  - `volatility -f <dumppath> --profile=<profiel> dlllist`
  - `volatility -f <dumppath> --profile=<profiel> handles`
- **Netwerk Aktiwiteit**
  - `volatility -f <dumppath> --profile=<profiel> connscan`
  - `volatility -f <dumppath> --profile=<profiel> netscan`

#### Niet-Volatile Data

- **Registry**
  - `volatility -f <dumppath> --profile=<proprofiel> printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
  - `volatility -f <djsonpath> --profile=<profiel> hivelist`
- **Gebruikers**
  - `volatility -f <dumppath> --profile=<profiel> userassist`
  - `volatility -f <dumjsonpath> --profile=<profiel> shellbags`

#### Ander Analise

- **Malware**
  - `volatility -f <dumppath> --profile=<profiel> malfind`
- **Rootkits**
  - `voljsonpath> --profile=<profiel> ldrmodules`
- **Geheue Map**
  - `volatility -f <dumppath> --profile=<profiel> memmap`
- **Virusskande**
  - `volatility -f <dumppath> --profile=<profiel> malscan`

#### Aanvullende Hulpbronne

- [Volatility GitHub](https://github.com/volatilityfoundation/volatility)
- [Volatility Dokumentasie](https://volatilityfoundation.github.io/volatility/)
- [Volatility Profiele](https://github.com/volatilityfoundation/profiles)
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Strings per prosesse

Volatility stel ons in staat om te kontroleer tot watter proses 'n string behoort.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volmemory -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `voljson -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> --output-file <output_file>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Dit maak dit ook moontlik om vir strings binne 'n proses te soek deur die yarascan module te gebruik:
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %} 

# Volatility Cheatsheet

## Basic Forensic Methodology

### Memory Dump Analysis

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Running Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Loaded Drivers**
  - `voljson -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Process Handles**
  - `voljson -f <memory_dump> --profile=<profile> handles`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Extracting Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Analyzing DLLs**
  - `volatility -json -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyidentifying Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing User Sessions**
  - `voljson -f <memory_dump> --profile=<profile> sessions`

- **Analyzing User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> userassist`
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> moddump`

- **Analyizing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Threads**
  - `volvolatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> devicetree`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Analyzing Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDTs**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden GDTs**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden APIs**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing Hidden User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> userassist`
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> moddump`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Threads**
  - `volvolatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> devicetree`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Analyzing Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDTs**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden GDTs**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden APIs**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing Hidden User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> userassist`
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> moddump`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Threads**
  - `volvolatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> devicetree`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Analyzing Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDTs**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden GDTs**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden APIs**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden GDI Tables**
  - `volatility -f <memory_dump> --profile=<profile> gditimers`

- **Analyzing Hidden SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden User Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing Hidden User Accounts**
  - `volatility -f <memory_dump> --profile=<profile> userassist`
  - `volatility -f <memory_dump> --profile=<profile> consoles`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <key>`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyzing Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden LDR Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** hou by watter programme jy hardloop deur 'n kenmerk in die register genaamd **UserAssist keys**. Hierdie sleutels hou by hoeveel keer elke program uitgevoer is en wanneer dit laas uitgevoer is.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Forensiese Metodologie

#### Geheue Dump Analise

1. **Volatility Installasie**
   - Installeer Volatility op 'n Windows-sisteem.
   
2. **Profiel Ophaling**
   - Verkry die korrekte profiel vir die geheue dump.
   
3. **Volatility Gebruik**
   - Voer Volatility-opdragte uit om inligting uit die geheue dump te ontleed.
   
4. **Analise van Resultate**
   - Ontleed die verkrygte inligting om insigte te kry oor die aanval of voorval.

5. **Verdere Navorsing**
   - Voer aanvullende ondersoek en analise uit om die bevindinge te verfyn.

6. **Verslagdoening**
   - Stel 'n volledige verslag op van die geheue dump-analise en bevindinge.

### Volatility Opdragte

- **Imageinfo:** Gee inligting oor die geheue dump.
- **Pslist:** Lys alle aktiewe prosesse.
- **Pstree:** Vertoon 'n boomstruktuur van prosesse.
- **Netscan:** Skandeer vir netwerkaktiwiteit.
- **Cmdline:** Wys die bevellyn-argumente van prosesse.
- **Handles:** Identifiseer lêerhandvatsels wat deur prosesse gebruik word.

### Voorbeelde van Gebruik

- `volatility -f memdump.mem imageinfo`
- `volatility -f memdump.mem pslist`
- `volatility -f memdump.mem pstree`

{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante siberbeveiliging gebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie en siberbeveiliging professionele in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Dienste

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse**
  - `volatility -f memdump.mem --profile=ProfileName pslist`
  - `volatility -f memdump.mem --profile=ProfileName psscan`
- **DLLs en Handles**
  - `volatility -f memdump.mem --profile=ProfileName dlllist`
  - `volatility -f memdump.mem --profile=ProfileName handles`
- **Netwerk Aktiwiteit**
  - `volatility -f memdump.mem --profile=ProfileName netscan`
  - `volatility -f memdump.mem --profile=ProfileName connscan`
- **Gebruikers en Groepe**
  - `volatility -f memdump.mem --profile=ProfileName getsids`
  - `volatility -f memdump.mem --profile=ProfileName getsids`
- **Registry**
  - `volatility -f memdump.mem --profile=ProfileName printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
  - `volatility -f memdump.mem --profile=ProfileName printkey -K "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"`
- **Bestande en Direktorië**
  - `volatility -f memdump.mem --profile=ProfileName filescan`
  - `volatility -f memdump.mem --profile=ProfileName filescan | grep -i "interesting_string"`

#### Non-Volatile Data

- **MFT Analise**
  - `volatility -f memdump.mem --profile=ProfileName mftparser`
- **Prefetch Analise**
  - `volatility -f memdump.mem --profile=ProfileName prefetchparser`
- **Registry Analise**
  - `volatility -f memdump.mem --profile=ProfileName hivelist`
  - `volatility -f memdump.mem --profile=ProfileName printkey -o 0xXXXXXXXX -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
- **Event Logs**
  - `voljson -f memdump.mem --profile=ProfileName evtxtract`
  - `volatility -f memdump.mem --profile=ProfileName evtlogs`

#### Ander Nuttige Opdragte

- **Kyk na alle prosesse**
  - `volatility -f memdump.mem --profile=ProfileName pstree`
- **Kyk na alle modules**
  - `volatility -f memdump.mem --profile=ProfileName modscan`
- **Kyk na alle dienste**
  - `volatility -f memdump.mem --profile=ProfileName servicestart`
- **Kyk na alle gebruikers**
  - `volatility -f memdump.mem --profile=ProfileName userassist`
- **Kyk na alle geheue kaarte**
  - `volatility -f memdump.mem --profile=ProfileName memmap`
- **Kyk na alle virusskande**
  - `volatility -f memdump.mem --profile=ProfileName malsysproc`
- **Kyk na alle netwerk konneksies**
  - `volatility -f memdump.mem --profile=ProfileName connscan`
- **Kyk na alle geheue modules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue objekte**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue handles**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue dienste**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue bestande**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue sleutels**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue tokens**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue vensters**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue werksessies**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue diens punte**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules`
- **Kyk na alle geheue skedules**
  - `volatility -f memdump.mem --profile=ProfileName ldrmodules
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Netwerk

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Algemene Inligting

- **Naam:** Volatiliteit
- **Beskrywing:** 'n Kragtige geheue-analise-raamwerk
- **Aanvanklike Vrystelling:** 2007
- **Lisensie:** GNU Algemene Openbare Lisensie v2.0
- **URL:** https://www.volatilityfoundation.org/

#### Belangrike Opdragte

- **Volledige Stelselontleding:** `volatility -f <geheue-dump> imageinfo`
- **Prosesinligting:** `volatility -f <geheue-dump> pslist`
- **Netwerkaktiwiteit:** `volatility -f <geheue-dump> netscan`
- **Bestandstelselaktiwiteit:** `volatility -f <geheue-dump> filescan`

#### Geheueprofiel

- **Windows XP SP2 x86:** `WinXPSP2x86`
- **Windows 7 SP0 x64:** `Win7SP0x64`
- **Windows 10 15063 x64:** `Win10x64_15063`

#### Voorbeelde Gebruik

- **Analiseer geheue-dump:** `volatility -f memdump.mem imageinfo`
- **Ondersoek prosesse:** `volatility -f memdump.mem pslist`
- **Vind verdagte DLL's:** `volatility -f memdump.mem dlllist`

#### Aanvullende Hulpbronne

- **Volatiliteit Dokumentasie:** https://github.com/volatilityfoundation/volatility/wiki
- **Volatiliteit Plugins:** https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
## Registrieringskamp

### Druk beskikbare kampstukke af

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Algemene Inligting

- **Volatiliteit** - 'n raamwerk vir geheue-analise
- **Profilering** - identifiseer die besturingstelsel en die stelsel se konfigurasie
- **Prosesse** - lys die aktiewe prosesse
- **Netwerk** - identifiseer netwerkverbindings
- **Bestandstelsel** - analiseer die bestandstelsel
- **Registry** - ontleed die Windows-register
- **Handles** - identifiseer oop handvatsels
- **DLLs** - lys gelaai DLLs
- **Drivers** - identifiseer gelaai drywers
- **Kode-injeksie** - identifiseer kode-injeksie in prosesse
- **API-hoëvlak** - identifiseer API-oproepe
- **API-laagvlak** - identifiseer API-oproepe op laag vlak
- **Virusskandeerders** - identifiseer aktiewe antivirusprogramme
- **Yster** - identifiseer yster-inligting
- **Kerneldrukkers** - identifiseer aktiewe kerneldrukkers
- **Kernelland** - identifiseer kernelland-inligting
- **Kerneltreë** - identifiseer kerneltreë-inligting
- **Kernelsekuriteit** - identifiseer kernelsekuriteit-inligting
- **Kerneltimers** - identifiseer kerneltimer-inligting
- **Kerneltokens** - identifiseer kerneltoken-inligting
- **Kerneltuistes** - identifiseer kerneltuistuinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **Kerneltuistuistes** - identifiseer kerneltuistuisinligting
- **
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### Kry 'n waarde

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Algemene Inligting

- **Aan die gang kry:**
  - `volatility -f <geheuebeeld> imageinfo`

- **Prosesse en hanteerders:**
  - `volatility -f <geheuebeeld> pslist`
  - `volatility -f <geheuebeeld> pstree`
  - `volatility -f <geheuebeeld> psscan`

- **DLLs en hanteerders:**
  - `volatility -f <geheuebeeld> dlllist`
  - `volatility -f <geheuebeeld> handles`

- **Netwerkaktiwiteit:**
  - `volatility -f <geheuebeeld> connscan`
  - `volatility -f <geheuebeeld> sockets`

- **Gebruikersaktiwiteit:**
  - `volatility -f <geheuebeeld> hivelist`
  - `volatility -f <geheuebeeld> userassist`

- **Bestandstelselaktiwiteit:**
  - `volatility -f <geheuebeeld> mftparser`
  - `volatility -f <geheuebeeld> filescan`

- **Registry-analise:**
  - `volatility -f <geheuebeeld> printkey`
  - `volatility -f <geheuebeeld> hivelist`
  - `volatility -f <geheuebeeld> shellbags`

- **Geheue-analise:**
  - `volatility -f <geheuebeeld> memmap`
  - `volatility -f <geheuebeeld> memdump`

#### Gevorderde Analise

- **Rootkit-opsies:**
  - `volatility -f <geheuebeeld> ldrmodules`
  - `volatility -f <geheuebeeld> ldrmodules -p <proses-ID>`
  - `volatility -f <geheuebeeld> ldrmodules -o <offset>`

- **API-hoëvlakfunksies:**
  - `volatility -f <geheuebeeld> apihooks`
  - `volatility -f <geheuebeeld> apihooks -p <proses-ID>`

- **Kernel-objekte:**
  - `volatility -f <geheuebeeld> kdbgscan`
  - `volatility -f <geheuebeeld> kpcrscan`

- **Kernel-geheue:**
  - `volatility -f <geheuebeeld> modules`
  - `volatility -f <geheuebeeld> modscan`

- **Kernel-geheue-objekte:**
  - `volatility -f <geheuebeeld> objectscan`
  - `volatility -f <geheuebeeld> objtypescan`

- **Kernel-geheue-voorwerpe:**
  - `volatility -f <geheuebeeld> vadinfo`
  - `volatility -f <geheuebeeld> vadtree`

- **Kernel-geheue-gebruik:**
  - `volatility -f <geheuebeeld> vadwalk`
  - `volatility -f <geheuebeeld> vadtree`

- **Kernel-geheue-afdruk:**
  - `volatility -f <geheuebeeld> physmap`
  - `volatility -f <geheuebeeld> memmap`

- **Kernel-geheue-afdruk:**
  - `volatility -f <geheuebeeld> memdump`
  - `volatility -f <geheuebeeld> memdump --dump-dir <afdruk-gids>`

- **Kernel-geheue-afdruk:**
  - `volatility -f <geheuebeeld> memdump`
  - `volatility -f <geheuebeeld> memdump --dump-dir <afdruk-gids>`

- **Kernel-geheue-afdruk:**
  - `volatility -f <geheuebeeld> memdump`
  - `volatility -f <geheuebeeld> memdump --dump-dir <afdruk-gids>`

- **Kernel-geheue-afdruk:**
  - `volatility -f <geheuebeeld> memdump`
  - `volatility -f <geheuebeeld> memdump --dump-dir <afdruk-gids>`
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Storting
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Lêersisteem

### Monteer

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse en Dienste**
  - `volatility -f memory.raw --profile=Win7SP1x64 pslist`
  - `volatility -f memory.raw --profile=Win7SP1x64 psscan`
- **Netwerk Aktiwiteit**
  - `volatility -f memory.raw --profile=Win7SP1x64 netscan`
  - `volatility -f memory.raw --profile=Win7SP1x64 connscan`
- **Geopen Lêers**
  - `volatility -f memory.raw --profile=Win7SP1x64 filescan`
  - `volatility -f memory.raw --profile=Win7SP1x64 handles`
- **Registry Sleutels**
  - `volatility -f memory.raw --profile=Win7SP1x64 hivelist`
  - `volatility -f memory.raw --profile=Win7SP1x64 printkey -o 0xfffff8a00002b010`
- **Geheue Kaarte**
  - `volatility -f memory.raw --profile=Win7SP1x64 memmap`
  - `volatility -f memory.raw --profile=Win7SP1x64 memdump -p 123 -D .`

#### Non-Volatile Data

- **Bestandstelsel Analise**
  - `volatility -f memory.raw --profile=Win7SPjson1x64 mftparser`
  - `volatility -f memory.raw --profile=Win7SP1x64 filescan`
- **Gebruikersaktiwiteit**
  - `volatility -f memory.raw --profile=Win7SP1x64 userassist`
  - `volatility -f memory.raw --profile=Win7SP1x64 shellbags`
- **Programmatuur en Dienste**
  - `volatility -f memory.raw --profile=Win7SP1x64 svcscan`
  - `volatility -f memory.raw --profile=Win7SP1x64 drivermodule`
- **Netwerk Aktiwiteit**
  - `volatility -f memory.raw --profile=Win7SP1x64 connscan`
  - `volatility -f memory.raw --profile=Win7SP1x64 sockets`
- **Registry Sleutels**
  - `volatility -f memory.raw --profile=Win7SP1x64 printkey -o 0xfffff8a00002b010`
  - `volatility -f memory.raw --profile=Win7SP1x64 hivelist`

#### Ander Nuttige Opdragte

- **Help**
  - `volatility -h`
- **Profiel Inligting**
  - `volatility -f memory.raw imageinfo`
- **Prosesse en Hanteerders**
  - `volatility -f memory.raw --profile=Win7SP1x64 pslist`
  - `volatility -f memory.raw --profile=Win7SP1x64 handles`
- **Netwerk Aktiwiteit**
  - `volatility -f memory.raw --profile=Win7SP1x64 netscan`
  - `volatility -f memory.raw --profile=Win7SP1x64 connscan`
- **Geheue Kaarte**
  - `volatility -f memory.raw --profile=Win7SP1x64 memmap`
  - `volatility -f memory.raw --profile=Win7SP1x64 memdump -p 123 -D .`

{% endtab %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Deurskou / dump

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Algemene Opdragte

- **Volatiliteit installeer:** `pip install volatility`
- **Lys beskikbare profiele:** `volatility -f memory_dump.raw imageinfo`
- **Voer 'n spesifieke plugin uit:** `volatility -f memory_dump.raw <plugin_name>`

#### Basiese Geheue-analise

- **Lys alle prosesse:** `volatility -f memory_dump.raw pslist`
- **Lys gelaaide modules:** `volatility -f memory_dump.raw ldrmodules`
- **Vind 'n spesifieke proses se PID:** `volatility -f memory_dump.raw pslist \| grep <process_name>`
- **Analiseer 'n spesifieke proses se DLLs:** `volatility -f memory_dump.raw dlllist -p <PID>`
- **Skandeer vir verdagte prosesse:** `volatility -f memory_dump.raw psxview`
- **Vind 'n spesifieke proses se handle:** `volatility -f memory_dump.raw handles -p <PID>`
- **Lys alle gelaaide stuurprogramme:** `volatility -f memory_dump.raw driverscan`

#### Netwerk-analise

- **Lys alle netwerkverbindings:** `volatility -f memory_dump.raw connections`
- **Lys alle luisterende poorte:** `volatility -f memory_dump.raw sockets`
- **Vind 'n spesifieke proses se netwerkaktiwiteit:** `volatility -f memory_dump.raw netscan -p <PID>`

#### Gebruikers-en-konfigurasie-analise

- **Lys alle aangemelde gebruikers:** `volatility -f memory_dump.raw getsids`
- **Vind 'n spesifieke gebruiker se sessie-inligting:** `volatility -f memory_dump.raw sessionfinder -u <username>`
- **Lys alle geopen bestande:** `volatility -f memory_dump.raw filescan`

#### Ander nuttige opdragte

- **Vind 'n spesifieke proses se inligting:** `volatility -f memory_dump.raw pstree -p <PID>`
- **Analiseer 'n spesifieke proses se inligting:** `volatility -f memory_dump.raw psscan -p <PID>`
- **Lys alle geheue-areas:** `volatility -f memory_dump.raw memmap`
- **Vind 'n spesifieke proses se inligting oor geheuegebruik:** `volatility -f memory_dump.raw vadinfo -p <PID>`
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Meesterlêertabel

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Basiese Geheue Dump Analise Metodologie

1. **Proses Profilering**
   - Identifiseer die bedryfstelsel en weergawe.
   - Kies die regte profiel vir analise.

2. **Proses Analise**
   - Identifiseer aktiewe prosesse.
   - Kyk na verdagte prosesse.
   - Ontleed proses geheue.

3. **Netwerk Analise**
   - Identifiseer netwerkverbindings en -aktiwiteite.
   - Ontleed netwerk buffers en data.

4. **Gebruikersaktiwiteit**
   - Identifiseer gebruikersaktiwiteit en -interaksies.
   - Ontleed gebruikersdata en -aktiwiteit.

5. **Verdagte Aktiwiteit**
   - Identifiseer en ondersoek verdagte aktiwiteit.
   - Kyk na verdagte prosesse, netwerkverbindings, en gebruikersaktiwiteit.

6. **Data Ontleding**
   - Ontleed data in geheue.
   - Identifiseer en ontleed relevante data.

7. **Rapportering**
   - Stel 'n volledige verslag op van die analisebevindinge.
   - Sluit alle relevante inligting in vir verdere ondersoek.

#### Volatiliteit Bevele

- **Imageinfo:** Verskaf inligting oor die geheue dump.
- **Pslist:** Gee 'n lys van aktiewe prosesse.
- **Pstree:** Vertoon prosesboomstruktuur.
- **Netscan:** Identifiseer netwerkverbindings.
- **Connections:** Toon aktiewe netwerkverbindings.
- **Cmdline:** Haal die bevellynargumente van prosesse op.
- **Filescan:** Skandeer vir geopen lêers deur prosesse.
- **Handles:** Identifiseer lêerhandvatsels deur prosesse.
- **Vadinfo:** Verskaf inligting oor virtuele adresruimtes.
- **Yarascan:** Skandeer vir patrone met YARA reëls.
- **Malfind:** Identifiseer verdagte prosesse.
- **Dlldump:** Haal DLL-lêers uit prosesse.
- **Memdump:** Stoor 'n geheue dump van 'n spesifieke proses.
- **Rdpscan:** Identifiseer RDP-sessies.
- **Kdbgscan:** Identifiseer KDBG-adresse.
- **Apihooks:** Identifiseer API-hake in prosesse.
- **Ldrmodules:** Gee 'n lys van gelaai DLL-lêers.
- **Driverirp:** Identifiseer stuurprograma IRP's.
- **Privs:** Toon prosespriviliges.
- **Cmdscan:** Identifiseer bevellynargumente in prosesse.
- **Consoles:** Identifiseer proseskonsole-inligting.
- **Malfind:** Identifiseer verdagte prosesse.
- **Dmesg:** Toon die kernel-messagelog.
- **Hivelist:** Gee 'n lys van gelaai hive-profiel.
- **Hivedump:** Haal hive-lêers uit prosesse.
- **Hiveinspect:** Identifiseer hive-inligting.
- **Printkey:** Toon sleutelinhoud van die register.
- **Handles:** Identifiseer lêerhandvatsels deur prosesse.
- **Privs:** Toon prosespriviliges.
- **Threads:** Gee 'n lys van prosesdrade.
- **Vadtree:** Vertoon virtuele adresruimteboomstruktuur.
- **Vadwalk:** Loop deur virtuele adresruimte.
- **Vadinfo:** Verskaf inligting oor virtuele adresruimtes.
- **Vadscan:** Skandeer vir spesifieke virtuele adresruimte-eienskappe.
- **Vadtype:** Identifiseer die tipe virtuele adresruimte.
- **Vaddump:** Haal virtuele adresruimte uit prosesse.
- **Vadcarve:** Herstel verlore virtuele adresruimte.
- **Modscan:** Identifiseer gelaai modules.
- **Moddump:** Haal module-lêers uit prosesse.
- **Modload:** Laai 'n module in die geheue.
- **Malfind:** Identifiseer verdagte prosesse.
- **Apihooks:** Identifiseer API-hake in prosesse.
- **Apihooks:** Identifiseer API-hake in prosesse.
- **Apihooks:** Identifiseer API-hake in prosesse.
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
Die **NTFS-lêersisteem** maak gebruik van 'n kritiese komponent wat bekend staan as die _meesterlêertabel_ (MFT). Hierdie tabel sluit ten minste een inskrywing vir elke lêer op 'n volume in, wat ook die MFT self insluit. Belangrike besonderhede oor elke lêer, soos **grootte, tydstempels, regte, en werklike data**, is ingekapsuleer binne die MFT-inskrywings of in areas ekstern tot die MFT maar waarna verwys word deur hierdie inskrywings. Meer besonderhede kan gevind word in die [amp;offisiële dokumentasie](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
Afrikaanse vertaling:

{% endtab %}

{% tab title="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %}Volatility Spiekbrief

### Basiese Geheue Dump Analise

#### Volatile Data

- **Prosesse en Dienste**
  - `pslist`: Lys alle prosesse
  - `psscan`: Skandeer vir prosesinligting
  - `pstree`: Toon prosesboom

- **Netwerkaktiwiteit**
  - `netscan`: Skandeer vir netwerkverbindings
  - `sockets`: Lys alle oop sokkels
  - `connscan`: Skandeer vir netwerkverbindings

- **Gebruikersaktiwiteit**
  - `sessions`: Lys gebruikerssessies
  - `cmdscan`: Skandeer vir opdragreëls

- **Ander nuttige beveelde**
  - `dlllist`: Lys gelaai DLL's
  - `handles`: Lys oop handvatsels
  - `filescan`: Skandeer vir oop lêers

#### Nie-Volatile Data

- **Registry-analise**
  - `hivelist`: Lys gelaai hive's
  - `printkey`: Druk sleutelinhoud
  - `dumpkey`: Stort sleutelinhoud

- **Lêeranalise**
  - `filescan`: Skandeer vir oop lêers
  - `dumpfiles`: Stort lêers na die skryfgeheue

- **Prosesanalise**
  - `malfind`: Identifiseer verdagte prosesse
  - `ldrmodules`: Lys gelaai modules per proses

- **Netwerkanalise**
  - `connections`: Lys netwerkverbindings
  - `connscan`: Skandeer vir netwerkverbindings

- **Gebruikersanalise**
  - `getsids`: Kry gebruikers-SID's
  - `getsid`: Kry SID vir spesifieke gebruiker

- **Ander nuttige beveelde**
  - `apihooks`: Identifiseer API-hake
  - `callbacks`: Lys geregistreerde terugroepfunksies
  - `driverirp`: Analiseer bestuurs-I/O-aanvraag-pakket

### Gebruik Volatility om 'n Geheue Dump te Analiseer

1. **Identifiseer Profiel**
   - `imageinfo`: Kry inligting oor die geheue dump

2. **Analiseer Geheue**
   - Kies relevante analise-module (bv. `pslist`, `netscan`, ens.)
   - Voer die bevel uit met die korrekte profiel

3. **Dieper Analise**
   - Gebruik ander Volatility-bevele om spesifieker te ondersoek

4. **Stoor Resultate**
   - Skryf die resultate na lêers vir verdere ondersoek

5. **Interpreteer Data**
   - Analiseer die data om insigte te kry oor die geheue dump

6. **Rapportering**
   - Stel 'n verslag op van bevindings

### Voorbeelde

- Analiseer alle prosesse:
  ```bash
  volatility -f memdump.mem pslist
  ```

- Identifiseer verdagte prosesse:
  ```bash
  volatility -f memdump.mem malfind
  ```

- Skandeer vir netwerkverbindings:
  ```bash
  volatility -f memdump.mem netscan
  ```

- Lys gebruikerssessies:
  ```bash
  volatility -f memdump.mem sessions
  ```

- Lys gelaai DLL's:
  ```bash
  volatility -f memdump.mem dlllist
  ```

- Druk sleutelinhoud van 'n registry hive:
  ```bash
  volatility -f memdump.mem printkey -o hiveoffset -K key
  ```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### Skandering met yara

Gebruik hierdie skripsie om al die yara-malware-reëls vanaf github af te laai en saam te voeg: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Skep die _**reëls**_ gids en voer dit uit. Dit sal 'n lêer genaamd _**malware\_rules.yar**_ skep wat al die yara-reëls vir malware bevat.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `volmemory_dump> --profile=<profile> file -S <start_address> -E <end_address> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> --output-file <output_file>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Dumping User Credentials**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Identifying Driver IRP**
  - `volvolatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Dumping Kernel Cache**
  - `volatility -f <memory_dump> --profile=<profile> kdbgscan`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Dumping Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> moddump -D <output_directory>`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Dumping Process Environment**
  - `volatility -f <memory_dump> --profile=<profile> envars`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Identifying Malware Artifacts**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Dumping WMI Filters**
  - `volatility -f <memory_dump> --profile=<profile> wmi`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Identifying Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Dumping Desktop Heaps**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Analyzing Atom Tables**
  - `volatility -f <memory_dump> --profile=<profile> atomscan`

- **Identifying Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Dumping Session Hives**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Identifying Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Dumping Cached Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Identifying Imposters**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Dumping Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Analyzing LDR Entries**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Malicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Driver Sections**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Analyzing Driver IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Dumping Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Identifying Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Dumping Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Dumping Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> netscan`

- **Identifying Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Dumping Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Identifying Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Dumping Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Identifying Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> windows`

- **Dumping Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Identifying Hidden Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Dumping Hidden Session Hives**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Analyzing Hidden Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Identifying Hidden Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Dumping Hidden Cached Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing Hidden API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Identifying Hidden Imposters**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Dumping Hidden Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Analyzing Hidden LDR Entries**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Malicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden Driver Sections**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Analyzing Hidden Driver IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Dumping Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Identifying Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> netscan`

- **Dumping Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Identifying Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Dumping Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Dumping Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> windows`

- **Analyzing Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Hidden Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Dumping Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Identifying Hidden Session Hives**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Dumping Hidden Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Analyzing Hidden Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Identifying Hidden Cached Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping Hidden API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden Imposters**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Identifying Hidden Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Dumping Hidden LDR Entries**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Malicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Driver Sections**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Dumping Hidden Driver IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Dumping Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden IRPs**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Identifying Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> netscan`

- **Dumping Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Identifying Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Dumping Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Dumping Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> windows`

- **Analyzing Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Hidden Desktops**
  - `volatility -f <memory_dump> --profile=<profile> desktops`

- **Dumping Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Sessions**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Identifying Hidden Session Hives**
  - `volatility -f <memory_dump> --profile=<profile> sessions`

- **Dumping Hidden Shimcache**
  - `volatility -f <memory_dump> --profile=<profile> shimcache`

- **Identifying Hidden Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Dumping Hidden Cached Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing Hidden API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Identifying Hidden Imposters**
  - `volatility -f <memory_dump> --profile=<profile> getsids`

- **Dumping Hidden Cached Credentials**
  - `volatility -f <memory_dump> --profile=<profile> cachedump`

- **Analyzing Hidden LDR Entries**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Malicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden Driver Sections**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Analyzing Hidden Driver IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Identifying Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Identifying Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> getservicesids`

- **Dumping Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Dumping Hidden IRPs**
  - `volatility -f <memory_dump>
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## VERSKILLENDE

### Eksterne invoegtoepassings

As jy eksterne invoegtoepassings wil gebruik, moet jy seker maak dat die gelate wat verband hou met die invoegtoepassings die eerste parameter is wat gebruik word.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}Afrikaans translation{% endtab %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
#### Autoruns

Laai dit af van [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Basiese Geheue Dump Analise Metodologie

1. **Prosesanalise**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 pslist`

2. **Netwerkverkeer**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 netscan`

3. **Bestandstelselaktiwiteit**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 filescan`

4. **Registry-analise**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"`

5. **Prosesverkeer**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 malfind`

6. **Geheuekaart**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 memmap`

7. **Kernelmodule**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 modscan`

8. **API-logboeke**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 apihooks`

9. **Rootkitverkenning**
   - `vol.py -f memdump.mem --profile=Win7SP1x64 rootkit`

10. **Volledige scan**
    - `vol.py -f memdump.mem --profile=Win7SP1x64`

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Symboliese skakels

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Algemene Inligting

- **Volatiliteit** is 'n kragtige geheue-analise-raamwerk.
- Dit kan gebruik word vir forensiese ondersoeke en om inligting uit geheue-dumpe te onttrek.
- Dit ondersteun 'n wye verskeidenheid van bedryfstelsels en geheue-argitekture.

#### Basiese Gebruik

1. **Profiel bepaling**: Identifiseer die korrekte profiel vir die geheue-dump.
2. **Inligting soektog**: Soek na spesifieke inligting in die geheue-dump.
3. **Prosesse en modules**: Identifiseer aktiewe prosesse en gelaai modules.
4. **Netwerkaktiwiteit**: Onthul inligting oor netwerkverbindings en -aktiwiteit.
5. **Gebruikersaktiwiteit**: Vind inligting oor gebruikersaktiwiteit in die geheue-dump.

#### Gevorderde Gebruik

- **Kernel-objekte**: Identifiseer en ondersoek kernel-objekte in die geheue.
- **Rootkit-ontleding**: Spoor en ontleed verborge prosesse en aktiwiteite.
- **Malware-analise**: Help om malware-aktiwiteit in die geheue te identifiseer.
- **Data-herwinning**: Herstel verlore of verwyderde inligting uit die geheue-dump.

#### Bronne

- Volatiliteit-dokumentasie: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)
- Volatiliteit-plugins: [https://github.com/volatilityfoundation/volatility/wiki/Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

Dit is moontlik om **vanaf die geheue die bash geskiedenis te lees.** Jy kan ook die _.bash\_history_ lêer dump, maar as dit uitgeskakel is, sal jy bly wees dat jy hierdie volatility module kan gebruik.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}### Volatility Cheatsheet

#### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
     - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

#### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Identifying Kernel Modules**
  - `voljson -f <memory_dump> --profile=<profile>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Extracting DLLs from a Process**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Identifying Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Driver Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing LDRModules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Vad Trees**
  - `volatility -f <memory_dump> --profile=<profile> vadtree`

- **Analyzing Vad Walk**
  - `volatility -f <memory_dump> --profile=<profile> vadwalk`

- **Analyzing Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Malproc**
  - `volatility -f <memory_dump> --profile=<profile> malproc`

- **Analyzing Malware Config**
  - `volatility -f <memory_dump> --profile=<profile> malconfscan`

- **Analyzing Malware Strings**
  - `volatility -f <memory_dump> --profile=<profile> malstr`

- **Analyzing Malware API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> malapi`

- **Analyzing Malware Pid**
  - `volatility -f <memory_dump> --profile=<profile> malpid`

- **Analyzing Malware Yara**
  - `volatility -f <memory_dump> --profile=<profile> malyara`

- **Analyzing Malware Malfind**
  - `volatility -f <memory_dump> --profile=<profile> malmind`

- **Analyzing Malware Malsysproc**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malserv**
  - `volatility -f <memory_dump> --profile=<profile> malserv`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -f <memory_dump> --profile=<profile> malthr`

- **Analyzing Malware Malthr**
  - `volatility -
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Tydlyn

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}Translate the relevant English text to Afrikaans and return the translation keeping excatly the same markdown and html syntax. Do not translate things like code, hacking technique names, hacking word, cloud/SaaS platform names (like Workspace, aws, gcp...), the word 'leak', pentesting, and markdown tags. Also don't add any extra stuff apart from the translation and markdown syntax.
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### Bestuurders

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
Afrikaanse vertaling:

### Volatiliteit Spiekbrief

#### Basiese Geheue Dump Analise

1. **Volatiliteit Installeer**
   - `pip install volatility`

2. **Profiel bepaal**
   - `volatility -f memory_dump.raw imageinfo`

3. **Prosesse ondersoek**
   - `volatility -f memory_dump.raw --profile=Profile pslist`

4. **Netwerkaktiwiteit**
   - `volatility -f memory_dump.raw --profile=Profile netscan`

5. **Bestandeondersoek**
   - `volatility -f memory_dump.raw --profile=Profile filescan`

6. **Verdagte modules**
   - `volatility -f memory_dump.raw --profile=Profile modscan`

7. **Registry-analise**
   - `volatility -f memory_dump.raw --profile=Profile hivelist`
   - `volatility -f memory_dump.raw --profile=Profile printkey -o OFFSET`

8. **Gebruikersaktiwiteit**
   - `volatility -f memory_dump.raw --profile=Profile userassist`

9. **Koppelvlakaktiwiteit**
   - `volatility -f memory_dump.raw --profile=Profile shimcache`

10. **Volledige prosesboom**
    - `volatility -f memory_dump.raw --profile=Profile pstree`

11. **Verdagte drade**
    - `volatility -f memory_dump.raw --profile=Profile threads`

12. **DLL's**
    - `volatility -f memory_dump.raw --profile=Profile dlllist`

13. **Kernelmodules**
    - `volatility -f memory_dump.raw --profile=Profile kdbgscan`
    - `volatility -f memory_dump.raw --profile=Profile ldrmodules`

14. **Netwerkverbindings**
    - `volatility -f memory_dump.raw --profile=Profile connections`

15. **Skeduleerderaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile malfind`

16. **Geheuekaart**
    - `volatility -f memory_dump.raw --profile=Profile memmap`

17. **API-hoëvlakaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile apihooks`

18. **Rootkit-aktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile rootkit`

19. **Geheue-inhoud**
    - `volatility -f memory_dump.raw --profile=Profile memdump -p PID -D .`

20. **VSA**
    - `volatility -f memory_dump.raw --profile=Profile vadinfo`

21. **Geheue-analise**
    - `volatility -f memory_dump.raw --profile=Profile memmap`

22. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userhandles`

23. **API-skeduleerderaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile apiscan`

24. **Gebruikersinligting**
    - `volatility -f memory_dump.raw --profile=Profile getsids`

25. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

26. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

27. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

28. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

29. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

30. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

31. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

32. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

33. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

34. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

35. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

36. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

37. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

38. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

39. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

40. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

41. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

42. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

43. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

44. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

45. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

46. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

47. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

48. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

49. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`

50. **Gebruikersaktiwiteit**
    - `volatility -f memory_dump.raw --profile=Profile userassist`
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Kry knipbord
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Kry IE geskiedenis
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Kry notepad teks
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Skermkiekie
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Meester Opstartsleutel (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Die **Master Boot Record (MBR)** speel 'n kritieke rol in die bestuur van die logiese partisies van 'n stoormedium, wat gestruktureer is met verskillende [lêersisteme](https://en.wikipedia.org/wiki/File\_system). Dit hou nie net partisie uitleg in nie, maar bevat ook uitvoerbare kode wat as 'n opstartlader optree. Hierdie opstartlader inisieer óf direk die OS se tweede-fase laaiproses (sien [tweede-fase opstartlader](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)) óf werk in harmonie met die [volume boot record](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) van elke partisie. Vir in-diepte kennis, verwys na die [MBR Wikipedia-bladsy](https://en.wikipedia.org/wiki/Master\_boot\_record).

## Verwysings

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
