# Volatility - Spiekbrief

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheidsevenement in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en kuberveiligheidspesialiste in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

As jy iets **vinnig en mal** wil hê wat verskeie Volatility-plugins gelyktydig sal uitvoer, kan jy gebruik maak van: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
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
#### Metode 1

Die eerste metode wat gebruik kan word om 'n geheue-dump te analiseer, is deur die gebruik van die `volatility2`-raamwerk. Hier is 'n paar nuttige opdragte wat gebruik kan word:

##### Basiese opdragte

- `imageinfo`: Hierdie opdrag gee inligting oor die geheue-dump, soos die besturingstelsel, die argitektuur en die tyd van die dump.
- `pslist`: Hierdie opdrag lys die aktiewe prosesse in die geheue-dump.
- `pstree`: Hierdie opdrag gee 'n boomstruktuur van die prosesse in die geheue-dump.
- `dlllist`: Hierdie opdrag lys die gelaai DLL's in die geheue-dump.
- `handles`: Hierdie opdrag gee 'n lys van die hanteerders in die geheue-dump.
- `filescan`: Hierdie opdrag soek na oop lêers in die geheue-dump.
- `cmdline`: Hierdie opdrag gee die opdraglyne van die prosesse in die geheue-dump.
- `vadinfo`: Hierdie opdrag gee inligting oor die virtuele adresruimtes in die geheue-dump.

##### Gevorderde opdragte

- `malfind`: Hierdie opdrag soek na verdagte kode in die geheue-dump.
- `apihooks`: Hierdie opdrag soek na API-hake in die geheue-dump.
- `ldrmodules`: Hierdie opdrag gee inligting oor die gelaai modules in die geheue-dump.
- `modscan`: Hierdie opdrag soek na verdagte modules in die geheue-dump.
- `ssdt`: Hierdie opdrag gee inligting oor die System Service Descriptor Table (SSDT) in die geheue-dump.
- `driverscan`: Hierdie opdrag soek na verdagte bestuurders in die geheue-dump.
- `mutantscan`: Hierdie opdrag soek na verdagte mutante in die geheue-dump.

##### Voorbeeldopdragte

- `volatility2 -f dump.raw imageinfo`: Voer die `imageinfo`-opdrag uit op die geheue-dump `dump.raw`.
- `volatility2 -f dump.raw pslist`: Lys die aktiewe prosesse in die geheue-dump `dump.raw`.
- `volatility2 -f dump.raw malfind`: Soek na verdagte kode in die geheue-dump `dump.raw`.
- `volatility2 -f dump.raw ldrmodules`: Gee inligting oor die gelaai modules in die geheue-dump `dump.raw`.

{% endtab %}

{% tab title="Method2" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% tab title="Metode 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility Opdragte

Kry toegang tot die amptelike dokumentasie in [Volatility-opdragverwysing](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### 'n Nota oor "lys" vs. "skandering" invoegtoepassings

Volatility het twee hoofbenaderings tot invoegtoepassings, wat soms weerspieël word in hul name. "Lys" invoegtoepassings sal probeer om deur Windows Kernel-strukture te navigeer om inligting soos prosesse op te haal (lokalisering en loop deur die gekoppelde lys van `_EPROCESS` strukture in die geheue), OS-hanteerders (lokalisering en lys van die hanteerdertabel, dereferensie van enige gevonde wysers, ens.). Hulle gedra hulle min of meer soos die Windows API sou doen as dit versoek sou word om byvoorbeeld prosesse te lys.

Dit maak "lys" invoegtoepassings redelik vinnig, maar net so kwesbaar soos die Windows API vir manipulasie deur kwaadwillige sagteware. Byvoorbeeld, as kwaadwillige sagteware DKOM gebruik om 'n proses van die `_EPROCESS` gekoppelde lys af te koppel, sal dit nie in die Taakbestuurder verskyn nie en ook nie in die pslys nie.

"Skandering" invoegtoepassings daarenteen sal 'n benadering volg wat soortgelyk is aan die uitsny van die geheue vir dinge wat sin maak wanneer dit as spesifieke strukture gedereferensieer word. `psscan` sal byvoorbeeld die geheue lees en probeer om `_EPROCESS`-voorwerpe daaruit te maak (dit gebruik pool-tag-skandering, wat soek na 4-byte-reekse wat die teenwoordigheid van 'n belangrike struktuur aandui). Die voordeel is dat dit prosesse kan opgrawe wat beëindig is, en selfs as kwaadwillige sagteware met die `_EPROCESS` gekoppelde lys knoei, sal die invoegtoepassing steeds die struktuur in die geheue vind (aangesien dit steeds moet bestaan vir die proses om te loop). Die nadeel is dat "skandering" invoegtoepassings 'n bietjie stadiger as "lys" invoegtoepassings is, en soms vals positiewe resultate kan lewer ('n proses wat te lank gelede beëindig is en waarvan dele van die struktuur deur ander operasies oorskryf is).

Bron: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## BS-profiel

### Volatility3

Soos in die leesmyl verduidelik, moet jy die **simbooltabel van die BS** wat jy wil ondersteun, in _volatility3/volatility/symbols_ plaas.\
Simbooltabelpakke vir die verskillende bedryfstelsels is beskikbaar vir **aflaai** by:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Eksterne profiel

Jy kan die lys van ondersteunde profiele kry deur die volgende te doen:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
As jy 'n **nuwe profiel wat jy afgelaai het** wil gebruik (byvoorbeeld 'n Linux-profiel), moet jy die volgende vouerstruktuur êrens skep: _plugins/overlays/linux_ en sit die zip-lêer wat die profiel bevat binne hierdie vouer. Kry dan die nommer van die profiele deur die volgende te gebruik:
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

In die vorige blok kan jy sien dat die profiel genoem word `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, en jy kan dit gebruik om iets soos die volgende uit te voer:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Ontdek Profiel
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Verskille tussen imageinfo en kdbgscan**

[**Vanaf hier**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): In teenstelling met imageinfo wat slegs profielvoorstelle bied, is **kdbgscan** ontwerp om die korrekte profiel en die korrekte KDBG-adres positief te identifiseer (as daar dalk meer as een is). Hierdie invoegtoepassing skandeer vir die KDBGHeader-handtekeninge wat gekoppel is aan Volatility-profiels en pas sinvolheidskontroles toe om vals positiewe te verminder. Die uitvoer se oorvloedigheid en die aantal sinvolheidskontroles wat uitgevoer kan word, hang af van of Volatility 'n DTB kan vind. As jy reeds die korrekte profiel ken (of as jy 'n profielvoorstel van imageinfo het), moet jy seker maak dat jy dit gebruik.

Neem altyd 'n kykie na die **aantal prosesse wat kdbgscan gevind het**. Soms kan imageinfo en kdbgscan **meer as een geskikte profiel vind**, maar slegs die **geldige een sal enkele prosesse hê** (Dit is omdat die korrekte KDBG-adres nodig is om prosesse te onttrek).
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

Die **kernel debugger block**, bekend as **KDBG** deur Volatility, is noodsaaklik vir forensiese take wat deur Volatility en verskeie debuggers uitgevoer word. Dit word geïdentifiseer as `KdDebuggerDataBlock` en is van die tipe `_KDDEBUGGER_DATA64`. Dit bevat essensiële verwysings soos `PsActiveProcessHead`. Hierdie spesifieke verwysing wys na die kop van die proseslys, wat die lys van alle prosesse moontlik maak, wat fundamenteel is vir deeglike geheue-analise.

## Bedryfstelselinligting
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Die invoegtoepassing `banners.Banners` kan gebruik word in **vol3 om Linux-banners** in die dump te probeer vind.

## Hasse/Wagwoorde

Onttrek SAM-hashe, [gekasteerde geloofsbriewe van die domein](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) en [lsa-geheime](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To filter the output based on a specific process name, use the `--name` option followed by the process name.

```
python vol.py -f <memory_dump> pslist --name <process_name>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network sockets, such as local and remote IP addresses, port numbers, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To filter the output based on a specific IP address or port number, use the `--ip` or `--port` option followed by the IP address or port number.

```
python vol.py -f <memory_dump> netscan --ip <ip_address>
python vol.py -f <memory_dump> netscan --port <port_number>
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles, file names, and file paths.

```
python vol.py -f <memory_dump> filescan
```

To extract a specific file from the memory dump, use the `dumpfiles` plugin followed by the file path.

```
python vol.py -f <memory_dump> dumpfiles --dump-dir <output_directory> --name <file_path>
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a starting point for using Volatility and performing common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of memory forensics.
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Geheue Dump

Die geheue dump van 'n proses sal **alles onttrek** van die huidige status van die proses. Die **procdump** module sal slegs die **kode onttrek**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteitsgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitsprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Prosesse

### Lys prosesse

Probeer om **verdagte** prosesse (volgens naam) of **onverwagte** kinderprosesse (byvoorbeeld 'n cmd.exe as 'n kind van iexplorer.exe) te vind.\
Dit kan interessant wees om die resultaat van pslist te vergelyk met dié van psscan om verborge prosesse te identifiseer.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To filter the output based on a specific process name, use the `--name` option followed by the process name.

```
python vol.py -f <memory_dump> pslist --name <process_name>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network sockets, such as local and remote IP addresses, port numbers, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To filter the output based on a specific IP address or port number, use the `--ip` or `--port` option followed by the IP address or port number.

```
python vol.py -f <memory_dump> netscan --ip <ip_address>
python vol.py -f <memory_dump> netscan --port <port_number>
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles, file names, and file paths.

```
python vol.py -f <memory_dump> filescan
```

To extract a specific file from the memory dump, use the `dumpfiles` plugin followed by the file path.

```
python vol.py -f <memory_dump> dumpfiles --dump-dir <output_directory> --name <file_path>
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a starting point for using Volatility and performing common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of memory forensics.
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### Stortingsproses

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their associated information, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network connections, including local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles and file names.

```
python vol.py -f <memory_dump> filescan
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. By using the commands and techniques outlined in this cheatsheet, you can perform a wide range of memory analysis tasks and gain insights into various types of incidents.
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Opdraglyn

Is daar enige iets verdagtes uitgevoer?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their associated information, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network connections, including local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles and file names.

```
python vol.py -f <memory_dump> filescan
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. By using the commands and techniques outlined in this cheatsheet, you can perform a wide range of memory analysis tasks and gain insights into various types of incidents.
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Opdragte wat in `cmd.exe` uitgevoer word, word bestuur deur **`conhost.exe`** (of `csrss.exe` op stelsels voor Windows 7). Dit beteken dat as **`cmd.exe`** deur 'n aanvaller beëindig word voordat 'n geheue-dump verkry word, dit steeds moontlik is om die opdraggeskiedenis van die sessie te herstel uit die geheue van **`conhost.exe`**. Om dit te doen, as ongewone aktiwiteit binne die modules van die konsole opgespoor word, moet die geheue van die betrokke **`conhost.exe`**-proses gedump word. Dan kan deur te soek na **strings** binne hierdie dump, moontlik opdraglyne wat in die sessie gebruik is, onttrek word.

### Omgewing

Kry die omgewingsveranderlikes van elke lopende proses. Daar kan interessante waardes wees.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Identifiseer die profiel van die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Vertoon 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's vir 'n spesifieke proses in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer vir lêers in die geheue-dump.
- `cmdline`: Vertoon die bevellyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

### Geheue-analise Opdragte

- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.

### Geheue-analise Funksies

- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.

## Volatility Profiele

Hierdie is 'n lys van algemene profiele wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

- `WinXPSP2x86`: Windows XP SP2 x86
- `WinXPSP3x86`: Windows XP SP3 x86
- `Win7SP0x86`: Windows 7 SP0 x86
- `Win7SP1x86`: Windows 7 SP1 x86
- `Win2003SP0x86`: Windows 2003 SP0 x86
- `Win2003SP1x86`: Windows 2003 SP1 x86
- `Win2003SP2x86`: Windows 2003 SP2 x86
- `Win2003R2SP0x86`: Windows 2003 R2 SP0 x86
- `Win2003R2SP1x86`: Windows 2003 R2 SP1 x86
- `Win2003R2SP2x86`: Windows 2003 R2 SP2 x86
- `Win2008SP1x86`: Windows 2008 SP1 x86
- `Win2008SP2x86`: Windows 2008 SP2 x86
- `Win2008R2SP0x86`: Windows 2008 R2 SP0 x86
- `Win2008R2SP1x86`: Windows 2008 R2 SP1 x86
- `Win2012SP0x86`: Windows 2012 SP0 x86
- `Win2012SP1x86`: Windows 2012 SP1 x86
- `Win2012R2SP0x86`: Windows 2012 R2 SP0 x86
- `Win2012R2SP1x86`: Windows 2012 R2 SP1 x86
- `Win2016SP0x86`: Windows 2016 SP0 x86
- `Win2016SP1x86`: Windows 2016 SP1 x86
- `Win2019SP0x86`: Windows 2019 SP0 x86
- `Win2019SP1x86`: Windows 2019 SP1 x86

## Bronne

- [Volatility Framework](https://www.volatilityfoundation.org/)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### Token voorregte

Kyk vir voorregte tokens in onverwagte dienste.\
Dit kan interessant wees om die prosesse te lys wat van sommige voorregte tokens gebruik maak.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their associated information, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network connections, including local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles and file names.

```
python vol.py -f <memory_dump> filescan
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a quick reference guide for using Volatility to perform common memory analysis tasks. Experiment with different plugins and options to maximize the effectiveness of your memory analysis.
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Kyk na elke SSID wat deur 'n proses besit word.\
Dit kan interessant wees om die prosesse wat 'n bevoorregte SSID gebruik (en die prosesse wat 'n diens SSID gebruik) te lys.
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Identifiseer die profiel van die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Vertoon 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's vir 'n spesifieke proses in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer vir lêers in die geheue-dump.
- `cmdline`: Vertoon die bevellyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

### Geheue-analise Opdragte

- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.

### Geheue-analise Funksies

- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `vadwalk`: Loop deur alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

## Volatility Profiele

- `WinXPSP2x86`: Windows XP SP2 x86
- `WinXPSP3x86`: Windows XP SP3 x86
- `Win7SP0x86`: Windows 7 SP0 x86
- `Win7SP1x86`: Windows 7 SP1 x86
- `Win7SP0x64`: Windows 7 SP0 x64
- `Win7SP1x64`: Windows 7 SP1 x64
- `Win2003SP0x86`: Windows 2003 SP0 x86
- `Win2003SP1x86`: Windows 2003 SP1 x86
- `Win2003SP2x86`: Windows 2003 SP2 x86
- `Win2003SP0x64`: Windows 2003 SP0 x64
- `Win2003SP1x64`: Windows 2003 SP1 x64
- `Win2003SP2x64`: Windows 2003 SP2 x64
- `Win2008SP1x86`: Windows 2008 SP1 x86
- `Win2008SP1x64`: Windows 2008 SP1 x64
- `Win2008SP2x86`: Windows 2008 SP2 x86
- `Win2008SP2x64`: Windows 2008 SP2 x64
- `WinVistaSP0x86`: Windows Vista SP0 x86
- `WinVistaSP1x86`: Windows Vista SP1 x86
- `WinVistaSP2x86`: Windows Vista SP2 x86
- `WinVistaSP0x64`: Windows Vista SP0 x64
- `WinVistaSP1x64`: Windows Vista SP1 x64
- `WinVistaSP2x64`: Windows Vista SP2 x64
- `Win2012R2x64`: Windows 2012 R2 x64
- `Win8SP0x86`: Windows 8 SP0 x86
- `Win8SP0x64`: Windows 8 SP0 x64
- `Win81SP0x86`: Windows 8.1 SP0 x86
- `Win81SP0x64`: Windows 8.1 SP0 x64
- `Win10x86`: Windows 10 x86
- `Win10x64`: Windows 10 x64

## Volatility Installasie

Volg hierdie stappe om Volatility Framework op Linux te installeer:

1. Installeer die vereiste afhanklikhede:

```bash
sudo apt-get install python2.7 python-pip
sudo pip install distorm3
```

2. Kloon die Volatility Framework-repo:

```bash
git clone https://github.com/volatilityfoundation/volatility.git
```

3. Navigeer na die Volatility Framework-directory:

```bash
cd volatility
```

4. Voer die installasieskrip uit:

```bash
sudo python setup.py install
```

## Volatility Gebruik

Om Volatility Framework te gebruik, voer die volgende opdrag uit:

```bash
volatility -f <geheue-dump> <opdrag>
```

Vervang `<geheue-dump>` met die pad na die geheue-dumplêer en `<opdrag>` met die spesifieke opdrag wat jy wil uitvoer.

## Bronne

- [Volatility Framework GitHub-repo](https://github.com/volatilityfoundation/volatility)
- [Volatility Framework Dokumentasie](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Framework Profiele](https://github.com/volatilityfoundation/profiles)
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Handvatsels

Nuttig om te weet aan watter ander lêers, sleutels, drade, prosesse... 'n **proses 'n handvat** het (geopen het)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To analyze a specific process, use the `psscan` plugin. This plugin scans the memory dump for process structures and displays information about each process, including its name, process ID, and parent process ID.

```
python vol.py -f <memory_dump> psscan --pid=<process_id>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about active network connections, including the local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To analyze network sockets, use the `sockets` plugin. This plugin lists all open network sockets and their details, such as the local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> sockets
```

## File Analysis

To analyze file handles in a memory dump, use the `handles` plugin. This plugin lists all open file handles and their details, such as the file name, file path, and process ID.

```
python vol.py -f <memory_dump> handles
```

To analyze file system artifacts, use the `mftparser` plugin. This plugin parses the Master File Table (MFT) and displays information about files, directories, and other file system objects.

```
python vol.py -f <memory_dump> mftparser
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a quick reference guide for using Volatility to perform common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of memory forensics.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% tab title="vol3" %}

### DLLs

{% tabs %}

{% tab title="1. DLL 리스트" %}

- DLL 리스트를 확인하기 위해서는 `dlllist` 명령어를 사용합니다.

```bash
volatility -f memory_dump.mem --profile=PROFILE dlllist
```

{% endtab %}

{% tab title="2. 특정 DLL 정보" %}

- 특정 DLL의 정보를 확인하기 위해서는 `dlldump` 명령어를 사용합니다.

```bash
volatility -f memory_dump.mem --profile=PROFILE dlldump -p PID -D DLL_NAME
```

{% endtab %}

{% tab title="3. DLL 메모리 덤프" %}

- DLL의 메모리 덤프를 확인하기 위해서는 `memdump` 명령어를 사용합니다.

```bash
volatility -f memory_dump.mem --profile=PROFILE memdump -p PID -D DLL_NAME -o OFFSET
```

{% endtab %}

{% endtabs %}

{% endtab %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, system compromises, and data breaches.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To analyze a specific process, use the `psscan` plugin. This plugin scans the memory dump for process structures and displays information about each process, including its name, process ID, and parent process ID.

```
python vol.py -f <memory_dump> psscan --pid=<process_id>
```

Replace `<process_id>` with the ID of the process you want to analyze.

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about active network connections, including the local and remote IP addresses, port numbers, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To analyze network sockets, use the `sockets` plugin. This plugin lists all open network sockets and their associated processes.

```
python vol.py -f <memory_dump> sockets
```

## File Analysis

To analyze file handles in a memory dump, use the `handles` plugin. This plugin lists all open file handles and their details, such as file name, process ID, and access rights.

```
python vol.py -f <memory_dump> handles
```

To analyze file system artifacts, use the `mftparser` plugin. This plugin parses the Master File Table (MFT) and displays information about files, directories, and other file system objects.

```
python vol.py -f <memory_dump> mftparser
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a quick reference guide for using Volatility to perform common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of the memory dump and the incident you are investigating.

For more information about Volatility and its capabilities, refer to the official documentation and community resources.
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Strings per prosesse

Volatility laat ons toe om te kyk tot watter proses 'n string behoort.
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik om inligting uit geheue-dumps te ontleed.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump, soos die besturingstelsel, die argitektuur en die tyd van die dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle hanteerder-objekte in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir gegewe lêername of uitbreidings.
- `cmdline`: Gee die opdraglyne van alle prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van die virtuele adresruimtes van prosesse in die geheue-dump.
- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `apihooks`: Identifiseer API-hake in die geheue-dump.

### Gevorderde Opdragte

- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `apihooks`: Identifiseer API-hake in die geheue-dump.
- `ldrmodules`: Lys alle gelaai modules in die geheue-dump.
- `modscan`: Skandeer die geheue-dump vir gegewe modulepatrone.
- `ssdt`: Gee inligting oor die System Service Descriptor Table (SSDT) in die geheue-dump.
- `driverirp`: Gee inligting oor die IRP-handlers van bestuurders in die geheue-dump.
- `devicetree`: Gee 'n boomstruktuur van die toestelboom in die geheue-dump.
- `privs`: Lys alle toegangsregte van prosesse in die geheue-dump.
- `envars`: Gee die omgewingsveranderlikes van prosesse in die geheue-dump.
- `cmdscan`: Skandeer die geheue-dump vir moontlike opdraglyne.
- `consoles`: Lys alle konsolvensters in die geheue-dump.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Die basis-klas vir Windows-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Die basis-klas vir Mac-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Die basis-klas vir Linux-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Die basis-klas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Die basis-klas vir iOS-opdragte.
- `volatility.plugins.common.AbstractBSDCommand`: Die basis-klas vir BSD-opdragte.

### Gevorderde Funksies

- `volatility.plugins.windows.registry.hivelist.HiveList`: Lys alle Windows-registernoeë in die geheue-dump.
- `volatility.plugins.windows.registry.printkey.PrintKey`: Druk die inhoud van 'n Windows-register sleutel.
- `volatility.plugins.windows.registry.printval.PrintVal`: Druk die waarde van 'n Windows-register sleutel.
- `volatility.plugins.windows.registry.userassist.UserAssist`: Gee inligting oor die UserAssist-sleutel in die Windows-register.
- `volatility.plugins.windows.registry.usbstor.USBStor`: Gee inligting oor USB-stoor toestelle in die Windows-register.
- `volatility.plugins.windows.registry.run.Run`: Gee inligting oor die uitvoering van programme in die Windows-register.
- `volatility.plugins.windows.registry.services.Services`: Gee inligting oor dienste in die Windows-register.
- `volatility.plugins.windows.registry.svcscan.SvcScan`: Skandeer die Windows-register vir dienste.
- `volatility.plugins.windows.registry.cmdline.CmdLine`: Gee die opdraglyne van programme in die Windows-register.
- `volatility.plugins.windows.registry.hivedump.HiveDump`: Stoor die inhoud van 'n Windows-register in 'n lêer.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Dit maak dit ook moontlik om te soek na strings binne 'n proses deur die yarascan module te gebruik:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source framework used for memory forensics. It allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheatsheet provides a quick reference guide for using Volatility to analyze memory dumps.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```bash
volatility -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can also specify additional options to customize the analysis.

## Common Plugins

Here are some commonly used Volatility plugins:

- `pslist`: Lists all running processes.
- `pstree`: Displays a process tree.
- `netscan`: Shows network connections.
- `modules`: Lists loaded modules.
- `handles`: Lists open handles.
- `dlllist`: Lists loaded DLLs.
- `cmdline`: Displays command-line arguments for processes.
- `filescan`: Scans for file objects in memory.

## Examples

Here are some examples of using Volatility:

- Analyze a memory dump and list all running processes:

```bash
volatility -f memory.dmp pslist
```

- Analyze a memory dump and display a process tree:

```bash
volatility -f memory.dmp pstree
```

- Analyze a memory dump and show network connections:

```bash
volatility -f memory.dmp netscan
```

## Conclusion

Volatility is a versatile tool for memory forensics. By using its powerful plugins, analysts can extract valuable information from memory dumps. This cheatsheet provides a quick reference guide for using Volatility to analyze memory dumps.
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** hou rekord van programme wat jy uitvoer deur gebruik te maak van 'n funksie in die register genaamd **UserAssist sleutels**. Hierdie sleutels hou by hoeveel keer elke program uitgevoer is en wanneer dit laas uitgevoer is.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump se beeld.
- `kdbgscan`: Skandeer vir die KDBG-handvatsel in die geheue-dump.
- `kpcrscan`: Skandeer vir die KPCR-handvatsel in die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesinligting in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle handvatsels in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte (VAD).
- `vadtree`: Gee 'n boomstruktuur van alle VAD's in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke VAD.
- `vadwalk`: Loop deur alle VAD's in die geheue-dump en gee inligting oor elkeen.
- `vadtree`: Gee 'n boomstruktuur van alle VAD's in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke VAD.
- `vadwalk`: Loop deur alle VAD's in die geheue-dump en gee inligting oor elkeen.

### Geheue-analise Opdragte

- `memmap`: Gee 'n lys van alle geheue-kaarte in die geheue-dump.
- `memdump`: Dump die inhoud van 'n spesifieke geheue-kaart.
- `memstrings`: Soek na ASCII- en Unicode-strings in die geheue-dump.
- `memscan`: Skandeer vir 'n spesifieke waarde in die geheue-dump.
- `memdiff`: Vergelyk twee geheue-dumps en identifiseer verskille.
- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.

### Gebruikersruimte Opdragte

- `cmdscan`: Skandeer vir uitgevoerde opdragte in die geheue-dump.
- `consoles`: Lys alle oop konsole-sessies in die geheue-dump.
- `cmdline`: Gee die opdraglyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `envars`: Lys alle omgewingsveranderlikes in die geheue-dump.
- `getsids`: Gee die sekuriteitsidentifikasienommers (SIDs) vir alle prosesse in die geheue-dump.
- `privs`: Lys die privilegiese van alle prosesse in die geheue-dump.
- `printkey`: Gee die inhoud van 'n spesifieke register sleutel in die geheue-dump.
- `printkey`: Gee die inhoud van 'n spesifieke register sleutel in die geheue-dump.
- `printkey`: Gee die inhoud van 'n spesifieke register sleutel in die geheue-dump.

### Kernelruimte Opdragte

- `modules`: Lys alle gelaai kernel modules in die geheue-dump.
- `modscan`: Skandeer vir kernel modules in die geheue-dump.
- `moddump`: Dump die inhoud van 'n spesifieke kernel module.
- `ssdt`: Gee die System Service Descriptor Table (SSDT) in die geheue-dump.
- `driverscan`: Skandeer vir gelaai kernel drivers in die geheue-dump.
- `driverirp`: Gee die IRP-handvatsels vir 'n spesifieke kernel driver in die geheue-dump.
- `driverirp`: Gee die IRP-handvatsels vir 'n spesifieke kernel driver in die geheue-dump.
- `driverirp`: Gee die IRP-handvatsels vir 'n spesifieke kernel driver in die geheue-dump.

### Netwerk Opdragte

- `connections`: Lys alle aktiewe netwerkverbindings in die geheue-dump.
- `sockets`: Lys alle aktiewe sokkels in die geheue-dump.
- `sockscan`: Skandeer vir sokkelinligting in die geheue-dump.
- `netscan`: Skandeer vir netwerkverbindings in die geheue-dump.
- `connscan`: Skandeer vir netwerkverbindings in die geheue-dump.
- `connscan`: Skandeer vir netwerkverbindings in die geheue-dump.
- `connscan`: Skandeer vir netwerkverbindings in die geheue-dump.

### Ander Opdragte

- `idt`: Gee die Interrupt Descriptor Table (IDT) in die geheue-dump.
- `gdt`: Gee die Global Descriptor Table (GDT) in die geheue-dump.
- `dt`: Gee die Descriptor Table (DT) in die geheue-dump.
- `ssdt`: Gee die System Service Descriptor Table (SSDT) in die geheue-dump.
- `callbacks`: Lys alle geregistreerde terugroepfunksies in die geheue-dump.
- `callbacks`: Lys alle geregistreerde terugroepfunksies in die geheue-dump.
- `callbacks`: Lys alle geregistreerde terugroepfunksies in die geheue-dump.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common: list_tasks()`: Gee 'n lys van alle aktiewe prosesse in die geheue-dump.
- `volatility.plugins.common: list_modules()`: Gee 'n lys van alle gelaai DLL's in die geheue-dump.
- `volatility.plugins.common: list_handles()`: Gee 'n lys van alle handvatsels in die geheue-dump.
- `volatility.plugins.common: list_drivers()`: Gee 'n lys van alle gelaai kernel drivers in die geheue-dump.
- `volatility.plugins.common: list_connections()`: Gee 'n lys van alle aktiewe netwerkverbindings in die geheue-dump.

### Geheue-analise Funksies

- `volatility.plugins.memmap: get_memmap()`: Gee 'n lys van alle geheue-kaarte in die geheue-dump.
- `volatility.plugins.memdump: dump_mem()`: Dump die inhoud van 'n spesifieke geheue-kaart.
- `volatility.plugins.memstrings: search_mem()`: Soek na ASCII- en Unicode-strings in die geheue-dump.
- `volatility.plugins.memscan: scan_mem()`: Skandeer vir 'n spesifieke waarde in die geheue-dump.
- `volatility.plugins.memdiff: diff_mem()`: Vergelyk twee geheue-dumps en identifiseer verskille.
- `volatility.plugins.malfind: find_malware()`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.

### Gebruikersruimte Funksies

- `volatility.plugins.cmdscan: scan_cmd()`: Skandeer vir uitgevoerde opdragte in die geheue-dump.
- `volatility.plugins.consoles: list_consoles()`: Lys alle oop konsole-sessies in die geheue-dump.
- `volatility.plugins.cmdline: get_cmdline()`: Gee die opdraglyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `volatility.plugins.envars: list_envars()`: Lys alle omgewingsveranderlikes in die geheue-dump.
- `volatility.plugins.getsids: get_sids()`: Gee die sekuriteitsidentifikasienommers (SIDs) vir alle prosesse in die geheue-dump.
- `volatility.plugins.privs: list_privs()`: Lys die privilegiese van alle prosesse in die geheue-dump.
- `volatility.plugins.printkey: print_key()`: Gee die inhoud van 'n spesifieke register sleutel in die geheue-dump.

### Kernelruimte Funksies

- `volatility.plugins.modules: list_modules()`: Lys alle gelaai kernel modules in die geheue-dump.
- `volatility.plugins.modscan: scan_modules()`: Skandeer vir kernel modules in die geheue-dump.
- `volatility.plugins.moddump: dump_module()`: Dump die inhoud van 'n spesifieke kernel module.
- `volatility.plugins.ssdt: get_ssdt()`: Gee die System Service Descriptor Table (SSDT) in die geheue-dump.
- `volatility.plugins.driverscan: scan_drivers()`: Skandeer vir gelaai kernel drivers in die geheue-dump.
- `volatility.plugins.driverirp: get_irp()`: Gee die IRP-handvatsels vir 'n spesifieke kernel driver in die geheue-dump.

### Netwerk Funksies

- `volatility.plugins.connections: list_connections()`: Lys alle aktiewe netwerkverbindings in die geheue-dump.
- `volatility.plugins.sockets: list_sockets()`: Lys alle aktiewe sokkels in die geheue-dump.
- `volatility.plugins.sockscan: scan_sockets()`: Skandeer vir sokkelinligting in die geheue-dump.
- `volatility.plugins.netscan: scan_network()`: Skandeer vir netwerkverbindings in die geheue-dump.

### Ander Funksies

- `volatility.plugins.idt: get_idt()`: Gee die Interrupt Descriptor Table (IDT) in die geheue-dump.
- `volatility.plugins.gdt: get_gdt()`: Gee die Global Descriptor Table (GDT) in die geheue-dump.
- `volatility.plugins.dt: get_dt()`: Gee die Descriptor Table (DT) in die geheue-dump.
- `volatility.plugins.ssdt: get_ssdt()`: Gee die System Service Descriptor Table (SSDT) in die geheue-dump.
- `volatility.plugins.callbacks: list_callbacks()`: Lys alle geregistreerde terugroepfunksies in die geheue-dump.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) is die mees relevante sibersekuriteit geleentheid in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en sibersekuriteitprofessionals in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

## Dienste

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik om inligting uit geheue-dumps te ontleed.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump, soos die besturingstelsel, die argitektuur en die tyd van die dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle hanteerder-objekte in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir gegewe lêername of uitbreidings.
- `cmdline`: Gee die opdraglyne van alle prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van die virtuele adresruimtes van prosesse in die geheue-dump.
- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `apihooks`: Identifiseer API-hake in die geheue-dump.

### Gevorderde Opdragte

- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `apihooks`: Identifiseer API-hake in die geheue-dump.
- `ldrmodules`: Lys alle gelaai modules in die geheue-dump.
- `modscan`: Skandeer die geheue-dump vir gegewe modulepatrone.
- `ssdt`: Gee inligting oor die System Service Descriptor Table (SSDT) in die geheue-dump.
- `driverirp`: Gee inligting oor die IRP-handlers van bestuurders in die geheue-dump.
- `devicetree`: Gee 'n boomstruktuur van die toestelboom in die geheue-dump.
- `privs`: Lys alle toegangsregte van prosesse in die geheue-dump.
- `envars`: Gee die omgewingsveranderlikes van prosesse in die geheue-dump.
- `cmdscan`: Skandeer die geheue-dump vir gegewe opdraglyne.
- `consoles`: Lys alle konsolvensters in die geheue-dump.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Die basis-klas vir Windows-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Die basis-klas vir Mac-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Die basis-klas vir Linux-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Die basis-klas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Die basis-klas vir iOS-opdragte.
- `volatility.plugins.common.AbstractBSDCommand`: Die basis-klas vir BSD-opdragte.
- `volatility.plugins.common.AbstractNetCommand`: Die basis-klas vir netwerk-opdragte.

### Gevorderde Funksies

- `volatility.plugins.windows.registry.hivelist.HiveList`: Lys alle gelaai hive-lêers in die geheue-dump.
- `volatility.plugins.windows.registry.printkey.PrintKey`: Druk die inhoud van 'n Windows-registersleutel.
- `volatility.plugins.windows.registry.printval.PrintVal`: Druk die waarde van 'n Windows-registersleutel.
- `volatility.plugins.windows.registry.hivedump.HiveDump`: Stoor die inhoud van 'n hive-lêer in 'n lêer.
- `volatility.plugins.windows.registry.hiveexport.HiveExport`: Voer die inhoud van 'n hive-lêer uit na 'n REG-lêer.
- `volatility.plugins.windows.registry.hivefind.HiveFind`: Vind alle hive-lêers wat 'n gegewe waarde bevat.
- `volatility.plugins.windows.registry.hiveinteract.HiveInteract`: Interageer met 'n hive-lêer deur sleutels en waardes te skep, wysig en verwyder.
- `volatility.plugins.windows.registry.hiveparse.HiveParse`: Analiseer die inhoud van 'n hive-lêer en gee 'n gestruktureerde uitset.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Dokumentasie](https://volatility.readthedocs.io/en/latest/)
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
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To filter the output based on a specific process name, use the `--name` option followed by the process name.

```
python vol.py -f <memory_dump> pslist --name <process_name>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network connections, such as local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To filter the output based on a specific IP address or port, use the `--ip` or `--port` option followed by the IP address or port number.

```
python vol.py -f <memory_dump> netscan --ip <ip_address>
python vol.py -f <memory_dump> netscan --port <port_number>
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles, file names, and file paths.

```
python vol.py -f <memory_dump> filescan
```

To extract a specific file from the memory dump, use the `dumpfiles` plugin followed by the file path.

```
python vol.py -f <memory_dump> dumpfiles --dump-dir <output_directory> --name <file_path>
```

## Conclusion

This cheatsheet provides a basic overview of Volatility and its usage for memory analysis. It covers some of the most commonly used plugins and their options. For more advanced analysis techniques and plugins, refer to the official Volatility documentation and community resources.
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
{% endtab %}
{% endtabs %}

## Registerhuis

### Druk beskikbare registerhuise af

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Identifiseer die profiel van die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Vertoon 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's vir 'n spesifieke proses in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer vir lêers in die geheue-dump.
- `cmdline`: Vertoon die bevellyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

### Geheue-analise Opdragte

- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.

### Geheue-analise Funksies

- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `vadwalk`: Loop deur alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

## Volatility Profiele

- `WinXPSP2x86`: Windows XP SP2 x86
- `WinXPSP3x86`: Windows XP SP3 x86
- `Win7SP0x86`: Windows 7 SP0 x86
- `Win7SP1x86`: Windows 7 SP1 x86
- `Win7SP0x64`: Windows 7 SP0 x64
- `Win7SP1x64`: Windows 7 SP1 x64
- `Win2003SP0x86`: Windows 2003 SP0 x86
- `Win2003SP1x86`: Windows 2003 SP1 x86
- `Win2003SP2x86`: Windows 2003 SP2 x86
- `Win2003SP0x64`: Windows 2003 SP0 x64
- `Win2003SP1x64`: Windows 2003 SP1 x64
- `Win2003SP2x64`: Windows 2003 SP2 x64
- `Win2008SP1x86`: Windows 2008 SP1 x86
- `Win2008SP1x64`: Windows 2008 SP1 x64
- `Win2008SP2x86`: Windows 2008 SP2 x86
- `Win2008SP2x64`: Windows 2008 SP2 x64
- `WinVistaSP0x86`: Windows Vista SP0 x86
- `WinVistaSP1x86`: Windows Vista SP1 x86
- `WinVistaSP2x86`: Windows Vista SP2 x86
- `WinVistaSP0x64`: Windows Vista SP0 x64
- `WinVistaSP1x64`: Windows Vista SP1 x64
- `WinVistaSP2x64`: Windows Vista SP2 x64
- `Win2012R2x64`: Windows 2012 R2 x64
- `Win8SP0x86`: Windows 8 SP0 x86
- `Win8SP0x64`: Windows 8 SP0 x64
- `Win81U1x86`: Windows 8.1 U1 x86
- `Win81U1x64`: Windows 8.1 U1 x64
- `Win10x86`: Windows 10 x86
- `Win10x64`: Windows 10 x64

## Volatility Installasie

Volg hierdie stappe om Volatility Framework op Linux te installeer:

1. Installeer die vereiste afhanklikhede:

```bash
sudo apt-get install python2.7 python-pip
sudo pip install distorm3
```

2. Kloon die Volatility Framework-repo:

```bash
git clone https://github.com/volatilityfoundation/volatility.git
```

3. Navigeer na die Volatility Framework-repo:

```bash
cd volatility
```

4. Voer die installasieskrip uit:

```bash
sudo python setup.py install
```

## Volatility Gebruik

Om Volatility Framework te gebruik, voer die volgende opdrag in:

```bash
volatility -f <geheue-dump> <opdrag>
```

Vervang `<geheue-dump>` met die pad na die geheue-dumplêer en `<opdrag>` met die spesifieke opdrag wat jy wil uitvoer.

## Bronne

- [Volatility Framework GitHub-repo](https://github.com/volatilityfoundation/volatility)
- [Volatility Framework Dokumentasie](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Framework Profiele](https://github.com/volatilityfoundation/profiles)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Kry 'n waarde

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik om inligting uit geheue-dumps te ontleed.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump, soos die besturingstelsel, die argitektuur en die tyd van die dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle hanteerder-objekte in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir gegewe lêername of uitbreidings.
- `cmdline`: Gee die opdraglyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor die virtuele adresruimte van 'n spesifieke proses in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van die virtuele adresruimte van 'n spesifieke proses in die geheue-dump.

### Gevorderde Opdragte

- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `apihooks`: Identifiseer API-hake in die geheue-dump.
- `ldrmodules`: Lys alle gelaai modules in die geheue-dump.
- `modscan`: Skandeer die geheue-dump vir gegewe modulepatrone.
- `ssdt`: Gee inligting oor die System Service Descriptor Table (SSDT) in die geheue-dump.
- `driverscan`: Skandeer die geheue-dump vir gegewe bestuurderpatrone.
- `mutantscan`: Skandeer die geheue-dump vir gegewe mutantpatrone.
- `yarascan`: Voer 'n YARA-handtekening-skandering uit op die geheue-dump.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Die basiese klas vir Windows-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Die basiese klas vir Linux-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Die basiese klas vir Mac-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Die basiese klas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Die basiese klas vir iOS-opdragte.

### Gevorderde Funksies

- `volatility.plugins.malware.malfind.Malfind`: Identifiseer moontlike kwaadwillige prosesse.
- `volatility.plugins.malware.apihooks.ApiHooks`: Identifiseer API-hake.
- `volatility.plugins.malware.ldrmodules.LdrModules`: Lys alle gelaai modules.
- `volatility.plugins.malware.modscan.ModScan`: Skandeer vir gegewe modulepatrone.
- `volatility.plugins.malware.ssdt.SSDT`: Gee inligting oor die SSDT.
- `volatility.plugins.malware.driverscan.DriverScan`: Skandeer vir gegewe bestuurderpatrone.
- `volatility.plugins.malware.mutantscan.MutantScan`: Skandeer vir gegewe mutantpatrone.
- `volatility.plugins.malware.yarascan.YaraScan`: Voer 'n YARA-handtekening-skandering uit.

## Volatility Instellings

- `--profile=PROFILE`: Spesifiseer die profiel van die geheue-dump.
- `--location=LOCATION`: Spesifiseer die pad na die geheue-dump.
- `--output=OUTPUT`: Spesifiseer die uitvoerformaat (bv. csv, json, sqlite).
- `--output-file=OUTPUT_FILE`: Spesifiseer die uitvoerlêer.
- `--plugins=PLUGINS`: Spesifiseer die plugins wat gebruik moet word.
- `--help`: Gee hulpinligting oor die opdrag.

## Volatility Voorbeelde

- `vol.py -f memory.dmp imageinfo`: Gee inligting oor die geheue-dump.
- `vol.py -f memory.dmp pslist`: Lys alle aktiewe prosesse.
- `vol.py -f memory.dmp vadinfo -p PID`: Gee inligting oor die virtuele adresruimte van 'n spesifieke proses.
- `vol.py -f memory.dmp malfind`: Identifiseer moontlike kwaadwillige prosesse.
- `vol.py -f memory.dmp yarascan -Y YARA_RULES`: Voer 'n YARA-handtekening-skandering uit.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
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
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik om inligting uit geheue-dumps te ontleed.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump, soos die besturingstelsel, die argitektuur en die tydskrif.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir gegewe lêername of uitbreidings.
- `cmdline`: Gee die opdraglyne van alle prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van die virtuele adresruimtes van prosesse in die geheue-dump.
- `malfind`: Identifiseer moontlike kwaadwillige prosesse in die geheue-dump.
- `apihooks`: Identifiseer API-hake in die geheue-dump.

### Gevorderde Opdragte

- `memdump`: Skep 'n geheue-dump van 'n spesifieke proses in die geheue-dump.
- `moddump`: Skep 'n geheue-dump van 'n spesifieke gelaai DLL in die geheue-dump.
- `vaddump`: Skep 'n geheue-dump van 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadwalk`: Gee 'n gedetailleerde lys van die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor die virtuele adresruimtes van prosesse in die geheue-dump.
- `vadwalk`: Gee 'n gedetailleerde lys van die virtuele adresruimtes van prosesse in die geheue-dump.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Die basisklas vir Windows-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Die basisklas vir Mac-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Die basisklas vir Linux-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Die basisklas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Die basisklas vir iOS-opdragte.
- `volatility.plugins.common.AbstractBSDCommand`: Die basisklas vir BSD-opdragte.

### Gevorderde Funksies

- `volatility.plugins.windows.registry.hivelist.HiveList`: Lys alle gelaai hive-lêers in die geheue-dump.
- `volatility.plugins.windows.registry.printkey.PrintKey`: Druk die inhoud van 'n spesifieke sleutel in die Windows-registreerder.
- `volatility.plugins.windows.registry.hivedump.HiveDump`: Skep 'n geheue-dump van 'n spesifieke hive-lêer in die geheue-dump.
- `volatility.plugins.windows.registry.hiveexport.HiveExport`: Voer die inhoud van 'n spesifieke hive-lêer uit na 'n REG-lêer.
- `volatility.plugins.windows.registry.hivefind.HiveFind`: Soek na spesifieke sleutels in die Windows-registreerder.
- `volatility.plugins.windows.registry.hiveprint.HivePrint`: Druk die inhoud van 'n spesifieke hive-lêer in die Windows-registreerder.
- `volatility.plugins.windows.registry.hivescan.HiveScan`: Skandeer die geheue-dump vir hive-lêers.
- `volatility.plugins.windows.registry.hivesize.HiveSize`: Gee die grootte van 'n spesifieke hive-lêer in die geheue-dump.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Dokumentasie](https://volatility.readthedocs.io/en/latest/)
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Skandeer/dump

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To filter the output based on a specific process name, use the `--name` option followed by the process name.

```
python vol.py -f <memory_dump> pslist --name <process_name>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network sockets, such as local and remote IP addresses, port numbers, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To filter the output based on a specific IP address or port number, use the `--ip` or `--port` option followed by the IP address or port number.

```
python vol.py -f <memory_dump> netscan --ip <ip_address>
python vol.py -f <memory_dump> netscan --port <port_number>
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles, file names, and file paths.

```
python vol.py -f <memory_dump> filescan
```

To extract a specific file from the memory dump, use the `dumpfiles` plugin followed by the file path.

```
python vol.py -f <memory_dump> dumpfiles --dump-dir <output_directory> --name <file_path>
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a starting point for using Volatility and performing common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of memory forensics.
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### Meesterlêertabel

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Identifiseer die profiel van die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Vertoon 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's vir 'n spesifieke proses in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer vir lêers in die geheue-dump.
- `cmdline`: Vertoon die bevellyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

### Geheue-analise Opdragte

- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.

### Geheue-analise Funksies

- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.

## Volatility Profiele

Hierdie is 'n lys van algemene profiele wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

- `WinXPSP2x86`: Windows XP SP2 x86
- `WinXPSP3x86`: Windows XP SP3 x86
- `Win7SP0x86`: Windows 7 SP0 x86
- `Win7SP1x86`: Windows 7 SP1 x86
- `Win2003SP0x86`: Windows 2003 SP0 x86
- `Win2003SP1x86`: Windows 2003 SP1 x86
- `Win2003SP2x86`: Windows 2003 SP2 x86
- `Win2003R2SP0x86`: Windows 2003 R2 SP0 x86
- `Win2003R2SP1x86`: Windows 2003 R2 SP1 x86
- `Win2003R2SP2x86`: Windows 2003 R2 SP2 x86
- `Win2008SP1x86`: Windows 2008 SP1 x86
- `Win2008SP2x86`: Windows 2008 SP2 x86
- `Win2008R2SP0x86`: Windows 2008 R2 SP0 x86
- `Win2008R2SP1x86`: Windows 2008 R2 SP1 x86
- `Win2012SP0x86`: Windows 2012 SP0 x86
- `Win2012SP1x86`: Windows 2012 SP1 x86
- `Win2012R2SP0x86`: Windows 2012 R2 SP0 x86
- `Win2012R2SP1x86`: Windows 2012 R2 SP1 x86
- `Win2016SP0x86`: Windows 2016 SP0 x86
- `Win2016SP1x86`: Windows 2016 SP1 x86
- `Win2019SP0x86`: Windows 2019 SP0 x86
- `Win2019SP1x86`: Windows 2019 SP1 x86

## Bronne

- [Volatility Framework](https://www.volatilityfoundation.org/)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

Die **NTFS-lêersisteem** maak gebruik van 'n kritieke komponent wat bekend staan as die _meesterlêertabel_ (MFT). Hierdie tabel bevat ten minste een inskrywing vir elke lêer op 'n volume, wat ook die MFT self dek. Belangrike besonderhede oor elke lêer, soos **grootte, tydstempels, toestemmings en werklike data**, word gekapsuleer binne die MFT-inskrywings of in areas buite die MFT maar waarna verwys word deur hierdie inskrywings. Meer besonderhede kan gevind word in die [ampertlike dokumentasie](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### SSL-sleutels/sertifikate
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump se beeld.
- `kdbgscan`: Skandeer die geheue-dump vir die opsporing van die KDBG-handvatsel.
- `kpcrscan`: Skandeer die geheue-dump vir die opsporing van die KPCR-handvatsel.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle handvatsels in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir die opsporing van lêers en hul metadata.
- `cmdline`: Gee die opdraglyne van alle prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor alle virtuele adresruimtes in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte.
- `memdump`: Dump die inhoud van 'n spesifieke proses se geheue.
- `moddump`: Dump die inhoud van 'n spesifieke DLL se geheue.

### Gevorderde Opdragte

- `malfind`: Skandeer die geheue-dump vir die opsporing van kwaadwillige prosesse.
- `ldrmodules`: Lys alle gelaai modules in die geheue-dump.
- `apihooks`: Lys alle API-hake in die geheue-dump.
- `ssdt`: Gee inligting oor die System Service Descriptor Table (SSDT).
- `gdt`: Gee inligting oor die Global Descriptor Table (GDT).
- `idt`: Gee inligting oor die Interrupt Descriptor Table (IDT).
- `callbacks`: Lys alle geregistreerde terugroepfunksies in die geheue-dump.
- `driverscan`: Skandeer die geheue-dump vir die opsporing van bestuurders.
- `devicetree`: Gee 'n boomstruktuur van alle toestelle in die geheue-dump.
- `privs`: Lys alle gebruikersprivileges in die geheue-dump.
- `getsids`: Lys alle sekuriteitsidentifikasies (SIDs) in die geheue-dump.
- `getsidsbyname`: Lys alle SIDs wat verband hou met 'n spesifieke gebruikersnaam.
- `envars`: Lys alle omgewingsveranderlikes in die geheue-dump.
- `hivelist`: Lys alle gelaai Windows-registerhives in die geheue-dump.
- `hivedump`: Dump die inhoud van 'n spesifieke Windows-registerhive.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Abstrakte klas vir Windows-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Abstrakte klas vir Linux-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Abstrakte klas vir Mac-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Abstrakte klas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Abstrakte klas vir iOS-opdragte.
- `volatility.plugins.common.AbstractBSDCommand`: Abstrakte klas vir BSD-opdragte.
- `volatility.plugins.common.AbstractNetCommand`: Abstrakte klas vir netwerk-opdragte.

### Gevorderde Funksies

- `volatility.plugins.malware.malfind.Malfind`: Klas vir die malfind-opdrag.
- `volatility.plugins.malware.malfind.MalfindOffset`: Klas vir die malfind-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindPid`: Klas vir die malfind-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVad`: Klas vir die malfind-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadOffset`: Klas vir die malfind-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadPid`: Klas vir die malfind-VAD-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVad`: Klas vir die malfind-VAD-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadOffset`: Klas vir die malfind-VAD-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadPid`: Klas vir die malfind-VAD-VAD-PID-opdrag.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
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
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, system compromises, and data breaches.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To analyze a specific process, use the `psscan` plugin. This plugin scans the memory dump for process structures and displays information about each process, including its name, process ID, and parent process ID.

```
python vol.py -f <memory_dump> psscan --pid=<process_id>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about active network connections, including the local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To analyze network sockets, use the `sockets` plugin. This plugin lists all open network sockets and their details, such as the local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> sockets
```

## File Analysis

To analyze file handles in a memory dump, use the `handles` plugin. This plugin lists all open file handles and their details, such as the file name, file path, and process ID.

```
python vol.py -f <memory_dump> handles
```

To analyze file system artifacts, use the `mftparser` plugin. This plugin parses the Master File Table (MFT) and displays information about files, directories, and other file system objects.

```
python vol.py -f <memory_dump> mftparser
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a quick reference guide for using Volatility to perform common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of the memory dump and the incident you are investigating.

For more information about Volatility and its capabilities, refer to the official documentation and community resources.
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

Gebruik hierdie skripsie om al die yara malware reëls vanaf GitHub af te laai en saam te voeg: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Skep die _**reëls**_ gids en voer dit uit. Dit sal 'n lêer genaamd _**malware\_rules.yar**_ skep wat al die yara reëls vir malware bevat.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump se beeld.
- `kdbgscan`: Skandeer die geheue-dump vir die opsporing van die KDBG-handvatsel.
- `kpcrscan`: Skandeer die geheue-dump vir die opsporing van die KPCR-handvatsel.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle handvatsels in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir die opsporing van lêers en hul metadata.
- `cmdline`: Gee die opdraglyne van alle prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor alle virtuele adresruimtes in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte.
- `memdump`: Dump die inhoud van 'n spesifieke proses se geheue.
- `moddump`: Dump die inhoud van 'n spesifieke DLL se geheue.

### Gevorderde Opdragte

- `malfind`: Skandeer die geheue-dump vir die opsporing van kwaadwillige prosesse.
- `ldrmodules`: Lys alle gelaai modules in die geheue-dump.
- `apihooks`: Lys alle API-hake in die geheue-dump.
- `ssdt`: Gee inligting oor die System Service Descriptor Table (SSDT).
- `gdt`: Gee inligting oor die Global Descriptor Table (GDT).
- `idt`: Gee inligting oor die Interrupt Descriptor Table (IDT).
- `callbacks`: Lys alle geregistreerde terugroepfunksies in die geheue-dump.
- `driverscan`: Skandeer die geheue-dump vir die opsporing van bestuurders.
- `devicetree`: Gee 'n boomstruktuur van alle toestelle in die geheue-dump.
- `privs`: Lys alle gebruikersprivileges in die geheue-dump.
- `getsids`: Lys alle sekuriteitsidentifikasies (SIDs) in die geheue-dump.
- `getsidsbyname`: Lys alle SIDs wat verband hou met 'n spesifieke gebruikersnaam.
- `envars`: Lys alle omgewingsveranderlikes in die geheue-dump.
- `hivelist`: Lys alle gelaai Windows-registerhives in die geheue-dump.
- `hivedump`: Dump die inhoud van 'n spesifieke Windows-registerhive.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Abstrakte klas vir Windows-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Abstrakte klas vir Linux-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Abstrakte klas vir Mac-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Abstrakte klas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Abstrakte klas vir iOS-opdragte.
- `volatility.plugins.common.AbstractBSDCommand`: Abstrakte klas vir BSD-opdragte.
- `volatility.plugins.common.AbstractNetCommand`: Abstrakte klas vir netwerk-opdragte.
- `volatility.plugins.common.AbstractRegistryCommand`: Abstrakte klas vir register-opdragte.
- `volatility.plugins.common.AbstractFileCommand`: Abstrakte klas vir lêer-opdragte.
- `volatility.plugins.common.AbstractProcessCommand`: Abstrakte klas vir proses-opdragte.
- `volatility.plugins.common.AbstractYaraCommand`: Abstrakte klas vir Yara-opdragte.

### Gevorderde Funksies

- `volatility.plugins.malware.malfind.Malfind`: Klas vir die malfind-opdrag.
- `volatility.plugins.malware.malfind.MalfindOffset`: Klas vir die malfind-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindPid`: Klas vir die malfind-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVad`: Klas vir die malfind-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadOffset`: Klas vir die malfind-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadPid`: Klas vir die malfind-VAD-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVad`: Klas vir die malfind-VAD-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadOffset`: Klas vir die malfind-VAD-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadPid`: Klas vir die malfind-VAD-VAD-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadVad`: Klas vir die malfind-VAD-VAD-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadVadOffset`: Klas vir die malfind-VAD-VAD-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadVadPid`: Klas vir die malfind-VAD-VAD-VAD-PID-opdrag.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### Eksterne invoegtoepassings

As jy eksterne invoegtoepassings wil gebruik, maak seker dat die gids wat verband hou met die invoegtoepassings die eerste parameter is wat gebruik word.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `volatility -f <dumppad> imageinfo`: Gee inligting oor die geheue-dump, soos die besturingstelsel, die argitektuur en die profiel.
- `volatility -f <dumppad> --profile=<profiel> pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> psscan`: Skandeer vir prosesse in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> pstree`: Gee 'n boomstruktuur van die prosesse in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> dlllist -p <proses-ID>`: Lys alle DLL's wat deur 'n spesifieke proses gelaai is.
- `volatility -f <dumppad> --profile=<profiel> handles -p <proses-ID>`: Lys alle handvatsels wat deur 'n spesifieke proses gebruik word.
- `volatility -f <dumppad> --profile=<profiel> cmdline -p <proses-ID>`: Gee die opdraglyn-argumente vir 'n spesifieke proses.
- `volatility -f <dumppad> --profile=<profiel> filescan`: Skandeer vir oop lêers in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> netscan`: Skandeer vir netwerkverbindings in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> connscan`: Skandeer vir netwerkverbindings in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> hivelist`: Lys alle gelaai registernood in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> hivedump -o <offset> -s <grootte> -f <uitvoernaam>`: Dump 'n spesifieke registernood na 'n lêer.

### Gevorderde Opdragte

- `volatility -f <dumppad> --profile=<profiel> malfind`: Skandeer vir verdagte kode in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> malfind -D <uitvoernaam>`: Dump die verdagte kode na 'n lêer.
- `volatility -f <dumppad> --profile=<profiel> vadinfo -p <proses-ID>`: Gee inligting oor die virtuele adresruimte van 'n spesifieke proses.
- `volatility -f <dumppad> --profile=<profiel> vadtree -p <proses-ID>`: Gee 'n boomstruktuur van die virtuele adresruimte van 'n spesifieke proses.
- `volatility -f <dumppad> --profile=<profiel> vadwalk -p <proses-ID>`: Loop deur die virtuele adresruimte van 'n spesifieke proses.
- `volatility -f <dumppad> --profile=<profiel> memdump -p <proses-ID> -D <uitvoernaam>`: Dump die geheue van 'n spesifieke proses na 'n lêer.
- `volatility -f <dumppad> --profile=<profiel> memmap`: Gee 'n lys van alle geheuekaarte in die geheue-dump.
- `volatility -f <dumppad> --profile=<profiel> memmap -p <proses-ID>`: Gee 'n lys van alle geheuekaarte vir 'n spesifieke proses.
- `volatility -f <dumppad> --profile=<profiel> memdump -r <kaartadres> -D <uitvoernaam>`: Dump 'n spesifieke geheuekaart na 'n lêer.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.registry.registryapi.RegistryApi`: API vir die hantering van registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintKey`: Druk die inhoud van 'n registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintValue`: Druk die waarde van 'n registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintValues`: Druk alle waardes van 'n registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintSubkeys`: Druk alle subnood van 'n registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintKeyWithValues`: Druk die inhoud en waardes van 'n registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintKeyWithSubkeys`: Druk die inhoud en subnood van 'n registernood.
- `volatility.plugins.registry.registryprintkey.RegistryPrintKeyWithValuesAndSubkeys`: Druk die inhoud, waardes en subnood van 'n registernood.

### Gevorderde Funksies

- `volatility.plugins.registry.registryapi.RegistryApi.get_hive_by_name`: Kry 'n registernood deur sy naam.
- `volatility.plugins.registry.registryapi.RegistryApi.get_hive_by_offset`: Kry 'n registernood deur sy offset.
- `volatility.plugins.registry.registryapi.RegistryApi.get_key_by_path`: Kry 'n registernood deur sy pad.
- `volatility.plugins.registry.registryapi.RegistryApi.get_value_by_name`: Kry 'n waarde deur sy naam.
- `volatility.plugins.registry.registryapi.RegistryApi.get_value_by_offset`: Kry 'n waarde deur sy offset.
- `volatility.plugins.registry.registryapi.RegistryApi.get_subkey_by_name`: Kry 'n subnood deur sy naam.
- `volatility.plugins.registry.registryapi.RegistryApi.get_subkey_by_offset`: Kry 'n subnood deur sy offset.
- `volatility.plugins.registry.registryapi.RegistryApi.get_subkey_by_path`: Kry 'n subnood deur sy pad.
- `volatility.plugins.registry.registryapi.RegistryApi.get_subkeys`: Kry 'n lys van alle subnood van 'n registernood.
- `volatility.plugins.registry.registryapi.RegistryApi.get_values`: Kry 'n lys van alle waardes van 'n registernood.
- `volatility.plugins.registry.registryapi.RegistryApi.get_key_path`: Kry die pad van 'n registernood.
- `volatility.plugins.registry.registryapi.RegistryApi.get_key_name`: Kry die naam van 'n registernood.
- `volatility.plugins.registry.registryapi.RegistryApi.get_value_name`: Kry die naam van 'n waarde.
- `volatility.plugins.registry.registryapi.RegistryApi.get_value_data`: Kry die data van 'n waarde.
- `volatility.plugins.registry.registryapi.RegistryApi.get_value_type`: Kry die tipe van 'n waarde.
- `volatility.plugins.registry.registryapi.RegistryApi.get_value_size`: Kry die grootte van 'n waarde.

## Bronne

- [Volatility Framework](https://www.volatilityfoundation.org/)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Laai dit af van [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexe

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, system compromises, and data breaches.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To analyze a specific process, use the `psscan` plugin. This plugin scans the memory dump for process structures and displays information about each process.

```
python vol.py -f <memory_dump> psscan -p <process_id>
```

Replace `<process_id>` with the ID of the process you want to analyze.

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network connections, such as local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To analyze network sockets, use the `sockets` plugin. This plugin lists all open network sockets and their details, such as local and remote IP addresses, ports, and process IDs.

```
python vol.py -f <memory_dump> sockets
```

## File Analysis

To analyze file handles in a memory dump, use the `handles` plugin. This plugin lists all open file handles and their details, such as file name, file path, and process ID.

```
python vol.py -f <memory_dump> handles
```

To analyze file system artifacts, use the `mftparser` plugin. This plugin parses the Master File Table (MFT) and displays information about files, directories, and other file system objects.

```
python vol.py -f <memory_dump> mftparser
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a quick reference guide for using Volatility to perform common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of the memory dump and the incident you are investigating.

For more information about Volatility and its capabilities, refer to the official documentation and community resources.
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Symlinks

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Identifiseer die profiel van die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Vertoon 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's vir 'n spesifieke proses in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer vir lêers in die geheue-dump.
- `cmdline`: Vertoon die bevellyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

### Geheue-analise Opdragte

- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.

### Geheue-analise Funksies

- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `vadwalk`: Loop deur alle virtuele adresruimtes in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

## Volatility Profiele

- `WinXPSP2x86`: Windows XP SP2 x86
- `WinXPSP3x86`: Windows XP SP3 x86
- `Win7SP0x86`: Windows 7 SP0 x86
- `Win7SP1x86`: Windows 7 SP1 x86
- `Win7SP0x64`: Windows 7 SP0 x64
- `Win7SP1x64`: Windows 7 SP1 x64
- `Win2003SP0x86`: Windows 2003 SP0 x86
- `Win2003SP1x86`: Windows 2003 SP1 x86
- `Win2003SP2x86`: Windows 2003 SP2 x86
- `Win2003SP0x64`: Windows 2003 SP0 x64
- `Win2003SP1x64`: Windows 2003 SP1 x64
- `Win2003SP2x64`: Windows 2003 SP2 x64
- `Win2008SP1x86`: Windows 2008 SP1 x86
- `Win2008SP1x64`: Windows 2008 SP1 x64
- `Win2008SP2x86`: Windows 2008 SP2 x86
- `Win2008SP2x64`: Windows 2008 SP2 x64
- `WinVistaSP0x86`: Windows Vista SP0 x86
- `WinVistaSP1x86`: Windows Vista SP1 x86
- `WinVistaSP2x86`: Windows Vista SP2 x86
- `WinVistaSP0x64`: Windows Vista SP0 x64
- `WinVistaSP1x64`: Windows Vista SP1 x64
- `WinVistaSP2x64`: Windows Vista SP2 x64
- `Win2012R2x64`: Windows 2012 R2 x64
- `Win8SP0x86`: Windows 8 SP0 x86
- `Win8SP0x64`: Windows 8 SP0 x64
- `Win81SP0x86`: Windows 8.1 SP0 x86
- `Win81SP0x64`: Windows 8.1 SP0 x64
- `Win10x86`: Windows 10 x86
- `Win10x64`: Windows 10 x64

## Volatility Installasie

Volg hierdie stappe om Volatility Framework op Linux te installeer:

1. Installeer die vereiste afhanklikhede:

```bash
sudo apt-get install python2.7 python-pip
sudo pip install distorm3
```

2. Kloon die Volatility Framework-repo:

```bash
git clone https://github.com/volatilityfoundation/volatility.git
```

3. Navigeer na die Volatility Framework-directory:

```bash
cd volatility
```

4. Voer die installasieskrip uit:

```bash
sudo python setup.py install
```

## Volatility Gebruik

Om Volatility Framework te gebruik, voer die volgende opdrag in:

```bash
volatility [opdrag] -f [geheue-dump] --profile=[profiel]
```

- `[opdrag]`: Die spesifieke opdrag wat uitgevoer moet word.
- `[geheue-dump]`: Die pad na die geheue-dumplêer.
- `[profiel]`: Die profiel van die geheue-dump.

Byvoorbeeld, om die `imageinfo`-opdrag uit te voer op 'n geheue-dump met die profiel `Win7SP1x64`, gebruik die volgende opdrag:

```bash
volatility imageinfo -f memory.dmp --profile=Win7SP1x64
```

## Bronne

- [Volatility Framework GitHub-repo](https://github.com/volatilityfoundation/volatility)
- [Volatility Framework Dokumentasie](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Framework Profiele](https://github.com/volatilityfoundation/profiles)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Dit is moontlik om **vanaf die geheue die bash-geskiedenis te lees.** Jy kan ook die _.bash\_history_ lêer aflaai, maar as dit gedeaktiveer is, sal jy bly wees dat jy hierdie volatiliteitsmodule kan gebruik.
```
./vol.py -f file.dmp linux.bash.Bash
```
# Volatility Cheatsheet

## Introduction

Volatility is a powerful open-source memory forensics framework that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of incidents, such as malware infections, data breaches, and system compromises.

This cheatsheet provides a quick reference guide for using Volatility to perform memory analysis tasks. It includes commands and options for common memory analysis techniques, such as process analysis, network analysis, and file analysis.

## Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive to a directory of your choice.
5. Navigate to the extracted directory and run Volatility using the command `python vol.py`.

## Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin>` with the name of the Volatility plugin you want to use. You can specify additional options to customize the analysis.

## Process Analysis

To analyze processes in a memory dump, use the `pslist` plugin. This plugin lists all running processes and their details, such as process ID, parent process ID, and command line arguments.

```
python vol.py -f <memory_dump> pslist
```

To filter the output based on a specific process name, use the `--name` option followed by the process name.

```
python vol.py -f <memory_dump> pslist --name <process_name>
```

## Network Analysis

To analyze network connections in a memory dump, use the `netscan` plugin. This plugin displays information about open network sockets, such as local and remote IP addresses, port numbers, and process IDs.

```
python vol.py -f <memory_dump> netscan
```

To filter the output based on a specific IP address or port number, use the `--ip` or `--port` option followed by the IP address or port number.

```
python vol.py -f <memory_dump> netscan --ip <ip_address>
python vol.py -f <memory_dump> netscan --port <port_number>
```

## File Analysis

To analyze files in a memory dump, use the `filescan` plugin. This plugin scans the memory dump for file artifacts, such as file handles, file names, and file paths.

```
python vol.py -f <memory_dump> filescan
```

To extract a specific file from the memory dump, use the `dumpfiles` plugin followed by the file path.

```
python vol.py -f <memory_dump> dumpfiles --dump-dir <output_directory> --name <file_path>
```

## Conclusion

Volatility is a versatile tool for memory analysis that can help you uncover valuable information from memory dumps. This cheatsheet provides a starting point for using Volatility and performing common memory analysis tasks. Experiment with different plugins and options to gain a deeper understanding of memory forensics.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Tydlyn

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
# Volatility Cheat Sheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility, 'n kragtige raamwerk vir geheue-dump-analise. Hierdie spiekbrief is bedoel as 'n verwysing vir forensiese ondersoekers en beveiligingsanaliste wat Volatility gebruik.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Gee inligting oor die geheue-dump se beeld.
- `kdbgscan`: Skandeer die geheue-dump vir die opsporing van die KDBG-handvatsel.
- `kpcrscan`: Skandeer die geheue-dump vir die opsporing van die KPCR-handvatsel.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Gee 'n boomstruktuur van alle prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's in die geheue-dump.
- `handles`: Lys alle handvatsels in die geheue-dump.
- `filescan`: Skandeer die geheue-dump vir die opsporing van lêers en hul metadata.
- `cmdline`: Gee die opdraglyne van alle prosesse in die geheue-dump.
- `vadinfo`: Gee inligting oor alle virtuele adresruimtes in die geheue-dump.
- `vadtree`: Gee 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte.
- `memdump`: Dump die inhoud van 'n spesifieke proses se geheue.

### Gevorderde Opdragte

- `malfind`: Skandeer die geheue-dump vir verdagte kode en prosesse.
- `ldrmodules`: Lys alle gelaai modules in die geheue-dump.
- `modscan`: Skandeer die geheue-dump vir die opsporing van verdagte modules.
- `ssdt`: Gee inligting oor die System Service Descriptor Table (SSDT).
- `gdt`: Gee inligting oor die Global Descriptor Table (GDT).
- `idt`: Gee inligting oor die Interrupt Descriptor Table (IDT).
- `driverscan`: Skandeer die geheue-dump vir die opsporing van verdagte bestuurders.
- `privs`: Gee inligting oor die privilegies van alle prosesse in die geheue-dump.
- `getsids`: Gee inligting oor die sekuriteitsidentifikasies van alle prosesse in die geheue-dump.
- `hivelist`: Lys alle gelaai hive's in die geheue-dump.
- `hivedump`: Dump die inhoud van 'n spesifieke hive.

## Volatility Funksies

### Basiese Funksies

- `volatility.plugins.common.AbstractWindowsCommand`: Die basiese klas vir Windows-opdragte.
- `volatility.plugins.common.AbstractLinuxCommand`: Die basiese klas vir Linux-opdragte.
- `volatility.plugins.common.AbstractMacCommand`: Die basiese klas vir Mac-opdragte.
- `volatility.plugins.common.AbstractAndroidCommand`: Die basiese klas vir Android-opdragte.
- `volatility.plugins.common.AbstractIOSCommand`: Die basiese klas vir iOS-opdragte.
- `volatility.plugins.common.AbstractBSDCommand`: Die basiese klas vir BSD-opdragte.

### Gevorderde Funksies

- `volatility.plugins.malware.malfind.Malfind`: Die klas vir die malfind-opdrag.
- `volatility.plugins.malware.malfind.MalfindOffset`: Die klas vir die malfind-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindPid`: Die klas vir die malfind-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVad`: Die klas vir die malfind-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadOffset`: Die klas vir die malfind-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadPid`: Die klas vir die malfind-VAD-PID-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVad`: Die klas vir die malfind-VAD-VAD-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadOffset`: Die klas vir die malfind-VAD-VAD-offset-opdrag.
- `volatility.plugins.malware.malfind.MalfindVadVadPid`: Die klas vir die malfind-VAD-VAD-PID-opdrag.

## Bronne

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Bestuurders

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
# Volatility Cheatsheet

Hierdie spiekbrief bevat 'n lys van algemene opdragte en funksies wat gebruik kan word met Volatility Framework vir geheue-dump-analise.

## Volatility Opdragte

### Basiese Opdragte

- `imageinfo`: Identifiseer die profiel van die geheue-dump.
- `pslist`: Lys alle aktiewe prosesse in die geheue-dump.
- `pstree`: Vertoon 'n boomstruktuur van alle aktiewe prosesse in die geheue-dump.
- `psscan`: Skandeer vir prosesse in die geheue-dump.
- `dlllist`: Lys alle gelaai DLL's vir 'n spesifieke proses in die geheue-dump.
- `handles`: Lys alle hanteerderobjekte in die geheue-dump.
- `filescan`: Skandeer vir lêers in die geheue-dump.
- `cmdline`: Vertoon die bevellyn-argumente vir 'n spesifieke proses in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

### Geheue-analise Opdragte

- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.
- `malfind`: Identifiseer verdagte kode in die geheue-dump.

### Geheue-analise Funksies

- `volshell`: Voer 'n interaktiewe skulpry uit binne die geheue-dump.
- `vadwalk`: Loop deur alle virtuele adresruimtes in die geheue-dump.
- `vaddump`: Dump die inhoud van 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.
- `vadinfo`: Gee inligting oor 'n spesifieke virtuele adresruimte in die geheue-dump.
- `vadtree`: Vertoon 'n boomstruktuur van alle virtuele adresruimtes in die geheue-dump.

## Volatility Profiele

- `WinXPSP2x86`: Windows XP SP2 x86
- `WinXPSP3x86`: Windows XP SP3 x86
- `Win7SP0x86`: Windows 7 SP0 x86
- `Win7SP1x86`: Windows 7 SP1 x86
- `Win7SP0x64`: Windows 7 SP0 x64
- `Win7SP1x64`: Windows 7 SP1 x64
- `Win2003SP0x86`: Windows 2003 SP0 x86
- `Win2003SP1x86`: Windows 2003 SP1 x86
- `Win2003SP2x86`: Windows 2003 SP2 x86
- `Win2003SP0x64`: Windows 2003 SP0 x64
- `Win2003SP1x64`: Windows 2003 SP1 x64
- `Win2003SP2x64`: Windows 2003 SP2 x64
- `Win2008SP1x86`: Windows 2008 SP1 x86
- `Win2008SP1x64`: Windows 2008 SP1 x64
- `Win2008SP2x86`: Windows 2008 SP2 x86
- `Win2008SP2x64`: Windows 2008 SP2 x64
- `WinVistaSP0x86`: Windows Vista SP0 x86
- `WinVistaSP1x86`: Windows Vista SP1 x86
- `WinVistaSP2x86`: Windows Vista SP2 x86
- `WinVistaSP0x64`: Windows Vista SP0 x64
- `WinVistaSP1x64`: Windows Vista SP1 x64
- `WinVistaSP2x64`: Windows Vista SP2 x64
- `Win2012R2x64`: Windows 2012 R2 x64
- `Win8SP0x86`: Windows 8 SP0 x86
- `Win8SP0x64`: Windows 8 SP0 x64
- `Win81U1x86`: Windows 8.1 U1 x86
- `Win81U1x64`: Windows 8.1 U1 x64
- `Win10x86`: Windows 10 x86
- `Win10x64`: Windows 10 x64

## Volatility Installasie

Volg hierdie stappe om Volatility Framework op Linux te installeer:

1. Installeer die vereiste afhanklikhede:

```bash
sudo apt-get install python2.7 python-pip
sudo pip install distorm3
```

2. Kloon die Volatility Framework-repo:

```bash
git clone https://github.com/volatilityfoundation/volatility.git
```

3. Navigeer na die Volatility Framework-repo:

```bash
cd volatility
```

4. Voer die installasieskrip uit:

```bash
sudo python setup.py install
```

## Volatility Gebruik

Om Volatility Framework te gebruik, voer die volgende opdrag in:

```bash
volatility [opdrag] -f [geheue-dump] --profile=[profiel]
```

- `[opdrag]`: Die spesifieke opdrag wat uitgevoer moet word.
- `[geheue-dump]`: Die pad na die geheue-dumplêer.
- `[profiel]`: Die profiel van die geheue-dump.

Byvoorbeeld, om die `imageinfo`-opdrag uit te voer op 'n geheue-dump met die profiel `Win7SP1x64`, gebruik die volgende opdrag:

```bash
volatility imageinfo -f memory.dmp --profile=Win7SP1x64
```

## Bronne

- [Volatility Framework GitHub-repo](https://github.com/volatilityfoundation/volatility)
- [Volatility Framework Dokumentasie](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Framework Profiele](https://github.com/volatilityfoundation/profiles)
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
volatility -f <memory_dump> --profile=<profile> iehistory
```

Hierdie bevel sal die Internet Explorer (IE) geskiedenis uit 'n geheue-dump analiseer. Vervang `<memory_dump>` met die pad na die geheue-dump lêer en `<profile>` met die korrekte profielnaam vir die geheue-dump.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Kry notepad teks

```bash
$ volatility -f memory_dump.mem notepad
```

Hierdie bevel gebruik die Volatility-raamwerk om die inhoud van die Notepad-toepassing in 'n geheue-dump te ontleed. Die `-f` vlag dui die geheue-dump-lêer aan wat ontleed moet word, en die `notepad` argument spesifiseer die tipe data wat ontleed moet word.

### Kry notepad teks

```bash
$ volatility -f memory_dump.mem notepad
```

Hierdie bevel gebruik die Volatility-raamwerk om die inhoud van die Notepad-toepassing in 'n geheue-dump te ontleed. Die `-f` vlag dui die geheue-dump-lêer aan wat ontleed moet word, en die `notepad` argument spesifiseer die tipe data wat ontleed moet word.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Skermkiekie
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Meesteropstartrekord (MBR)

Die Meesteropstartrekord (MBR) is 'n kritieke deel van 'n stoormedium, soos 'n harde skyf of 'n USB-stokkie, wat gebruik word om die opstartproses van 'n rekenaar te inisieer. Dit bevat die eerste program wat uitgevoer word wanneer die rekenaar opstart, bekend as die opstartlader. Die MBR bevat ook 'n klein stukkie kode wat die stoormedium se partisie-inligting bevat.

Die MBR kan 'n belangrike bron van inligting wees vir forensiese analise, aangesien dit inligting kan verskaf oor die stoormedium se opstelling, soos die aantal partisies, die grootte van elke partisie en die tipe stoormedium wat gebruik word. Dit kan ook aanduidings gee van enige ongewenste veranderinge of kwaadwillige aktiwiteite wat op die stoormedium plaasgevind het.

Forensiese analiste kan gereedskap soos Volatility gebruik om die MBR van 'n geheue-dump te ontleed en relevante inligting te onttrek vir verdere ondersoek.
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Die **Master Boot Record (MBR)** speel 'n belangrike rol in die bestuur van die logiese partisies van 'n stoormedium, wat gestruktureer is met verskillende [lêersisteme](https://af.wikipedia.org/wiki/L%C3%AAersisteem). Dit hou nie net inligting oor die partisie-opset nie, maar bevat ook uitvoerbare kode wat as 'n opstartlaaier optree. Hierdie opstartlaaier begin óf direk die tweede-fase laaiproses van die bedryfstelsel (sien [tweede-fase opstartlaaier](https://af.wikipedia.org/wiki/Tweede-fase_opstartlaaier)) óf werk saam met die [volume-opstartrekord](https://af.wikipedia.org/wiki/Volume-opstartrekord) (VBR) van elke partisie. Vir diepgaande kennis, verwys na die [MBR Wikipedia-bladsy](https://af.wikipedia.org/wiki/Master_boot_record).

## Verwysings
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is die mees relevante kuberveiligheidsevenement in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n kookpunt vir tegnologie- en kuberveiligheidspesialiste in elke dissipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
