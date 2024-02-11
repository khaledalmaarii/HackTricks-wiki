# Volatility - CheatSheet

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

Ikiwa unataka kitu **haraka na cha kushangaza** ambacho kitazindua programu-jalizi kadhaa za Volatility kwa wakati mmoja, unaweza kutumia: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Usanidi

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
#### Njia1

```bash
volatility2 -f memory_dump.vmem imageinfo
```

Hii itatoa habari muhimu kuhusu kumbukumbu ya picha, kama vile mfumo wa uendeshaji, toleo la kernel, na usanidi wa kumbukumbu.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 pslist
```

Hii itaorodhesha michakato yote iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 pstree
```

Hii itaonyesha muundo wa mti wa michakato iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 cmdline
```

Hii itaonyesha amri zilizotumiwa na michakato iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 filescan
```

Hii itaorodhesha faili zote zilizokuwa zimefunguliwa wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 netscan
```

Hii itaonyesha maelezo ya mtandao, kama vile anwani za IP na bandari, kwa michakato iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hivelist
```

Hii itaorodhesha mizizi yote ya usajili iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hivedump -o <offset> -s <size> -k <key>
```

Hii itachambua faili ya usajili iliyochukuliwa kutoka kwa kumbukumbu ya picha na kuonyesha maudhui yake.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 printkey -o <offset> -K <key>
```

Hii itachambua faili ya usajili iliyochukuliwa kutoka kwa kumbukumbu ya picha na kuonyesha maudhui ya funguo maalum.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 dumpregistry -o <offset> -s <size> -k <key> -D <output_directory>
```

Hii itachambua faili ya usajili iliyochukuliwa kutoka kwa kumbukumbu ya picha na kuokoa maudhui yake kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 malfind -D <output_directory>
```

Hii itatafuta mafaili yote ya kutekelezwa katika kumbukumbu ya picha na kuziokoa kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 dlllist -p <pid>
```

Hii itaorodhesha maktaba zote zilizounganishwa na michakato maalum iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 procdump -p <pid> -D <output_directory>
```

Hii itachukua kumbukumbu ya mchakato maalum kutoka kwa kumbukumbu ya picha na kuokoa kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 memdump -p <pid> -D <output_directory>
```

Hii itachukua kumbukumbu ya kumbukumbu ya mchakato maalum kutoka kwa kumbukumbu ya picha na kuokoa kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 memmap
```

Hii itaonyesha ramani ya kumbukumbu ya mfumo iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 memstrings -s <string> -n <length>
```

Hii itatafuta herufi zilizopatikana katika kumbukumbu ya picha na kuziokoa kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hashdump
```

Hii itachambua nywila zilizohifadhiwa katika kumbukumbu ya picha na kuziokoa kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hibinfo
```

Hii itatoa habari kuhusu faili ya hibernation iliyochukuliwa kutoka kwa kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hibdump -o <offset> -s <size> -D <output_directory>
```

Hii itachambua faili ya hibernation iliyochukuliwa kutoka kwa kumbukumbu ya picha na kuokoa maudhui yake kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hibprefs
```

Hii itatoa mipangilio ya faili ya hibernation iliyochukuliwa kutoka kwa kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hiblist
```

Hii itaorodhesha mizizi yote ya usajili iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hibdump -o <offset> -s <size> -D <output_directory>
```

Hii itachambua faili ya hibernation iliyochukuliwa kutoka kwa kumbukumbu ya picha na kuokoa maudhui yake kwenye saraka iliyotolewa.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hibprefs
```

Hii itatoa mipangilio ya faili ya hibernation iliyochukuliwa kutoka kwa kumbukumbu ya picha.

```bash
volatility2 -f memory_dump.vmem --profile=Win7SP1x64 hiblist
```

Hii itaorodhesha mizizi yote ya usajili iliyokuwa ikifanya kazi wakati wa kuchukua kumbukumbu ya picha.
```

{% endtab %}
{% endtabs %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% tab title="Njia 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Amri za Volatility

Pata hati rasmi katika [Marejeleo ya Amri za Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Taarifa kuhusu programu-jalizi za "list" dhidi ya "scan"

Volatility ina njia mbili kuu za programu-jalizi, ambazo mara nyingi zinaonekana katika majina yao. Programu-jalizi za "list" zitajaribu kupitia muundo wa Windows Kernel ili kupata habari kama michakato (kutambua na kutembea kwenye orodha iliyounganishwa ya muundo wa `_EPROCESS` kwenye kumbukumbu), vitambulisho vya mfumo wa uendeshaji (kutambua na kuorodhesha meza ya vitambulisho, kufuta viungo vyovyote vilivyopatikana, nk). Kimsingi, zinafanya kazi kama API ya Windows ingefanya ikiombwa, kwa mfano, kuorodhesha michakato.

Hii inafanya programu-jalizi za "list" kuwa haraka, lakini vile vile hatarini kama API ya Windows kwa udanganyifu na programu hasidi. Kwa mfano, ikiwa programu hasidi inatumia DKOM kuondoa kiungo cha michakato kutoka kwenye orodha iliyounganishwa ya `_EPROCESS`, haitaonekana kwenye Meneja wa Kazi na wala haitaonekana kwenye pslist.

Programu-jalizi za "scan", kwa upande mwingine, zitachukua njia kama ile ya kukata kumbukumbu kwa vitu ambavyo vinaweza kuwa na maana wakati vinapotajwa kama muundo maalum. Kwa mfano, `psscan` itasoma kumbukumbu na kujaribu kuunda vitu vya `_EPROCESS` kutoka kwake (inatumia utafutaji wa alama za dimbwi, ambayo ni kutafuta herufi za 4-baiti ambazo zinaonyesha uwepo wa muundo unaovutia). Faida ni kwamba inaweza kuchimba michakato ambayo imefungwa, na hata ikiwa programu hasidi inabadilisha orodha iliyounganishwa ya `_EPROCESS`, programu-jalizi bado itapata muundo uliopo kwenye kumbukumbu (kwani bado inahitaji kuwepo kwa mchakato kuendesha). Kikwazo ni kwamba programu-jalizi za "scan" ni kidogo polepole kuliko programu-jalizi za "list", na mara nyingine inaweza kutoa matokeo sahihi ya uwongo (mchakato ambao ulifungwa muda mrefu uliopita na sehemu za muundo wake zimefutwa na shughuli zingine).

Kutoka: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profaili za Mfumo wa Uendeshaji

### Volatility3

Kama ilivyoelezwa kwenye faili ya kusoma, unahitaji kuweka **meza ya alama ya mfumo wa uendeshaji** unayotaka kuunga mkono ndani ya _volatility3/volatility/symbols_.\
Pakiti za meza ya alama kwa mifumo ya uendeshaji mbalimbali zinapatikana kwa **kupakuliwa** kwenye:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profaili ya Nje

Unaweza kupata orodha ya profaili zinazoungwa mkono kwa kufanya:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Ikiwa unataka kutumia **wasifu mpya uliopakuliwa** (kwa mfano wa linux), unahitaji kuunda muundo wa folda ifuatayo: _plugins/overlays/linux_ na kuweka ndani ya folda hii faili ya zip inayohifadhi wasifu. Kisha, pata idadi ya wasifu kwa kutumia:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Unaweza **kupakua maelezo ya Linux na Mac** kutoka [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Katika kipande kilichopita unaweza kuona kuwa maelezo yanaitwa `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, na unaweza kuitumia kutekeleza kitu kama:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Pata Maelezo ya Profaili

```bash
volatility -f <memory_dump> imageinfo
```

Hii amri inatumika kuchunguza maelezo ya msingi ya faili ya kumbukumbu. Inatoa habari kama vile mfumo wa uendeshaji, toleo la kernel, na usanidi wa kumbukumbu.

#### Extracting Processes and DLLs

```bash
volatility -f <memory_dump> --profile=<profile> pslist
```

Hii amri inatumika kuchanganua mchakato na DLL zinazohusiana na faili ya kumbukumbu. Inatoa orodha ya michakato iliyopo na habari kama vile kitambulisho cha mchakato, jina la mchakato, na jina la faili ya kutekelezwa.

#### Analyzing Network Connections

```bash
volatility -f <memory_dump> --profile=<profile> connscan
```

Hii amri inatumika kuchunguza uhusiano wa mtandao uliopo katika faili ya kumbukumbu. Inatoa habari kama vile anwani za IP za chanzo na marudio, namba za bandari, na hali ya uhusiano.

#### Examining Registry Keys

```bash
volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>
```

Hii amri inatumika kuchunguza na kuchanganua funguo za usajili katika faili ya kumbukumbu. Inatoa habari kama vile jina la funguo, njia ya funguo, na thamani zilizohifadhiwa.

#### Recovering Deleted Files

```bash
volatility -f <memory_dump> --profile=<profile> hivelist
volatility -f <memory_dump> --profile=<profile> dumpregistry -H <hive_offset> -o <output_directory>
```

Hii amri inatumika kupata faili zilizofutwa katika faili ya kumbukumbu. Inachunguza faili za usajili zilizofutwa na kuziokoa kwenye saraka iliyotolewa.

#### Analyzing Open Files

```bash
volatility -f <memory_dump> --profile=<profile> handles
```

Hii amri inatumika kuchunguza faili zilizofunguliwa katika faili ya kumbukumbu. Inatoa habari kama vile kitambulisho cha faili, njia ya faili, na mchakato unaofungua faili hiyo.

#### Extracting Memory Artifacts

```bash
volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>
```

Hii amri inatumika kuchanganua na kuchukua kumbukumbu ya mchakato maalum katika faili ya kumbukumbu. Inahifadhi kumbukumbu ya mchakato katika saraka iliyotolewa.

#### Analyzing Malware Behavior

```bash
volatility -f <memory_dump> --profile=<profile> malfind
```

Hii amri inatumika kuchunguza tabia ya programu hasidi katika faili ya kumbukumbu. Inatoa habari kama vile anwani za kumbukumbu zinazohusiana na programu hasidi na habari ya kumbukumbu inayohusiana.
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Tofauti kati ya imageinfo na kdbgscan**

[Kutoka hapa](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Tofauti na imageinfo ambayo tu hutoa mapendekezo ya profile, **kdbgscan** imeundwa kwa ajili ya kutambua kwa uhakika profile sahihi na anwani sahihi ya KDBG (ikiwa kuna zaidi ya moja). Programu-jalizi hii inatafuta saini za KDBGHeader zinazohusiana na profile za Volatility na hufanya ukaguzi wa akili ili kupunguza matokeo sahihi ya uwongo. Uzito wa matokeo na idadi ya ukaguzi wa akili unaweza kufanywa inategemea ikiwa Volatility inaweza kupata DTB, kwa hivyo ikiwa tayari unajua profile sahihi (au ikiwa una mapendekezo ya profile kutoka imageinfo), basi hakikisha unaitumia kutoka.

Daima angalia **idadi ya michakato ambayo kdbgscan imeipata**. Mara nyingine imageinfo na kdbgscan wanaweza kupata **zaidi ya moja** profile inayofaa **lakini moja sahihi itakuwa na michakato inayohusiana** (Hii ni kwa sababu ya kuchambua michakato anwani sahihi ya KDBG inahitajika)
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

**KDBG**, inayojulikana kama **kernel debugger block** na Volatility, ni muhimu kwa kazi za uchunguzi zinazofanywa na Volatility na debuggers mbalimbali. Inatambulika kama `KdDebuggerDataBlock` na ina aina ya `_KDDEBUGGER_DATA64`, ina virejeleo muhimu kama `PsActiveProcessHead`. Virejeleo hivi maalum vinawezesha kuorodhesha mchakato wote, ambayo ni muhimu kwa uchambuzi kamili wa kumbukumbu.

## Taarifa za OS
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Kifaa cha ziada `banners.Banners` kinaweza kutumika katika **vol3 kujaribu kupata bango za linux** katika kumbukumbu.

## Hashes/Passwords

Chambua hash za SAM, [vyeti vilivyohifadhiwa vya kikoa](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) na [siri za lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `cmdscan`: Scans for command-line history.
- `consoles`: Lists all open console handles.
- `privs`: Lists all privileges for each process.

### Plugin Usage

Volatility also provides a wide range of plugins for specific analysis tasks. To use a plugin, simply run `python vol.py <plugin_name>`. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Extracts timeline information from memory dumps.
- `dumpfiles`: Extracts files from memory dumps.
- `hashdump`: Dumps password hashes from memory.
- `svcscan`: Lists Windows services.
- `printkey`: Prints registry keys.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into the system's state at the time of the dump.
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Kumbukumbu ya Kumbukumbu

Kumbukumbu ya kumbukumbu ya mchakato ita **chukua kila kitu** cha hali ya sasa ya mchakato. Moduli ya **procdump** itachukua tu **msimbo**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

## Mchakato

### Orodha ya mchakato

Jaribu kupata mchakato **tahadhari** (kwa jina) au mchakato wa mtoto **usiotarajiwa** (kwa mfano cmd.exe kama mtoto wa iexplorer.exe).\
Inaweza kuwa ya kuvutia kulinganisha matokeo ya pslist na psscan ili kutambua michakato iliyofichwa.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.
- `cmdline`: Displays the command line arguments of a process.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs) of a process.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules and their dependencies.
- `svcscan`: Lists all Windows services.
- `privs`: Lists the privileges of a process.
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `driverirp`: Lists all IRP handlers for loaded drivers.
- `modscan`: Scans for modules in memory.
- `mutantscan`: Lists all mutant objects.
- `atomscan`: Lists all atom tables.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of events based on process and file activity.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hashdump`: Dumps password hashes from memory.
- `shellbags`: Lists recently accessed folders.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Dump proc

{% tabs %}
{% tab title="vol3" %}
### Dump proc

Kupata maelezo ya mchakato kutoka kwa kumbukumbu ya kufurika, tumia amri ifuatayo:

```bash
volatility -f <dump_file> --profile=<profile> procdump -p <pid> -D <output_directory>
```

Mfano:

```bash
volatility -f memdump.mem --profile=Win7SP1x64 procdump -p 1234 -D ./output
```

Hii itachambua kumbukumbu ya kufurika na kutoa maelezo ya mchakato na faili za kufurika kwa mchakato ulio na PID uliyopewa. Faili za kufurika zitahifadhiwa kwenye saraka ya pato iliyopewa.

Kwa mfano, amri ifuatayo itachambua kumbukumbu ya kufurika na kutoa maelezo ya mchakato na faili za kufurika kwa mchakato ulio na PID 1234. Faili za kufurika zitahifadhiwa kwenye saraka ya pato iliyopewa `./output`.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 procdump -p 1234 -D ./output
```
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `cmdscan`: Scans for command-line history.
- `consoles`: Lists all open console handles.
- `privs`: Lists all privileges for each process.

### Plugin Usage

Volatility also provides a wide range of plugins for specific analysis tasks. To use a plugin, simply run `python vol.py <plugin_name>`. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Extracts timeline information from memory dumps.
- `dumpfiles`: Extracts files from memory dumps.
- `hashdump`: Dumps password hashes from memory.
- `svcscan`: Lists Windows services.
- `printkey`: Prints registry keys.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into the system's state at the time of the dump.
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Amri ya mstari wa amri

Je, kuna kitu chochote kisicho cha kawaida kilichotekelezwa?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Amri zilizotekelezwa katika `cmd.exe` zinasimamiwa na **`conhost.exe`** (au `csrss.exe` kwenye mifumo kabla ya Windows 7). Hii inamaanisha kwamba ikiwa **`cmd.exe`** inakomeshwa na mshambuliaji kabla ya kuchukua kumbukumbu ya kumbukumbu, bado inawezekana kupata historia ya amri ya kikao kutoka kwa kumbukumbu ya **`conhost.exe`**. Ili kufanya hivyo, ikiwa shughuli isiyo ya kawaida inagunduliwa ndani ya moduli za konsoli, kumbukumbu ya mchakato wa **`conhost.exe`** inapaswa kuchukuliwa. Kisha, kwa kutafuta **strings** ndani ya kumbukumbu hii, mistari ya amri iliyotumiwa katika kikao inaweza kuchimbwa.

### Mazingira

Pata mazingira ya env ya kila mchakato unaoendelea. Inaweza kuwa na thamani za kuvutia.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules and their dependencies.
- `vadinfo`: Displays information about the Virtual Address Descriptor (VAD) tree.
- `vadtree`: Displays a tree view of the VAD tree.
- `vaddump`: Dumps the memory range associated with a VAD node.
- `memdump`: Dumps the entire physical memory.
- `memmap`: Displays the memory map.
- `memstrings`: Extracts printable strings from memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of events based on process and file activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `hivelist`: Lists the registry hives.
- `hashdump`: Dumps password hashes from memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### Haki za Tokeni

Angalia tokeni za haki katika huduma zisizotarajiwa.\
Inaweza kuwa ya kuvutia kuorodhesha michakato inayotumia tokeni za haki.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdscan`: Scans for command history in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for injected or malicious code.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `dumpfiles`: Extracts files from memory.
- `memdump`: Dumps a specific process's memory.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for injected or malicious code.
- `timeliner`: Creates a timeline of events based on process and file activity.
- `psxview`: Displays hidden processes.
- `svcscan`: Lists Windows services.
- `hivelist`: Lists registry hives.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Angalia kila SSID inayomilikiwa na mchakato.\
Inaweza kuwa ya kuvutia kuorodhesha michakato inayotumia SSID ya mamlaka (na michakato inayotumia SSID ya huduma fulani).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules and their dependencies.
- `vadinfo`: Displays information about the Virtual Address Descriptor (VAD) tree.
- `vadtree`: Displays a tree view of the VAD tree.
- `vaddump`: Dumps the memory range associated with a VAD node.
- `memdump`: Dumps the entire physical memory.
- `memmap`: Displays the memory map.
- `memstrings`: Extracts printable strings from memory.
- `memscan`: Scans for a specific pattern in memory.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Extracts timeline information from memory.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.

To use a plugin, simply run `python vol.py -f <memory_dump> --profile=<profile> <plugin_name>`. Replace `<memory_dump>` with the path to the memory dump file, `<profile>` with the appropriate profile for the operating system, and `<plugin_name>` with the name of the plugin.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. With Volatility, analysts can extract valuable information from memory dumps and uncover important evidence in forensic investigations.
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Vitambulisho

Inatumika kujua kwa faili, funguo, nyuzi, michakato... ambayo **mchakato una vitambulisho** kwa (imefunguliwa)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules and their corresponding memory addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `vaddump`: Dumps the memory contents of a specific VAD.
- `memdump`: Dumps the memory contents of a specific process.

### Plugin Usage

Volatility also provides a wide range of plugins for specific analysis tasks. To use a plugin, simply run `python vol.py <plugin_name>`. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Extracts timeline information from memory dumps.
- `dumpfiles`: Extracts files from memory dumps.
- `cmdscan`: Scans for command history in memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into the activities of a compromised system.
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
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. By leveraging Volatility's capabilities, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Strings per processes

Volatility inaruhusu sisi kuangalia ni mchakato gani kamba inamiliki.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. By leveraging Volatility's capabilities, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Pia inaruhusu kutafuta herufi ndani ya mchakato kwa kutumia moduli ya yarascan:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.

To use a plugin, simply run `python vol.py -f <memory_dump> --profile=<profile> <plugin_name>`. Replace `<memory_dump>` with the path to the memory dump file, `<profile>` with the appropriate profile for the operating system, and `<plugin_name>` with the name of the plugin.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. By leveraging Volatility's capabilities, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** inahifadhi rekodi ya programu unazotumia kwa kutumia kipengele katika rejista kinachoitwa **UserAssist keys**. Vipengele hivi vinarekodi mara ngapi kila programu inatekelezwa na wakati ilipotekelezwa mara ya mwisho.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila fani.

{% embed url="https://www.rootedcon.com/" %}

## Huduma

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdscan`: Scans for command history in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for injected or malicious code.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `dumpfiles`: Extracts files from memory.
- `memdump`: Dumps a specific process's memory.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for injected or malicious code.
- `timeliner`: Creates a timeline of events based on process and file activity.
- `psxview`: Displays hidden processes.
- `svcscan`: Lists Windows services.
- `hivelist`: Lists registry hives.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Mtandao

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. By leveraging Volatility's capabilities, analysts can extract valuable information from memory dumps and gain insights into system activity.
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

## Hifadhidata ya Usajili

### Chapisha hifadhidata zilizopo

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Pata thamani

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `hivelist`: Lists the registry hives.
- `hashdump`: Dumps the password hashes.
- `shellbags`: Lists the recently accessed folders.
- `cmdscan`: Scans for command history in memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
### Kumbukumbu

A memory dump is a snapshot of the computer's RAM at a specific point in time. It contains valuable information that can be analyzed to understand the state of the system and identify any malicious activity.

Kumbukumbu ya kumbukumbu ni picha ya RAM ya kompyuta katika wakati fulani. Ina taarifa muhimu ambazo zinaweza kuchunguzwa ili kuelewa hali ya mfumo na kutambua shughuli yoyote ya uovu.

### Volatility

Volatility is a popular open-source framework for memory forensics. It provides a wide range of plugins and commands to analyze memory dumps and extract useful information.

Volatility ni mfumo maarufu wa chanzo wazi kwa uchunguzi wa kumbukumbu. Inatoa aina mbalimbali za programu-jalizi na amri za kuchambua kumbukumbu na kutoa taarifa muhimu.

### Basic Forensic Methodology

1. Acquire the memory dump: Obtain a copy of the memory dump from the target system. This can be done using various tools and techniques, such as using a hardware write blocker or creating a memory dump from a live system.

1. Pata kumbukumbu ya kumbukumbu: Pata nakala ya kumbukumbu ya kumbukumbu kutoka kwenye mfumo wa lengo. Hii inaweza kufanywa kwa kutumia zana na mbinu mbalimbali, kama vile kutumia kizuizi cha kuandika vifaa au kuunda kumbukumbu ya kumbukumbu kutoka kwenye mfumo hai.

2. Analyze the memory dump: Use Volatility and its plugins to analyze the memory dump. This includes identifying running processes, open network connections, loaded modules, and other relevant information.

2. Chambua kumbukumbu ya kumbukumbu: Tumia Volatility na programu-jalizi zake kuchambua kumbukumbu ya kumbukumbu. Hii ni pamoja na kutambua michakato inayofanya kazi, uhusiano wa mtandao uliofunguliwa, moduli zilizopakia, na taarifa nyingine muhimu.

3. Extract useful information: Extract any relevant information from the memory dump, such as passwords, encryption keys, or evidence of malicious activity. This can be done using Volatility's plugins or by manually searching through the memory dump.

3. Chota taarifa muhimu: Chota taarifa yoyote muhimu kutoka kwenye kumbukumbu ya kumbukumbu, kama vile nywila, funguo za encryption, au ushahidi wa shughuli mbaya. Hii inaweza kufanywa kwa kutumia programu-jalizi za Volatility au kwa kutafuta kwa mkono kupitia kumbukumbu ya kumbukumbu.

4. Document findings: Document all findings and observations during the analysis process. This includes recording the steps taken, the tools used, and any relevant information discovered.

4. Andika matokeo: Andika matokeo yote na uchunguzi wakati wa mchakato wa uchambuzi. Hii ni pamoja na kurekodi hatua zilizochukuliwa, zana zilizotumiwa, na taarifa yoyote muhimu iliyogunduliwa.

5. Report and present findings: Prepare a detailed report summarizing the findings and present them to the relevant stakeholders. This report should include any recommendations for further investigation or remediation.

5. Andika ripoti na toa matokeo: Andaa ripoti ya kina inayohitimisha matokeo na uwasilishe kwa wadau husika. Ripoti hii inapaswa kujumuisha mapendekezo yoyote kwa uchunguzi zaidi au urekebishaji.

By following this basic forensic methodology and using tools like Volatility, you can effectively analyze memory dumps and uncover valuable information for forensic investigations.
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Mfumo wa faili

### Kusakinisha

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Kuchunguza/kudump

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Mfumo wa Faili Mkuu

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**Mfumo wa faili wa NTFS** hutumia sehemu muhimu inayojulikana kama _master file table_ (MFT). Jedwali hili linajumuisha angalau kuingia kwa kila faili kwenye kiasi, likijumuisha MFT yenyewe pia. Maelezo muhimu kuhusu kila faili, kama vile **ukubwa, alama za wakati, ruhusa, na data halisi**, zimefungwa ndani ya kuingia za MFT au katika maeneo nje ya MFT lakini yanayotajwa na kuingia hizi. Maelezo zaidi yanaweza kupatikana katika [hati rasmi](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Vyeti/Maneno ya SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `hivelist`: Lists the registry hives.
- `hashdump`: Dumps the password hashes.
- `shellbags`: Lists the recently accessed folders.
- `cmdscan`: Scans for command history in memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Programu hasidi

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
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.
- `cmdscan`: Scans for command history in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for injected or malicious code.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `vaddump`: Dumps the memory contents of a specific VAD.
- `memdump`: Dumps the memory contents of a specific process.
- `dumpfiles`: Dumps files from memory.
- `dumpregistry`: Dumps the Windows registry from memory.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for injected or malicious code.
- `timeliner`: Extracts timeline information from memory.
- `apihooks`: Lists all API hooks.
- `cmdscan`: Scans for command history in memory.
- `dumpcerts`: Dumps certificates from memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. With Volatility, analysts can extract valuable information from memory dumps to aid in investigations and incident response.
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

### Uchunguzi kwa kutumia yara

Tumia skripti hii kupakua na kuunganisha sheria zote za yara za zisizo kutoka kwenye github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Tengeneza saraka ya _**kanuni**_ na itekeleze. Hii itaunda faili iliyoitwa _**malware\_rules.yar**_ ambayo ina sheria zote za yara kwa ajili ya zisizo.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### Vifaa vya nje

Ikiwa unataka kutumia vifaa vya nje hakikisha kuwa folda zinazohusiana na vifaa hivyo ni parameter ya kwanza iliyotumiwa.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. By leveraging Volatility's capabilities, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Pakua kutoka [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `hivelist`: Lists the registry hives.
- `hashdump`: Dumps the password hashes.
- `shellbags`: Lists the recently accessed folders.
- `cmdscan`: Scans for command history in memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Viungo ishara

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `cmdline`: Displays the command line arguments of a process.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vaddump`: Dumps the memory of a specific VAD.
- `vadtree`: Displays a tree view of the VADs.
- `memmap`: Displays the memory map of the system.
- `memdump`: Dumps the entire physical memory.
- `strings`: Searches for ASCII and Unicode strings in memory.

### Plugins

Volatility supports a wide range of plugins that extend its functionality. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Creates a timeline of system activity.
- `dumpregistry`: Dumps the Windows registry.
- `dumpcerts`: Dumps certificates from memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists the registry hives.
- `hivedump`: Dumps a specific registry hive.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. By leveraging Volatility's capabilities, analysts can extract valuable information from memory dumps and gain insights into system activity.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Inawezekana **kusoma historia ya bash kutoka kwenye kumbukumbu.** Unaweza pia kudump faili ya _.bash\_history_, lakini ikiwa imelemazwa utafurahi kuwa unaweza kutumia moduli hii ya volatility.
```
./vol.py -f file.dmp linux.bash.Bash
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7.x or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for common malware injection techniques.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `cmdscan`: Scans for command-line history.
- `consoles`: Lists all open console handles.
- `privs`: Lists all privileges for each process.

### Plugin Usage

Volatility also provides a wide range of plugins for specific analysis tasks. To use a plugin, simply run `python vol.py <plugin_name>`. Some popular plugins include:

- `malfind`: Scans for common malware injection techniques.
- `timeliner`: Extracts timeline information from memory dumps.
- `dumpfiles`: Extracts files from memory dumps.
- `hashdump`: Dumps password hashes from memory.
- `svcscan`: Lists all Windows services.
- `printkey`: Prints the contents of a registry key.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. By using the commands and plugins provided in this cheatsheet, analysts can extract valuable information from memory dumps and uncover evidence of malicious activity.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Muda

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### Madereva

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
## Volatility Cheatsheet

### Introduction

This cheatsheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

Here are some basic commands to get started with Volatility:

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes.
- `pstree`: Displays a tree view of the running processes.
- `netscan`: Lists all network connections.
- `modules`: Lists all loaded modules.
- `dlllist`: Lists all loaded DLLs.
- `handles`: Lists all open handles.
- `filescan`: Scans for file objects in memory.
- `cmdscan`: Scans for command history in memory.

### Advanced Commands

Here are some advanced commands for more in-depth analysis:

- `malfind`: Scans for injected or malicious code.
- `apihooks`: Lists all API hooks.
- `ldrmodules`: Lists all loaded modules with their base addresses.
- `vadinfo`: Displays information about the Virtual Address Descriptors (VADs).
- `vadtree`: Displays a tree view of the VADs.
- `vaddump`: Dumps the memory contents of a specific VAD.
- `memdump`: Dumps the memory contents of a specific process.
- `dumpfiles`: Dumps files from memory.
- `dumpregistry`: Dumps the registry from memory.

### Plugins

Volatility also supports plugins, which provide additional functionality. Some popular plugins include:

- `malfind`: Scans for injected or malicious code.
- `timeliner`: Creates a timeline of events based on process and file activity.
- `psxview`: Lists hidden processes.
- `apihooks`: Lists all API hooks.
- `yarascan`: Scans for files matching a YARA rule.
- `dumpcerts`: Dumps certificates from memory.

### Conclusion

Volatility is a powerful tool for memory forensics analysis. This cheatsheet provides a quick reference guide for using Volatility and its various commands and plugins. With Volatility, analysts can extract valuable information from memory dumps to aid in investigations and incident response.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Pata ubao wa kunakili
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Pata historia ya IE

To get the Internet Explorer (IE) history, you can use the following command:

Kutafuta historia ya Internet Explorer (IE), unaweza kutumia amri ifuatayo:

```bash
volatility -f <memory_dump> iehistory
```

Replace `<memory_dump>` with the path to your memory dump file.

Badilisha `<memory_dump>` na njia ya faili yako ya kumbukumbu ya kufa.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Pata maandishi ya notepad

To get the text from a notepad file, you can use the following command:

```bash
$ volatility -f <memory_dump_file> notepad
```

This command will search for any open notepad instances in the memory dump file and extract the text from them. The output will include the process ID, process name, and the text content of each notepad instance found.

To filter the output and only display the text content, you can use the `--output=text` option:

```bash
$ volatility -f <memory_dump_file> notepad --output=text
```

This will display only the text content of each notepad instance found in the memory dump file.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Picha ya Skrini
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Rekodi ya Mwalimu wa Kuanza (MBR)

Rekodi ya Mwalimu wa Kuanza (MBR) ni sehemu muhimu ya kwanza ya diski ngumu. Ina habari muhimu kuhusu muundo wa diski na ina jukumu muhimu katika mchakato wa kuanza mfumo wa uendeshaji. MBR ina sehemu tatu kuu:

1. **Bootstrap Code**: Kanuni hii inasaidia kuanza mfumo wa uendeshaji kwa kusoma sehemu ya kwanza ya mfumo wa faili.

2. **Disk Signature**: Hii ni nambari ya pekee inayotambulisha diski.

3. **Partition Table**: Jedwali hili lina habari kuhusu sehemu zilizogawanywa kwenye diski, kama vile ukubwa, aina ya faili, na anwani ya kuanza.

Kuchambua MBR inaweza kusaidia katika uchunguzi wa kina wa diski ngumu na kugundua shughuli za kutiliwa shaka au vitisho vya usalama.
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** inacheza jukumu muhimu katika kusimamia sehemu za mantiki za kumbukumbu ya uhifadhi, ambazo zimepangwa na [mifumo ya faili](https://en.wikipedia.org/wiki/File_system) tofauti. Sio tu inashikilia habari ya mpangilio wa sehemu lakini pia ina kificho kinachofanya kazi kama mzigo wa kuanza. Mzigo huu wa kuanza unaanzisha moja kwa moja mchakato wa kupakia hatua ya pili ya mfumo wa uendeshaji (angalia [mzigo wa kuanza hatua ya pili](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) au inafanya kazi kwa ushirikiano na [rekodi ya mzigo wa kiasi](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) ya kila sehemu. Kwa maarifa ya kina, tazama [ukurasa wa Wikipedia wa MBR](https://en.wikipedia.org/wiki/Master_boot_record).

## Marejeo
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi katika **Ulaya**. Kwa **malengo ya kukuza maarifa ya kiufundi**, mkutano huu ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila uwanja.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
