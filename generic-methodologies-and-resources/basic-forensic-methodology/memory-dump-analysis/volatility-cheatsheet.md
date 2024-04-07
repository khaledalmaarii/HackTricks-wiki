# Volatility - CheatSheet

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti **kibernetičke bezbednosti u Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i kibernetičkih profesionalaca u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

Ako želite nešto **brzo i ludo** što će pokrenuti nekoliko Volatility dodataka paralelno, možete koristiti: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalacija

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
#### volatility2

{% tabs %}
{% tab title="Metod1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Metoda 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Komande Volatility

Pristupite zvaničnoj dokumentaciji na [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Napomena o "list" vs. "scan" dodacima

Volatility ima dva glavna pristupa dodacima, što se ponekad odražava u njihovim imenima. "list" dodaci će pokušati da navigiraju kroz strukture Windows Kernela kako bi dobili informacije poput procesa (lociraju i prođu kroz povezanu listu `_EPROCESS` struktura u memoriji), OS ručki (lociraju i navedu tabelu ručki, dereferencirajući bilo koje pronađene pokazivače, itd). Oni se više-manje ponašaju kao Windows API kada bi bio zatražen, na primer, popis procesa.

To čini "list" dodatke prilično brzim, ali jednako ranjivim kao i Windows API na manipulaciju od strane malvera. Na primer, ako malver koristi DKOM da odvoji proces od povezane liste `_EPROCESS`, neće se pojaviti u Task Manageru, niti u pslist-u.

"scan" dodaci, s druge strane, pristupiće slično kao da se urezuju memorija za stvari koje bi mogle imati smisla kada se dereferenciraju kao specifične strukture. Na primer, `psscan` će pročitati memoriju i pokušati da napravi objekte `_EPROCESS` od nje (koristi skeniranje pool-tagova, što je traženje 4-bajtnih nizova koji ukazuju na prisustvo strukture od interesa). Prednost je što može otkriti procese koji su završili, i čak ako malver manipuliše sa povezanom listom `_EPROCESS`, dodatak će i dalje pronaći strukturu ostavljenu u memoriji (jer joj i dalje treba postojati da bi proces radio). Mana je što su "scan" dodaci malo sporiji od "list" dodataka, i ponekad mogu dati lažne pozitivne rezultate (proces koji je završio pre dugo vremena i čiji su delovi strukture prepisani drugim operacijama).

Izvor: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OS Profili

### Volatility3

Kako je objašnjeno u readme datoteci, morate staviti **tabelu simbola OS-a** koji želite podržati unutar _volatility3/volatility/symbols_.\
Paketi tabela simbola za različite operativne sisteme dostupni su za **preuzimanje** na:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Spoljni Profil

Možete dobiti listu podržanih profila izvršavanjem:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Ako želite da koristite **novi profil koji ste preuzeli** (na primer, linux profil), treba da kreirate sledeću strukturu foldera: _plugins/overlays/linux_ i stavite zip fajl sa profilom unutar ovog foldera. Zatim, dobijte broj profila koristeći:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Možete **preuzeti profile za Linux i Mac** sa [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

U prethodnom odeljku možete videti da se profil zove `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, i možete ga koristiti da izvršite nešto poput:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Otkrij profil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Razlike između imageinfo i kdbgscan**

[**Ovde**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Za razliku od imageinfo koji jednostavno pruža predloge profila, **kdbgscan** je dizajniran da pozitivno identifikuje tačan profil i tačnu KDBG adresu (ako ih ima više). Ovaj dodatak skenira potpise KDBGHeader povezane sa Volatility profilima i primenjuje provere ispravnosti kako bi se smanjili lažni pozitivi. Opširnost izlaza i broj provera ispravnosti koje se mogu izvršiti zavise od toga da li Volatility može pronaći DTB, pa ako već znate tačan profil (ili ako imate predlog profila od imageinfo), onda se pobrinite da ga koristite iz .

Uvek pogledajte **broj procesa koje je kdbgscan pronašao**. Ponekad imageinfo i kdbgscan mogu pronaći **više od jednog** odgovarajućeg **profila**, ali samo **validan će imati neke procese povezane** (To je zato što je za izvlačenje procesa potrebna tačna KDBG adresa)
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

**Kernel Debugger Block**, poznat kao **KDBG** u Volatility-u, ključan je za forenzičke zadatke koje obavlja Volatility i razni debuggeri. Identifikovan kao `KdDebuggerDataBlock` i tipa `_KDDEBUGGER_DATA64`, sadrži bitne reference poput `PsActiveProcessHead`. Ova specifična referenca pokazuje na početak liste procesa, omogućavajući listanje svih procesa, što je osnovno za temeljnu analizu memorije.

## Informacije o operativnom sistemu
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Plugin `banners.Banners` može se koristiti u **vol3 za pokušaj pronalaženja linux banera** u dump-u.

## Hashes/Lozinke

Izvadite SAM heševe, [keširane kredencijale domena](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) i [lsa tajne](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets).
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %} 

## Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
  - `vollocation -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Extracting DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> pslist`
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyling User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermodehooks`

- **Analyzing SSDT Hooks**
 json
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing Hidden SSDT**
  - `vollocation -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermodehooks`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> pslist`
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Hidden Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Hidden Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Hidden Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Analyzing Hidden Files**
  - `vollocation -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Analyzing Hidden Image**
  - `volatility -f <memory_dump> imageinfo`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Analyzing Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermodehooks`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> pslist`
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Hidden Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Hidden Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Analyzing Hidden Files**
  - `vollocation -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Analyzing Hidden Image**
  - `volatility -f <memory_dump> imageinfo`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Analyzing Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing Hidden Callbacks**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden User Mode Hooks**
  - `volatility -f <memory_dump> --profile=<profile> usermodehooks`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden CSRSS**
  - `volatility -f <memory_dump> --profile=<profile> csrss`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing Hidden Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> pslist`
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Hidden Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing Hidden Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Hidden Registry**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Hidden Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Analyzing Hidden Files**
  - `vollocation -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

### Plugin Development

- **Creating a New Plugin**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name>`

- **Debugging a Plugin**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> --debug <plugin_name>`

- **Listing Available Plugins**
  - `volatility --plugins=<path_to_plugin_directory> --info`

- **Listing Available Plugin Options**
  - `volatility --plugins=<path_to_plugin_directory> --info <plugin_name>`

- **Running a Plugin with Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --<option_name> <option_value>`

- **Running a Plugin with Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to File**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> > <output_file>`

- **Running a Plugin with Output to CSV**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=csv > <output_csv_file>`

- **Running a Plugin with Output to JSON**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=json > <output_json_file>`

- **Running a Plugin with Output to SQLite Database**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite > <output_sqlite_file>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name and Additional Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --<option_name> <option_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name and Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name and Debugging**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug`

- **Running a Plugin with Output to SQLite Database with Custom Table Name, Debugging, and Additional Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug --<option_name> <option_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name, Debugging, and Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name, Debugging, and Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name, Debugging, and Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name, Debugging, and Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name, Debugging, and Multiple Options**
  - `volatility --plugins=<path_to_plugin_directory> -f <memory_dump> --profile=<profile> <plugin_name> --output=sqlite --output-file=<output_sqlite_file> --output-table=<table_name> --debug --<option1_name> <option1_value> --<option2_name> <option2_value>`

- **Running a Plugin with Output to SQLite Database with Custom Table Name,
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Memorija za odlaganje

Memorija za odlaganje procesa će **izvući sve** trenutno stanje procesa. Modul **procdump** će samo **izvući** **kôd**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti **kibernetičke bezbednosti** u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i stručnjaka za kibernetičku bezbednost u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Procesi

### Lista procesa

Pokušajte da pronađete **sumnjive** procese (po imenu) ili **neočekivane** podprocese (na primer cmd.exe kao podproces iexplorer.exe).\
Moglo bi biti interesantno **uporediti** rezultat pslist sa rezultatom psscan kako biste identifikovali skrivene procese.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}Uobičajena metodologija i resursi

### Osnovna forenzička metodologija

1. **Identifikacija problema**
   - Definišite problem i ciljeve analize.

2. **Prikupljanje informacija**
   - Prikupite informacije o sistemu, incidentu ili problemu.

3. **Analiza informacija**
   - Analizirajte informacije kako biste identifikovali sumnjive aktivnosti.

4. **Dokumentacija nalaza**
   - Detaljno dokumentujte sve pronađene dokaze i rezultate analize.

5. **Izveštavanje**
   - Pripremite izveštaj sa svim relevantnim informacijama i preporukama.

### Analiza memorijskog ispusta pomoću Volatility alata

1. **Pronalaženje profila**
   - Identifikujte odgovarajući profil memorijskog ispusta.

2. **Analiza procesa**
   - Proučite procese koji su bili aktivni u trenutku memorijskog ispusta.

3. **Analiza mrežne aktivnosti**
   - Istražite mrežnu aktivnost zabeleženu u memorijskom ispustu.

4. **Analiza registara**
   - Pregledajte registre kako biste pronašli korisne informacije.

5. **Analiza fajlova i drajvera**
   - Ispitajte fajlove i drajvere koji su bili u upotrebi.

6. **Analiza zlonamernih aktivnosti**
   - Tražite tragove zlonamernih aktivnosti u memorijskom ispustu.

7. **Rekonstrukcija događaja**
   - Pokušajte rekonstruisati niz događaja koji su doveli do memorijskog ispusta.

8. **Ekstrakcija važnih informacija**
   - Izdvojite ključne informacije koje mogu pomoći u istrazi.

9. **Validacija nalaza**
   - Proverite i potvrdite svoje nalaze kako biste osigurali tačnost analize.

10. **Generisanje izveštaja**
    - Kreirajte detaljan izveštaj sa svim relevantnim informacijama i zaključcima.
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Dumpovanje procesa

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}Kratki vodič za Volatility

### Osnovne komande

- `imageinfo` - Informacije o slikama
- `pslist` - Lista procesa
- `pstree` - Stablo procesa
- `psscan` - Skeniranje procesa
- `dlllist` - Lista učitanih DLL-ova
- `handles` - Lista otvorenih ručica
- `filescan` - Skeniranje fajlova
- `cmdline` - Komandna linija procesa
- `consoles` - Konzole procesa
- `vadinfo` - Informacije o virtuelnoj adresi
- `vadtree` - Stablo virtuelne adrese
- `vaddump` - Dump virtuelne adrese
- `malfind` - Pronalaženje sumnjivih procesa
- `ldrmodules` - Lista učitanih modula
- `modscan` - Skeniranje modula
- `apihooks` - Prikazuje API hekove
- `svcscan` - Skeniranje servisa
- `connections` - Mrežne veze
- `sockets` - Sockets
- `devicetree` - Stablo uređaja
- `driverirp` - Prikazuje IRP za drajvere
- `ssdt` - Prikazuje SSDT
- `callbacks` - Prikazuje callback funkcije
- `gdt` - Prikazuje GDT
- `idt` - Prikazuje IDT
- `modules` - Lista modula
- `mutantscan` - Skeniranje mutanata
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atom
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Komandna linija

Da li je izvršeno nešto sumnjivo?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
Komande izvršene u `cmd.exe` upravljaju se pomoću **`conhost.exe`** (ili `csrss.exe` na sistemima pre Windows 7). To znači da, ako **`cmd.exe`** bude zatvoren od strane napadača pre nego što se dobije memorijski zapis, još uvek je moguće povratiti istoriju komandi sesije iz memorije **`conhost.exe`**. Da biste to uradili, ako se detektuje neobična aktivnost unutar modula konzole, treba dumpovati memoriju povezanog procesa **`conhost.exe`**. Zatim, pretraživanjem **stringova** unutar ovog zapisa, moguće je izvući potencijalno korištene komandne linije u sesiji.

### Okruženje

Dobijte vrednosti okružnih promenljivih svakog pokrenutog procesa. Mogu postojati neke zanimljive vrednosti.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> imageinfo | grep Profile`
- **PSList:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **PSTree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **NetScan:** `vol.py -f <memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **CmdLine:** `vol.py -f <memory_dump> --profile=<profile> cmdline`
- **FileScan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **MalFind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Dump:** `vol.py -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles`
- **DLLList:** `vol.py -json -f <memory_dump> --profile=<profile> dlllist`
- **DriverList:** `vol.py -f <memory_dump> --profile=<profile> driverlist`
- **Privs:** `vol.py -f <memory_dump> --profile=<profile> privs`
- **Getsids:** `vol.py -f <memory_dump> --profile=<profile> getsids`
- **Hivelist:** `vol.py -f <memory_dump> --profile=<profile> hivelist`
- **HiveScan:** `vol.py -f <memory_dump> --profile=<profile> hivescan`
- **UserAssist:** `vol.py -f <json_output> --profile=<profile> userassist`
- **Consoles:** `vol.py -f <memory_dump> --profile=<profile> consoles`
- **Cmdscan:** `vol.py -f <memory_dump> --profile=<profile> cmdscan`
- **ConsoleHistory:** `vol.py -f <memory_dump> --profile=<profile> consolehistory`
- **Mftparser:** `vol.py -f <memory_dump> --profile=<profile> mftparser`
- **Mftparser:** `vol.py -f <memory_dump> --profile=<profile> mftparser`
- **Mbrparser:** `vol.py -f <memory_dump> --profile=<profile> mbrparser`
- **Yarascan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Yarascan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Modscan:** `vol.py -f <memory_dump> --profile=<profile> modscan`
- **Moddump:** `vol.py -f <memory_dump> --profile=<profile> moddump`
- **Apihooks:** `vol.py -f <memory_dump> --profile=<profile> apihooks`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### Token privilegije

Proverite privilegije tokena u neočekivanim servisima.\
Moglo bi biti zanimljivo nabrojati procese koji koriste neki privilegovani token.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> --profile=<profile> <command>`
- **PSList:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **PSTree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **NetScan:** `vol.py -<memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **CmdLine:** `vol.py -f <memory_dump> --profile=<profile> cmdline`
- **Consoles:** `vol.py -f <memory_dump> --profile=<profile> consoles`
- **FileScan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **MalFind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Dump:** `vol.py -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles`
- **DLLList:** `vol.py -json -f <memory_dump> --profile=<profile> dlllist`
- **DriverList:** `vol.py -f <memory_dump> --profile=<profile> driverlist`
- **SSDT:** `vol.py -f <memory_dump> --profile=<profile> ssdt`
- **YaraScan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> m
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SID-ovi

Proverite svaki SSID koji je u vlasništvu procesa.\
Moglo bi biti zanimljivo navesti procese koji koriste privilegovani SID (i procese koji koriste neki servisni SID).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}Kratki vodič za Volatility

### Osnovne komande

- `imageinfo` - Informacije o slikama
- `kdbgscan` - Skeniranje za KDBG
- `pslist` - Lista procesa
- `pstree` - Stablo procesa
- `psscan` - Skeniranje procesa
- `dlllist` - Lista učitanih DLL-ova
- `handles` - Lista otvorenih ručica
- `cmdline` - Argumenti komandne linije
- `consoles` - Konzole procesa
- `vadinfo` - Informacije o VAD-ovima
- `vadtree` - Stablo VAD-ova
- `vaddump` - Dumpovanje VAD-ova
- `malfind` - Pronalaženje sumnjivih procesa
- `ldrmodules` - Lista učitanih modula
- `modules` - Lista modula
- `moddump` - Dumpovanje modula
- `apihooks` - Pregled API hook-ova
- `callbacks` - Pregled callback-ova
- `svcscan` - Skeniranje servisa
- `driverirp` - Analiza IRP-a drajvera
- `ssdt` - Pregled SSDT-a
- `gdt` - Pregled GDT-a
- `idt` - Pregled IDT-a
- `devicetree` - Stablo uređaja
- `privs` - Pregled privilegija
- `getsids` - Prikaz SID-ova
- `getsids` - Prikaz SID-ova
- `hivelist` - Lista učitanih registarskih datoteka
- `printkey` - Prikaz ključa registra
- `hashdump` - Dumpovanje LM/NTLM hash-eva
- `userassist` - Analiza UserAssist ključeva
- `shellbags` - Analiza ShellBags-a
- `mbrparser` - Analiza Master Boot Record-a
- `mftparser` - Analiza Master File Table-a
- `filescan` - Skeniranje fajlova
- `dumpfiles` - Dumpovanje fajlova
- `dumpregistry` - Dumpovanje registra
- `yarascan` - Skeniranje YARA pravila
- `yarascan` - Skeniranje YARA pravila
- `memmap` - Mapiranje memorije
- `memdump` - Dumpovanje memorije
- `memstrings` - Pronalaženje stringova u memoriji
- `memhistory` - Prikaz istorije memorije
- `messagehooks` - Pregled hook-ova poruka
- `timeliner` - Analiza vremenske linije
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Ručke

Korisno je znati za koje druge datoteke, ključeve, niti, procese... **proces ima ručku** (otvoreno).

{% tabs %}
{% endtab %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping a File**
 json
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <address_range> -D <output_directory>`

- **Registry Analysis**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `voljsonatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset> --output-file <output_file>`

- **Analyzing Timelime**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Suspicious Processes**
  - `volatility -f <memory_dump> --profile=<profile> malsysproc`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -p <pid> -D <output_directory>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLL-ovi

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %} 

## Osnovna forenzička metodologija

### Analiza memorije

#### Volatility Cheat Sheet

### Osnovne komande

- `volatility -f <dumpfile> imageinfo` - Informacije o dump fajlu
- `volatility -f <dumpfile> pslist` - Lista aktivnih procesa
- `volatility -f <dumpfile> psscan` - Skeniranje procesa
- `volatility -f <dumpfile> pstree` - Stablo procesa
- `volatility -f <dumpfile> dlllist -p <PID>` - Lista učitanih DLL-ova za određeni proces
- `volatility -f <dumpfile> filescan` - Skeniranje fajlova
- `volatility -f <dumpfile> cmdline -p <PID>` - Komandna linija za određeni proces
- `volatility -f <dumpfile> netscan` - Skeniranje mreže
- `volatility -f <dumpfile> connections` - Lista aktivnih konekcija
- `volatility -f <dumpfile> timeliner` - Prikaz vremenske linije aktivnosti
- `volatility -f <dumpfile> malfind` - Pronalaženje sumnjivih procesa
- `volatility -f <dumpfile> userassist` - Prikaz korisničkih aktivnosti
- `volatility -f <dumpfile> hivelist` - Lista učitanih registarskih ključeva
- `volatility -f <dumpfile> printkey -o <offset>` - Prikaz registarskog ključa na određenoj adresi
- `volatility -f <dumpfile> hashdump` - Izvlačenje korisničkih lozinki

### Napredne komande

- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` - Dumpovanje memorijskog prostora procesa
- `volatility -f <dumpfile> memmap --profile=<profile>` - Mapiranje memorijskog prostora
- `volatility -f <dumpfile> linux_bash` - Prikaz Bash istorije komandi
- `volatility -f <dumpfile> linux_lsof` - Prikaz otvorenih fajlova na Linux sistemu
- `volatility -f <dumpfile> linux_psaux` - Prikaz procesa sa detaljima na Linux sistemu
- `volatility -f <dumpfile> linux_proc_maps` - Prikaz mapiranja memorijskog prostora procesa na Linux sistemu

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Stringovi po procesima

Volatility nam omogućava da proverimo kojem procesu pripada određeni string.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> imageinfo | grep Profile`
- **PSList:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **PSTree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **NetScan:** `vol.py -f <memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **CmdLine:** `vol.py -f <memory_dump> --profile=<profile> cmdline`
- **FileScan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **MalFind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **YaraScan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Dump:** `vol.py -f <memory_dump> --profile=<profile> procdump -p <pid> -D <output_directory>`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles`
- **Privs:** `vol.py -json -f <memory_dump> --profile=<profile> privs`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **APIHooks:** `vol.py -f <memory_dump> --profile=<profile> apihooks`
- **LdrModules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **DriverModules:** `vol.py -json -f <memory_dump> --profile=<profile> drivermodules`
- **SSDT:** `vol.py -f <memory_dump> --profile=<profile> ssdt`
- **GDT:** `vol.py -json -f <memory_dump> --profile=<profile> gdt`
- **UserAssist:** `vol.py -f <memory_dump> --profile=<profile> userassist`
- **Shellbags:** `vol.py -f <memory_dump> --profile=<profile> shellbags`
- **MFTParser:** `vol.py -f <memory_dump> --profile=<profile> mftparser`
- **MFT:** `vol.py -f <memory_dump> --profile=<profile> mftparser`
- **Hashdump:** `vol.py -f <memory_dump> --profile=<profile> hashdump`
- **Hivelist:** `vol.py -f <memory_dump> --profile=<profile> hivelist`
- **HiveScan:** `vol.py -f <memory_dump> --profile=<profile> hivescan`
- **PrintKey:** `vol.py -f <memory_dump> --profile=<profile> printkey -K <registry_key>`
- **DumpKey:** `vol.py -json -f <memory_dump> --profile=<profile> dumpkey -K <registry_key> -D <output_directory>`
- **CmdScan:** `vol.py -f <memory_dump> --profile=<profile> cmdscan`
- **Consoles:** `vol.py -f <memory_dump> --profile=<profile> consoles`
- **Desktops:** `vol.py -json -f <memory_dump> --profile=<profile> desktops`
- **Sockets:** `vol.py -f <memory_dump> --profile=<profile> sockets`
- **Mbrparser:** `vol.py -f <memory_dump> --profile=<profile> mbrparser`
- **Yarascan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Modscan:** `vol.py -f <memory_dump> --profile=<profile> modscan`
- **Apihooks:** `vol.py -f <memory_dump> --profile=<profile> apihooks`
- **Getsids:** `vol.py -f <memory_dump> --profile=<profile> getsids`
- **Hollowfind:** `vol.py -f <memory_dump> --profile=<profile> hollowfind`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Ldrmodules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
Takođe omogućava pretragu stringova unutar procesa korišćenjem modula yarascan:
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Volatility Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **List processes:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **Dump process:** `vol.py -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`
- **File scan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **Yara scan:** `vol.py -f <memory_dump> --profile=<profile> yarascan --yara-rules=<rules_file>`
- **Registry hives:** `vol.py -f <memory_dump> --profile=<profile> hivelist`
- **Dump registry hive:** `vol.py -f <memory_dump> --profile=<profile> printkey -o <output_directory> -K <hive_address>`
- **Network connections:** `vol.py -f <memory_dump> --profile=<profile> connections`
- **Command history:** `vol.py -f <memory_dump> --profile=<profile> cmdscan`
- **User accounts:** `vol.py -json -f <memory_dump> --profile=<profile> useraccounts`
- **Malware scan:** `vol.py -f <memory_dump> --profile=<profile> malscan`

### Advanced Volatility Commands

- **Detect rootkits:** `vol.py -f <memory_dump> --profile=<profile> rootkit`
- **Detect hidden processes:** `vol.py -f <memory_dump> --profile=<profile> psxview`
- **Detect injected code:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Detect API hooks:** `vol.py -f <memory_dump> --profile=<profile> apihooks`
- **Detect driver modules:** `vol.py -f <memory_dump> --profile=<profile> modules`
- **Detect SSDT hooks:** `vol.py -f <memory_dump> --profile=<profile> ssdt`
- **Detect callbacks:** `vol.py -f <memory_dump> --profile=<profile> callbacks`
- **Detect hidden modules:** `vol.py -f <memory_dump> --profile=<profile> ldrmodules`
- **Detect hidden services:** `vol.py -f <memory_dump> --profile=<profile> getservicesids`

### Memory Analysis Tips

- **Use Volatility plugins:** Volatility provides a wide range of plugins for specific analysis tasks.
- **Compare memory dumps:** Compare multiple memory dumps to identify changes over time.
- **Look for anomalies:** Pay attention to unusual processes, network connections, or registry entries.
- **Cross-reference findings:** Correlate findings from different plugins to get a comprehensive view of the system.

### References

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki) {% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** prati programe koje pokrećete koristeći funkciju u registru nazvanu **UserAssist ključevi**. Ovi ključevi beleže koliko puta je svaki program pokrenut i kada je poslednji put pokrenut.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}Kratki vodič za Volatility

### Osnovne komande

- `imageinfo` - Informacije o slikama
- `kdbgscan` - Skeniranje za KDBG
- `pslist` - Lista procesa
- `pstree` - Stablo procesa
- `psscan` - Skeniranje procesa
- `dlllist` - Lista učitanih DLL-ova
- `handles` - Lista otvorenih ručica
- `filescan` - Skeniranje fajlova
- `cmdline` - Komandna linija procesa
- `consoles` - Konzole procesa
- `vadinfo` - Informacije o VAD-ovima
- `vadtree` - Stablo VAD-ova
- `vaddump` - Dumpovanje VAD-ova
- `malfind` - Pronalaženje sumnjivih procesa
- `ldrmodules` - Lista učitanih modula
- `apihooks` - Detekcija API hook-ova
- `svcscan` - Skeniranje servisa
- `connections` - Lista mrežnih konekcija
- `connscan` - Skeniranje konekcija
- `sockets` - Lista soketa
- `sockscan` - Skeniranje soketa
- `modscan` - Skeniranje kernel modula
- `moddump` - Dumpovanje kernel modula
- `driverirp` - Analiza IRP-a drajvera
- `devicetree` - Stablo uređaja
- `idt` - Informacije o IDT-u
- `gdt` - Informacije o GDT-u
- `ssdt` - Informjsonacije o SSDT-u
- `callbacks` - Detekcija callback-ova
- `mutantscan` - Skeniranje mutanata
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `deskscan` - Skeniranje desktopa
- `hivelist` - Lista učitanih registry hive-ova
- `hivedump` - Dumpovanje registry hive-ova
- `printkey` - Prikazivanje registry ključa
- `privs` - Prikazivanje privilegija
- `getsids` - Prikazivanje SID-ova
- `psxview` - Prikazivanje skrivenih procesa
- `shimcache` - Analiza Shimcache-a
- `userassist` - Analiza Userassist-a
- `mbrparser` - Analiza Master Boot Record-a
- `yarascan` - Skeniranje memorije koristeći Yara pravila
- `yarascan` - Skeniranje memorije koristeći Yara pravila
- `memmap` - Mapiranje memorije
- `memdump` - Dumpovanje memorije
- `memstrings` - Pronalaženje stringova u memoriji
- `memhistory` - Istorija dumpovanja memorije
- `messagehooks` - Detekcija message hook-ova
- `timeliner` - Analiza vremenske linije
- `mftparser` - Analiza Master File Table-a
- `mftparser` - Analiza Master File Table-a
- `shellbags` - Analiza Shellbags-a
- `usnparser` - Analiza USN Journal-a
- `usnparser` - Analiza USN Journal-a
- `truecryptmaster` - Pronalaženje TrueCrypt master ključa
- `truecryptpassphrase` - Pronalaženje TrueCrypt passphrase-a
- `hashdump` - Dumpovanje korisničkih hash-ova
- `hashdump` - Dumpovanje korisničkih hash-ova
- `cachedump` - Dumpovanje keširanih kredencijala
- `cachedump` - Dumpovanje keširanih kredencijala
- `checkpst` - Provera strukture PST fajla
- `checkpst` - Provera strukture PST fajla
- `dumpcerts` - Dumpovanje sertifikata
- `dumpcerts` - Dumpovanje sertifikata
- `dumpfiles` - Dumpovanje fajlova
- `dumpfiles` - Dumpovanje fajlova
- `dumpregistry` - Dumpovanje registry-ja
- `dumpregistry` - Dumpovanje registry-ja
- `dumpsecurity` - Dumpovanje sigurnosnih informacija
- `dumpsecurity` - Dumpovanje sigurnosnih informacija
- `dumpvbr` - Dumpovanje Volume Boot Record-a
- `dumpvbr` - Dumpovanje Volume Boot Record-a
- `dumpvpb` - Dumpovanje Volume Parameter Block-a
- `dumpvpb` - Dumpovanje Volume Parameter Block-a
- `dumpcache` - Dumpovanje keša
- `dumpcache` - Dumpovanje keša
- `dumpall` - Dumpovanje svih dostupnih informacija
- `dumpall` - Dumpovanje svih dostupnih informacija
- `windows` - Analiza Windows memorije
- `linux` - Analiza Linux memorije
- `mac` - Analiza Mac memorije
- `imagecopy` - Kopiranje slike u datoteku
- `kpcrscan` - Skeniranje za KPCR
- `ss` - Analiza System Service Descriptor Table-a
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Sk
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti **kibernetičke bezbednosti** u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i stručnjaka za kibernetičku bezbednost u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Usluge

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **imageinfo**: Provides information about the profile and operating system version.
- **pslist**: Lists running processes.
- **pstree**: Displays the process list in a tree format.
- **psscan**: Scans for processes in the memory dump.
- **dlllist**: Lists DLLs loaded into each process.
- **handles**: Lists open handles in the memory dump.
- **filescan**: Scans for file objects in memory.
- **cmdline**: Displays process command line arguments.
- **netscan**: Scans for network artifacts.
- **connections**: Lists open network connections.
- **sockets**: Lists network socket information.
- **svcscan**: Scans for Windows services.
- **modscan**: Scans for kernel modules.
- **malfind**: Finds suspicious process mappings.
- **yarascan**: Scans for matches with Yara rules.
- **dumpfiles**: Extracts files from the memory dump.
- **dumpregistry**: Dumps the registry hives.
- **hashdump**: Dumps password hashes.
- **hivelist**: Lists registry hives.
- **printkey**: Prints a specific registry key.
- **timeliner**: Creates a timeline of processes and events.
- **apihooks**: Detects processes using API hooking techniques.
- **ldrmodules**: Lists loaded kernel modules.
- **devicetree**: Displays the device tree.
- **idt**: Displays the Interrupt Descriptor Table.
- **gdt**: Displays the Global Descriptor Table.
- **ssdt**: Displays the System Service Descriptor Table.
- **callbacks**: Lists kernel callbacks.
- **driverirp**: Lists drivers and IRP handlers.
- **deskscan**: Scans for windows on the desktop.
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SSIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
- **getsids**: Lists Security Identifiers (SIDs).
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Mreža

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %} 

## Osnovna metodologija analize memorije

### Volatility Cheat Sheet

#### Osnovne komande

- `volatility -f <dumpfile> imageinfo` - Informacije o dump fajlu
- `volatility -f <dumpfile> --profile=<profile> pslist` - Lista procesa
- `volatility -f <dumpfile> --profile=<profile> pstree` - Stablo procesa
- `volatility -f <dumpfile> --profile=<profile> psscan` - Skeniranje procesa
- `volatility -f <dumpfile> --profile=<profile> dlllist -p <pid>` - Lista učitanih DLL-ova za određeni proces
- `volatility -f <dumpfile> --profile=<profile> cmdline -p <pid>` - Komandna linija za određeni proces
- `volatility -f <dumpfile> --profile=<profile> filescan` - Skeniranje fajlova
- `volatility -f <dumpfile> --profile=<profile> netscan` - Skeniranje mreže
- `volatility -f <dumpfile> --profile=<profile> connections` - Lista mrežnih konekcija
- `volatility -f <dumpfile> --profile=<profile> timeliner` - Vremenska linija događaja
- `volatility -f <dumpfile> --profile=<profile> malfind` - Pronalaženje sumnjivih procesa
- `volatility -f <dumpfile> --profile=<profile> cmdline` - Komandna linija za sve procese
- `volatility -f <dumpfile> --profile=<profile> consoles` - Lista otvorenih konzola
- `volatility -f <dumpfile> --profile=<profile> hivelist` - Lista učitanih registarskih datoteka
- `volatility -f <dumpfile> --profile=<profile> printkey -o <offset>` - Prikazivanje registarskog ključa na određenoj adresi
- `volatility -f <dumpfile> --profile=<profile> userassist` - Prikazivanje UserAssist informacija
- `volatility -f <dumpfile> --profile=<profile> shimcache` - Prikazivanje Shimcache baze podataka
- `volatility -f <dumpfile> --profile=<profile> ldrmodules` - Prikazivanje učitanih modula
- `volatility -f <dumpfile> --profile=<profile> modscan` - Skeniranje modula
- `volatility -f <dumpfile> --profile=<profile> getsids` - Prikazivanje SID-ova
- `volatility -f <dumpfile> --profile=<profile> getservicesids` - Prikazivanje SID-ova usluga
- `volatility -f <dumpfile> --profile=<profile> svcscan` - Skeniranje usluga
- `volatility -f <dumpfile> --profile=<profile> driverirp` - Prikazivanje IRP informacija za drajvere
- `volatility -f <dumpfile> --profile=<profile> callbacks` - Prikazivanje callback funkcija
- `volatility -f <dumpfile> --profile=<profile> mutantscan` - Skeniranje mutanata
- `volatility -f <dumpfile> --profile=<profile> devicetree` - Prikazivanje stabla uređaja
- `volatility -f <dumpfile> --profile=<profile> threads` - Prikazivanje niti
- `volatility -f <dumpfile> --profile=<profile> handles` - Prikazivanje rukovaoca
- `volatility -f <dumpfile> --profile=<profile> vadinfo` - Informacije o VAD-ovima
- `volatility -f <dumpfile> --profile=<profile> vadtree` - Stablo VAD-ova
- `volatility -f <dumpfile> --profile=<profile> idt` - Prikazivanje IDT informacija
- `volatility -f <dumpfile> --profile=<profile> gdt` - Prikazivanje GDT informacija
- `volatility -f <dumpfile> --profile=<profile> ssdt` - Prikazivanje SSDT informacija
- `volatility -f <dumpfile> --profile=<profile> driverscan` - Skeniranje drajvera
- `volatility -f <dumpfile> --profile=<profile> psxview` - Prikazivanje skrivenih procesa
- `volatility -f <dumpfile> --profile=<profile> ldrmodules` - Prikazivanje učitanih modula
- `volatility -f <dumpfile> --profile=<profile> mftparser` - Analiza Master File Table-a
- `voljson` - Konvertovanje rezultata u JSON format
- `volshell` - Interaktivna ljuska za Volatility
- `volshell -f <dumpfile> --profile=<profile>` - Interaktivna ljuska za Volatility sa određenim dump fajlom i profilom

#### Napredne komande

- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory>` - Dumpovanje memorije za određeni proces
- `volatility -f <dumpfile> --profile=<profile> memmap --output=memmap.txt` - Mapiranje memorije
- `volatility -f <dumpfile> --profile=<profile> memmap --output=memmap.txt --format=txt` - Mapiranje memorije u tekstualnom formatu
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory>` - Dumpovanje memorije za određeni proces
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za određeni proces sa imenom
- `volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory> --name` - Dumpovanje memorije za odre
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
## Registarski koš

### Ispis dostupnih koševa

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Recovering Deleted Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist`

- **Extracting Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### Dobijanje vrednosti

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}Uobičajena metodologija i resursi

### Osnovna forenzička metodologija

- **Analiza memorije**
  - **Volatility cheatsheet**
    - Komande za analizu memorijskih dumpova
    - Analiza procesa, modula, konekcija, registara, itd.
    - Identifikacija rootkit-ova i backdoor-ova
    - Pronalaženje otvorenih fajlova i tokena
    - Istraživanje mrežnih aktivnosti
    - Analiza drajvera i servisa
    - Pronalaženje skrivenih procesa
    - Istraživanje keširanih fajlova
    - Analiza registarskih ključeva
    - Istraživanje procesa i konekcija
    - Analiza šifrovanih fajlova
    - Istraživanje memorije procesa
    - Analiza keširanih fajlova
    - Istraživanje keširanih registara
    - Analiza keširanih konekcija
    - Istraživanje keširanih procesa
    - Analiza keširanih drajvera
    - Istraživanje keširanih servisa
    - Analiza keširanih tokena
    - Istraživanje keširanih modula
    - Analiza keširanih rootkit-ova
    - Istraživanje keširanih backdoor-ova
    - Analiza keširanih mrežnih aktivnosti
    - Istraživanje keširanih drajvera i servisa
    - Analiza keširanih otvorenih fajlova
    - Istraživanje keširanih registarskih ključeva
    - Analiza keširanih procesa i konekcija
    - Istraživanje keširanih šifrovanih fajlova
    - Analiza keširane memorije procesa
    - Istraživanje keširanih keširanih fajlova
    - Analiza keširanih keširanih registara
    - Istraživanje keširanih keširanih konekcija
    - Analiza keširanih keširanih procesa
    - Istraživanje keširanih keširanih drajvera
    - Analiza keširanih keširanih servisa
    - Istraživanje keširanih keširanih tokena
    - Analiza keširanih keširanih modula
    - Istraživanje keširanih keširanih rootkit-ova
    - Analiza keširanih keširanih backdoor-ova
    - Istraživanje keširanih keširanih mrežnih aktivnosti
    - Istraživanje keširanih keširanih drajvera i servisa
    - Analiza keširanih keširanih otvorenih fajlova
    - Istraživanje keširanih keširanih registarskih ključeva
    - Analiza keširanih keširanih procesa i konekcija
    - Istraživanje keširanih keširanih šifrovanih fajlova
    - Analiza keširanih keširane memorije procesa
    - Istraživanje keširanih keširanih keširanih fajlova
    - Analiza keširanih keširanih keširanih registara
    - Istraživanje keširanih keširanih keširanih konekcija
    - Analiza keširanih keširanih keširanih procesa
    - Istraživanje keširanih keširanih keširanih drajvera
    - Analiza keširanih keširanih keširanih servisa
    - Istraživanje keširanih keširanih keširanih tokena
    - Analiza keširanih keširanih keširanih modula
    - Istraživanje keširanih keširanih keširanih rootkit-ova
    - Analiza keširanih keširanih keširanih backdoor-ova
    - Istraživanje keširanih keširanih keširanih mrežnih aktivnosti
    - Istraživanje keširanih keširanih keširanih drajvera i servisa
    - Analiza keširanih keširanih keširanih otvorenih fajlova
    - Istraživanje keširanih keširanih keširanih registarskih ključeva
    - Analiza keširanih keširanih keširanih procesa i konekcija
    - Istraživanje keširanih keširanih keširanih šifrovanih fajlova
    - Analiza keširanih keširanih keširane memorije procesa
    - Istraživanje keširanih keširanih keširanih keširanih fajlova
    - Analiza keširanih keširanih keširanih keširanih registara
    - Istraživanje keširanih keširanih keširanih keširanih konekcija
    - Analiza keširanih keširanih keširanih keširanih procesa
    - Istraživanje keširanih keširanih keširanih keširanih drajvera
    - Analiza keširanih keširanih keširanih keširanih servisa
    - Istraživanje keširanih keširanih keširanih keširanih tokena
    - Analiza keširanih keširanih keširanih keširanih modula
    - Istraživanje keširanih keširanih keširanih keširanih rootkit-ova
    - Analiza keširanih keširanih keširanih keširanih backdoor-ova
    - Istraživanje keširanih keširanih keširanih keširanih mrežnih aktivnosti
    - Istraživanje keširanih keširanih keširanih keširanih drajvera i servisa
    - Analiza keširanih keširanih keširanih keširanih otvorenih fajlova
    - Istraživanje keširanih keširanih keširanih keširanih registarskih ključeva
    - Analiza keširanih keširanih keširanih keširanih procesa i konekcija
    - Istraživanje keširanih keširanih keširanih keširanih šifrovanih fajlova
    - Analiza keširanih keširanih keširanih keširane memorije procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširanih registara
    - Istraživanje keširanih keširanih keširanih keširanih keširanih konekcija
    - Analiza keširanih keširanih keširanih keširanih keširanih procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih drajvera
    - Analiza keširanih keširanih keširanih keširanih keširanih servisa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih tokena
    - Analiza keširanih keširanih keširanih keširanih keširanih modula
    - Istraživanje keširanih keširanih keširanih keširanih keširanih rootkit-ova
    - Analiza keširanih keširanih keširanih keširanih keširanih backdoor-ova
    - Istraživanje keširanih keširanih keširanih keširanih keširanih mrežnih aktivnosti
    - Istraživanje keširanih keširanih keširanih keširanih keširanih drajvera i servisa
    - Analiza keširanih keširanih keširanih keširanih keširanih otvorenih fajlova
    - Istraživanje keširanih keširanih keširanih keširanih keširanih registarskih ključeva
    - Analiza keširanih keširanih keširanih keširanih keširanih procesa i konekcija
    - Istraživanje keširanih keširanih keširanih keširanih keširanih šifrovanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširane memorije procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih registara
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih konekcija
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih drajvera
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih servisa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih tokena
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih modula
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih rootkit-ova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih backdoor-ova
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih mrežnih aktivnosti
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih drajvera i servisa
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih otvorenih fajlova
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih registarskih ključeva
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih procesa i konekcija
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih šifrovanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširane memorije procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih registara
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih konekcija
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih drajvera
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih servisa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih tokena
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih modula
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih rootkit-ova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih backdoor-ova
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih mrežnih aktivnosti
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih drajvera i servisa
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih otvorenih fajlova
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih registarskih ključeva
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih procesa i konekcija
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih šifrovanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširane memorije procesa
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih keširanih fajlova
    - Analiza keširanih keširanih keširanih keširanih keširanih keširanih keširanih keširanih registara
    - Istraživanje keširanih keširanih keširanih keširanih keširanih keširanih keširanih keširanih konekcija
    - Analiza keširanih keširanih keširani
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
### Damp

{% endtab %}
{% endtabs %}
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Fajl sistem

### Montiranje

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f memory_image.raw imageinfo`
- **Filescan:** `vol.py -f memory_image.raw filescan`
- **PSScan:** `vol.py -f memory_image.raw psscan`
- **Handles:** `vol.py -f memory_image.raw handles`
- **Netscan:** `vol.py -f memory_image.raw netscan`
- **Connections:** `vol.py -f memory_image.raw connections`
- **Cmdline:** `vol.py -f memory_image.raw cmdline`
- **Console History:** `vol.py -f memory_image.raw cmdscan`
- **Malware Scan:** `vol.py -f memory_image.raw malscan`

### Plugins

- **PSList:** `vol.py -f memory_image.raw --profile=Win7SP1x64 pslist`
- **PSTree:** `vol.py -f memory_image.raw --profile=Win7SP1x64 pstree`
- **DLLList:** `vol.py -f memory_image.raw --profile=Win7SP1x64 dlllist`
- **Handles:** `vol.py -f memory_image.raw --profile=Win7SP1x64 handles`
- **SSDT:** `vol.py -f memory_image.raw --profile=Win7SP1x64 ssdt`
- **Driver Module:** `vol.py -f memory_image.raw --profile=Win7SP1x64 modscan`

### Dumping Processes

- **Dump Process:** `vol.py -f memory_image.raw --profile=Win7SP1x64 procdump -p <PID> -D <output_directory>`
- **Dump Process Memory:** `vol.py -f memory_image.raw --profile=Win7SP1x64 memdump -p <PID> -D <output_directory>`

### Extracting Files

- **File Extract:** `vol.py -f memory_image.raw --profile=Win7SP1x64 file -S <start> -E <end> -O <output_directory>`
- **Dump File:** `vol.py -f memory_image.raw --profile=Win7SP1x64 dumpfiles -Q <address_range> -D <output_directory>`

### Network Analysis

- **Netscan:** `vol.py -f memory_image.raw --profile=Win7SP1x64 netscan`
- **Connections:** `vol.py -f memory_image.raw --profile=Win7SP1x64 connections`
- **Sockets:** `vol.py -f memory_image.raw --profile=Win7SP1x64 sockets`
- **Sockscan:** `vol.py -f memory_image.raw --profile=Win7SP1x64 sockscan`

### Registry Analysis

- **Printkey:** `vol.py -f memory_image.raw --profile=Win7SP1x64 printkey -K <key>`
- **HiveList:** `vol.py -f memory_image.raw --profile=Win7SP1x64 hivelist`
- **HiveScan:** `vol.py -f memory_image.raw --profile=Win7SP1x64 hivescan`

### Malware Analysis

- **Malfind:** `vol.py -f memory_image.raw --profile=Win7SP1x64 malfind`
- **Yarascan:** `vol.py -f memory_image.raw --profile=Win7SP1x64 yarascan`

### Process Analysis

- **Cmdline:** `vol.py -f memory_image.raw --profile=Win7SP1x64 cmdline`
- **Consoles:** `voljson.py -f memory_image.raw --profile=Win7SP1x64 consoles`
- **Console History:** `vol.py -f memory_image.raw --profile=Win7SP1x64 cmdscan`

### Kernel Analysis

- **SSDT:** `vol.py -f memory_image.raw --profile=Win7SP1x64 ssdt`
- **Driver Module:** `vol.py -f memoryjson.py -f memory_image.raw --profile=Win7SP1x64 modscan`

### User Analysis

- **Getsids:** `vol.py -f memory_image.raw --profile=Win7SP1x64 getsids`
- **Privs:** `vol.py -f memory_image.raw --profile=Win7SP1x64 privs`
- **Malfind:** `vol.py -f memory_image.raw --profile=Win7SP1x64 malfind`

### Other Useful Commands

- **API Hooks:** `vol.py -f memory_image.raw --profile=Win7SP1x64 apihooks`
- **LDR Modules:** `vol.py -f memory_image.raw --profile=Win7SP1x64 ldrmodules`
- **API Audit:** `vol.py -f memory_image.raw --profile=Win7SP1x64 apiaudit`
- **Handles:** `vol.py -f memory_image.raw --profile=Win7SP1x64 handles`
- **Privs:** `vol.py -f memory_image.raw --profile=Win7SP1x64 privs`
- **Yarascan:** `vol.py -f memory_image.raw --profile=Win7SP1x64 yarascan`{% endtab %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Skeniranje/dumpovanje

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> imageinfo | grep Profile`
- **PSList:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **PSTree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **NetScan:** `vol.py -f <memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **CmdLine:** `vol.py -f <memory_dump> --profile=<profile> cmdline`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles`
- **DLLList:** `vol.py -f <memory_dump> --profile=<profile> dlllist`
- **Privs:** `vol.py -f <memory_dump> --profile=<profile> privs`
- **YaraScan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Dump:** `vol.py -f <memory_dump> --profile=<profile> -D <output_directory> memdump <process_id>`

### Advanced Commands

- **Mimikatz:** `vol.py -f <memory_dump> --profile=<profile> mimikatz`
- **Lsadump:** `vol.py -f <memory_dump> --profile=<profile> lsadump`
- **Hivelist:** `vol.py -f <memory_dump> --profile=<profile> hivelist`
- **Hashdump:** `vol.py -json -f <memory_dump> --profile=<profile> hashdump`
- **UserAssist:** `vol.py -f <memory_dump> --profile=<profile> userassist`
- **Registry:** `vol.py -f <memory_dump> --profile=<profile> printkey -K <registry_key>`
- **Dump Registry Hive:** `vol.py -f <memory_dump> --profile=<profile> dumpregistry -s <registry_hive>`
- **FileScan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **Dump Files:** `vol.py -f <memory_dump> --profile=<profile> dumpfiles -Q <file_path>`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles -p <process_id>`
- **API Hooks:** `vol.py -f <json_output> --profile=<profile> apihooks`
- **SSDT Hooks:** `vol.py -f <json_output> --profile=<profile> ssdt`
- **Driver Module:** `vol.py -f <memory_dump> --profile=<profile> modscan`
- **Driver Module Dump:** `vol.py -f <memory_dump> --profile=<profile> moddump -b <base_address> -m <module_name> -D <output_directory>`

### Plugin Output

- **Output to File:** `vol.py -f <memory_dump> --profile=<profile> <plugin_name> > output.txt`
- **Output in JSON Format:** `vol.py -f <memory_dump> --profile=<profile> <plugin_name> -json > output.json`
- **Output in CSV Format:** `vol.py -f <memory_dump> --profile=<profile> <plugin_name> --output=csv > output.csv`{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Master File Table

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}Kratki vodič za Volatility

### Osnovne komande

- `imageinfo` - Informacije o slikama
- `pslist` - Lista procesa
- `pstree` - Stablo procesa
- `psscan` - Skeniranje procesa
- `dlllist` - Lista učitanih DLL-ova
- `handles` - Lista otvorenih ručica
- `cmdline` - Argumenti komandne linije
- `consoles` - Konzole procesa
- `vadinfo` - Informacije o VAD-ovima
- `vadtree` - Stablo VAD-ova
- `vaddump` - Dumpovanje VAD-ova
- `malfind` - Pronalaženje sumnjivih procesa
- `ldrmodules` - Lista učitanih modula
- `apihooks` - Detekcija API hook-ova
- `svcscan` - Skeniranje servisa
- `connections` - Mrežne veze
- `sockets` - Sockets
- `devicetree` - Stablo uređaja
- `driverirp` - Analiza IRP-a drajvera
- `modscan` - Skeniranje kernel modula
- `ssdt` - SSDT hook-ovi
- `callbacks` - Callback hook-ovi
- `gdt` - Globalna deskriptorska tabela
- `idt` - Interrupt deskriptorska tabela
- `userhandles` - Lista korisničkih ručica
- `privs` - Privilegije procesa
- `privs` - Privilegije procesa
- `timeliner` - Analiza vremenske linije
- `mftparser` - Analiza Master File Table-a
- `mftparser` - Analiza Master File Table-a
- `filescan` - Skeniranje fajlova
- `dumpfiles` - Dumpovanje fajlova
- `dumpregistry` - Dumpovanje registra
- `hashdump` - Dumpovanje hash-ova lozinki
- `hivelist` - Lista učitanih registarskih datoteka
- `printkey` - Prikazivanje ključa registra
- `svcscan` - Skeniranje servisa
- `handles` - Lista otvorenih ručica
- `getsids` - Dobijanje SID-ova
- `getsids` - Dobijanje SID-ova
- `psxview` - Prikazivanje skrivenih procesa
- `netscan` - Skeniranje mreže
- `autoruns` - Prikazivanje autorun programa
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Skeniranje atoma
- `atomscan` - Sk
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFS fajl sistem** koristi ključnu komponentu poznatu kao _master fajl tabela_ (MFT). Ova tabela uključuje barem jedan unos za svaki fajl na volumenu, uključujući i samu MFT. Važni detalji o svakom fajlu, poput **veličine, vremenskih oznaka, dozvola i stvarnih podataka**, su enkapsulirani unutar unosa MFT-a ili u oblastima van MFT-a ali na koje se referišu ovi unosi. Više detalja možete pronaći u [zvaničnoj dokumentaciji](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### SSL Ključevi/Sertifikati

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}Kratki vodič za Volatility

### Osnovne komande

- `imageinfo` - prikaz informacija o slikama
- `pslist` - prikazuje procese
- `pstree` - prikazuje stablo procesa
- `dlllist` - prikazuje učitane DLL-ove
- `cmdline` - prikazuje argumente komandne linije
- `filescan` - skenira za otvorene fajlove
- `connscan` - skenira za otvorene mrežne konekcije
- `malfind` - pronalazi sumnjive procese
- `dumpfiles` - izvlači fajlove iz memorije
- `memdump` - pravi dump memorije procesa

### Analiza registara

- `hivelist` - prikazuje registre učitane u memoriju
- `printkey` - prikazuje ključeve registra
- `hashdump` - izvlači korisničke lozinke

### Analiza mreže

- `netscan` - prikazuje otvorene mrežne portove
- `sockets` - prikazuje otvorene sokete
- `connscan` - skenira za otvorene mrežne konekcije

### Analiza procesa

- `psscan` - skenira procese
- `psxview` - prikazuje skrivene procese
- `ldrmodules` - prikazuje učitane module

### Analiza drajvera

- `driverirp` - prikazuje IRP zahteve drajvera
- `drivermodule` - priukazuje učitane drajvere

### Analiza fajlova

- `filescan` - skenira za otvorene fajlove
- `dumpfiles` - izvlači fajlove iz memorije

### Analiza memorije

- `memmap` - prikazuje mapiranje memorije
- `memdump` - pravi dump memorije procesa
{% endtab %}
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

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> imageinfo | grep Profile`
- **PSList:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **PSTree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **NetScan:** `vol.py -f <memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **CmdLine:** `vol.py -f <memory_dump> --profile=<profile> cmdline`
- **FileScan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles`
- **Privs:** `vol.py -f <memory_dump> --profile=<profile> privs`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **MalProcFind:** `vol.py -json -f <memory_dump> --profile=<profile> malprocfind`
- **MalwareScan:** `vol.py -f <memory_dump> --profile=<profile> malsysproc`
- **YaraScan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Dump:** `vol.py -f <memory_dump> --profile=<profile> -D <output_directory> --dump-dir=<dump_directory> procdump -p <pid>`
- **Registry Hive:** `vol.py -f <memory_dump> --profile=<profile> printkey -o <output_directory> -K <registry_hive>`
- **Dump Registry:** `vol.py -f <memory_dump> --profile=<profile> dumpregistry -o <output_directory>`

### Advanced Commands

- **UserAssist:** `vol.py -f <memory_dump> --profile=<profile> userassist`
- **Shellbags:** `vol.py -f <memory_dump> --profile=<profile> shellbags`
- **MFTParser:** `vol.py -f <memory_dump> --profile=<profile> mftparser`
- **Lsass:** `vol.py -json -f <memory_dump> --profile=<profile> lsadump`
- **Dump SAM:** `vol.py -f <memory_dump> --profile=<profile> dump SAM -o <output_directory>`
- **Dump LSA:** `vol.py -f <memory_dump> --profile=<profile> dump LSA -o <outputjson>`
- **Dump Hashes:** `vol.py -f <memory_dump> --profile=<profile> hashdump -o <output_directory>`
- **Dump Password:** `vol.py -f <memory_dump> --profile=<profile> hashdump -o <output_directory> --dump-passwords`
- **Dump Certs:** `vol.py -f <memory_dump> --profile=<profile> dumpcerts -o <output_directory>`
- **Dump Vault:** `vol.py -f <memory_dump> --profile=<profile> dump vault -o <output_directory>`
- **Dump Chrome:** `vol.py -f <memory_dump> --profile=<profile> chromehistory -o <output_directory>`
- **Dump Firefox:** `vol.py -json -f <memory_dump> --profile=<profile> firefoxhistory -o <output_directory>`
- **Dump IE:** `vol.py -f <memory_dump> --profile=<profile> iehistory -o <outputjson>`
- **Dump Outlook:** `vol.py -f <memory_dump> --profile=<profile> outlook -o <output_directory>`
- **Dump Putty:** `vol.py -f <memory_dump> --profile=<profile> putty -o <output_directory>`
- **Dump RDP:** `vol.py -f <memory_dump> --profile=<profile> rdp -o <output_directory>`
- **Dump Truecrypt:** `vol.py -f <memory_dump> --profile=<profile> truecryptmaster -o <output_directory>`
- **Dump Bitlocker:** `vol.py -f <memory_dump> --profile=<profile> bitlocker -o <output_directory>`
- **Dump Keepass:** `vol.py -f <memory_dump> --profile=<profile> keepass -o <output_directory>`
- **Dump Wireless:** `vol.py -f <memory_dump> --profile=<profile> wireless -o <output_directory>`
- **Dump Pstalls:** `vol.py -f <memory_dump> --profile=<profile> pstalls -o <output_directory>`
- **Dump Psscan:** `vol.py -f <memory_dump> --profile=<profile> psscan -o <output_directory>`
- **Dump Psxview:** `vol.py -f <memory_dump> --profile=<profile> psxview -o <output_directory>`
- **Dump MalwareConfig:** `vol.py -f <json_output> --profile=<profile> malconfscan -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:** `vol.py -f <json_output> --profile=<profile> malapi -o <output_directory>`
- **Dump MalwareDlls:** `vol.py -f <json_output> --profile=<profile> maldlllist -o <output_directory>`
- **Dump MalwareHandles:** `vol.py -f <json_output> --profile=<profile> malhandle -o <output_directory>`
- **Dump MalwarePsList:** `vol.py -f <json_output> --profile=<profile> malpslist -o <output_directory>`
- **Dump MalwarePsTree:** `vol.py -f <json_output> --profile=<profile> malpstree -o <output_directory>`
- **Dump MalwareYara:** `vol.py -f <json_output> --profile=<profile> malyara -o <output_directory>`
- **Dump MalwareStrings:** `vol.py -f <json_output> --profile=<profile> malstrscan -o <output_directory>`
- **Dump MalwareApiHooks:** `vol.py -f <json_output> --profile=<profile> malapihooks -o <output_directory>`
- **Dump MalwareApi:**
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

### Skeniranje pomoću yara

Koristite ovaj skript za preuzimanje i spajanje svih yara pravila za malver sa github-a: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Napravite direktorijum _**rules**_ i izvršite skriptu. Ovo će kreirati fajl nazvan _**malware\_rules.yar**_ koji sadrži sva yara pravila za malver.
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

{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## RAZNO

### Spoljni dodaci

Ako želite da koristite spoljne dodatke, pobrinite se da su fascikle vezane za dodatke prvi parametar koji se koristi.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image info:** `vol.py -f <memory_dump> imageinfo`
- **Profile:** `vol.py -f <memory_dump> imageinfo | grep Profile`
- **PSList:** `vol.py -f <memory_dump> --profile=<profile> pslist`
- **PSTree:** `vol.py -f <memory_dump> --profile=<profile> pstree`
- **NetScan:** `vol.py -f <memory_dump> --profile=<profile> netscan`
- **Connections:** `vol.py -f <memory_dump> --profile=<profile> connscan`
- **CmdLine:** `vol.py -f <memory_dump> --profile=<profile> cmdline`
- **FileScan:** `vol.py -f <memory_dump> --profile=<profile> filescan`
- **MalFind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **YaraScan:** `vol.py -f <memory_dump> --profile=<profile> yarascan`
- **Dump:** `vol.py -f <memory_dump> --profile=<profile> -D <output_directory> --name=<process_name>`
- **Handles:** `vol.py -f <memory_dump> --profile=<profile> handles`
- **Privs:** `vol.py -f <memory_dump> --profile=<profile> privs`
- **Getsids:** `vol.py -f <memory_dump> --profile=<profile> getsids`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> malfind`
- **Malfind:** `vol.py -f <memory_dump> --profile=<profile> m
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Preuzmite sa [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}Uobičajena metodologija i resursi

### Osnovna forenzička metodologija

1. **Identifikacija problema**
   - Definišite problem i ciljeve analize.

2. **Prikupljanje informacija**
   - Prikupite informacije o sistemu, korisnicima, aktivnostima i vremenskom okviru.

3. **Analiza informacija**
   - Analizirajte informacije kako biste identifikovali sumnjive aktivnosti ili tragove.

4. **Validacija**
   - Potvrdite identifikovane tragove i aktivnosti.

5. **Izveštavanje**
   - Pripremite izveštaj o analizi sa svim relevantnim informacijama i zaključcima.

### Analiza memorijskog ispusta pomoću Volatility alata

1. **Identifikacija profila**
   - Identifikujte odgovarajući profil memorijskog ispusta.

2. **Analiza procesa**
   - Proučite procese u memorijskom ispustu.

3. **Analiza mrežnih veza**
   - Istražite mrežne veze i aktivnosti.

4. **Analiza registara**
   - Pregledajte registre radi pronalaženja korisnih informacija.

5. **Analiza datoteka**
   - Ispitajte datoteke kako biste pronašli sumnjive sadržaje.

6. **Analiza šifrovanja**
   - Identifikujte i dešifrujte šifrovane podatke ako je potrebno.

7. **Analiza zlonamernih aktivnosti**
   - Tražite znakove zlonamernih aktivnosti u memorijskom ispustu.

8. **Generisanje izveštaja**
   - Kreirajte detaljan izveštaj o analizi memorijskog ispusta.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Simboličke veze

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

Moguće je **čitati iz memorije istoriju komandi u bash-u.** Takođe možete izvući fajl _.bash\_history_, ali ako je onemogućen, bićete srećni što možete koristiti ovaj modul volatilnosti.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

## Osnovna forenzička metodologija

### Analiza memorije

#### Volatility Cheat Sheet

### Osnovne komande

- `volatility -f <dumpfile> imageinfo` - prikaz informacija o dump fajlu
- `volatility -f <dumpfile> pslist` - prikaz listi aktivnih procesa
- `volatility -f <dumpfile> psscan` - skeniranje procesa
- `volatility -f <dumpfile> pstree` - prikaz stabla procesa
- `volatility -f <dumpfile> dlllist -p <PID>` - prikaz učitanih DLL-ova za određeni proces
- `volatility -f <dumpfile> filescan` - skeniranje fajlova
- `volatility -f <dumpfile> cmdline -p <PID>` - prikaz komandne linije za određeni proces
- `volatility -f <dumpfile> netscan` - skeniranje mrežnih konekcija
- `volatility -f <dumpfile> connections` - prikaz TCP konekcija
- `volatility -f <dumpfile> timeliner` - analiza vremenske linije
- `volatility -f <dumpfile> malfind` - detekcija sumnjivih procesa
- `volatility -f <dumpfile> apihooks` - prikaz API hook-ova
- `volatility -f <dumpfile> ldrmodules` - prikaz učitanih modula
- `volatility -f <dumpfile> modscan` - skeniranje modula
- `volatility -f <dumpfile> mutantscan` - skeniranje mutanata
- `volatility -f <dumpfile> svcscan` - skeniranje servisa
- `volatility -f <dumpfile> userassist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> shimcache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> hivelist` - prikaz registarskih ključeva
- `volatility -f <dumpfile> printkey -o <Offset>` - prikaz sadržaja registarskog kljujsona na određenom offsetu
- `volatility -f <dumpfile> hashdump` - ekstrakcija korisničkih lozinki
- `volatility -f <dumpfile> truecryptpassphrase` - ekstrakcija TrueCrypt lozinke
- `volatility -f <dumpfile> clipboard` - prikaz sadržaja clipboard-a
- `volatility -f <dumpfile> screenshot` - snimanje screenshot-a
- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` - dumpovanje memorije za određeni proces
- `volatility -f <dumpfile> memdump -p <PID> --output-file <output_file>` - dumpovanje memorije za određeni proces u određeni fajl
- `volatility -f <dumpfile> memmap` - prikaz mapiranja memorije
- `volatility -f <dumpfile> raw2dmp -f <input_file> -o <output_file>` - konverzija raw memorije u dump fajl
- `volatility -f <dumpfile> raw2dmp --physmap -f <input_file> -o <output_file>` - konverzija raw fizičke memorije u dump fajl

### Napredne komande

- `volatility -f <dumpfile> windows.lsadump.Lsadump` - ekstrakcija LSASS procesa
- `volatility -f <dumpfile> windows.dumpfiles.DumpFiles` - ekstrakcija fajlova iz memorije
- `volatility -f <dumpfile> windows.registry.hivelist.HiveList` - prikaz registarskih ključeva
- `volatility -f <dumpfile> windows.registry.printkey.PrintKey -o <Offset>` - prikaz sadržaja registarskog ključa na određenom offsetu
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
- `volatility -f <dumpfile> windows.registry.shimcache.ShimCache` - analiza Shimcache baze podataka
- `volatility -f <dumpfile> windows.registry.userassist.UserAssist` - analiza UserAssist ključeva
-
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Vremenska linija

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`

- **Dumping a Registry Hive**
  - `voljsonity -f <memory_dump> --profile=<profile> printkey -o <output_directory> -K <hive_offset>`

### Advanced Commands

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Identifying Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Extracting DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump -D <output_directory>`

- **Analyzing Timelining**
  - `volatility -f <memory_dump> --profile=<profile> timeliner`

- **Analyzing Packed Binaries**
  - `volatility -f <memory_dump> --profile=<profile> mpp`

- **Analyzing Suspicious Drivers**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Registry Transactions**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <output_directory> -K <hive_offset>`

- **Analyzing UserAssist**
  - `volatility -f <memory_dump> --profile=<profile> userassist`

- **Analyzing Shellbags**
  - `volatility -f <memory_dump> --profile=<profile> shellbags`

- **Analyzing LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing IRP Hooks**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing IDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing GDT Hooks**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> ldrmodules`

- **Analyzing Hidden SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing Hidden IRP**
  - `volatility -f <memory_dump> --profile=<profile> irp`

- **Analyzing Hidden IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing Hidden GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing Hidden Handlers**
  - `volatility -f <memory_dump> --profile=<profile> handlers`

- **Analyzing Hidden Ports**
  - `volatility -f <memory_dump> --profile=<profile> ports`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> svcscan`

- **Analyizing Hidden Devices**
  - `volatility -f <memory_dump> --profile=<profile> devicetree`

- **Analyzing Hidden Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`

- **Analyzing Hidden Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> hivescan`

- **Analyzing Hidden Objects**
  - `volatility -f <memory_dump> --profile=<profile> callbacks`

- **Analyzing Hidden Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Hidden Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockets`

- **Analyzing Hidden Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads`

- **Analyzing Hidden Timers**
  - `volatility -f <memory_dump> --profile=<profile> timers`

- **Analyzing Hidden Windows**
  - `volatility -f <memory_dump> --profile=<profile> windows`

- **Analyzing Hidden Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing Hidden Tokens**
  - `volatility -f <memory_dump> --profile=<profile> tokens`

- **Analyzing Hidden Drivers**
  - `volatility -f <memory_dump> --profile=<profile> drivers`

- **Analyzing Hidden Services**
  - `volatility -f <memory_dump> --profile=<profile> services`

- **Analyzing Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyizing Hidden Modules**
  - `volatility -f <memory_dump> --profile=<profile> modules`

- **Analyzing Hidden DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlldump`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Hidden Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### Drajveri

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}Kratki vodič za Volatility

- **Analiza procesa**
  - `volatility -f <dumpfile> --profile=<profile> pslist` - Lista aktivnih procesa
  - `volatility -f <dumpfile> --profile=<profile> psscan` - Skenira procese u fizičkoj memoriji
  - `volatility -f <dumpfile> --profile=<profile> pstree` - Prikazuje stablo procesa

- **Analiza mreže**
  - `volatility -f <dumpfile> --profile=<profile> netscan` - Skenira otvorene mrežne veze
  - `volatility -f <dumpfile> --profile=<profile> connscan` - Skenira TCP i UDP konekcije

- **Analiza registra**
  - `volatility -f <dumpfile> --profile=<profile> hivelist` - Lista registarskih datoteka u memoriji
  - `volatility -f <dumpfile> --profile=<profile> printkey -o <offset>` - Prikazuje ključeve registra

- **Analiza datoteka**
  - `volatility -f <dumpfile> --profile=<profile> filescan` - Skenira otvorene datoteke
  - `volatility -f <dumpfile> --profile=<profile> dumpfiles -Q <address>` - Izdvaja datoteke iz memorije

- **Analiza korisnika**
  - `volatility -f <dumpfile> --profile=<profile> getsids` - Prikazuje SID-ove korisnika
  - `volatility -f <dumpfile> --profile=<profile> hivescan` - Skenira korisničke profile

- **Ostalo**
  - `volatility -f <dumpfile> --profile=<profile> cmdline` - Prikazuje argumente komandne linije procesa
  - `volatility -f <dumpfile> --profile=<profile> consoles` - Prikazuje otvorene konzole
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
### Dobijanje sadržaja klipborda
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Dobijanje istorije pretraživača Internet Explorer
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Dobijanje teksta iz beležnice
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Snimak ekrana
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** igra ključnu ulogu u upravljanju logičkim particijama skladišnog medijuma, koje su strukturirane sa različitim [sistemima datoteka](https://en.wikipedia.org/wiki/File\_system). Ne samo da sadrži informacije o rasporedu particija već takođe sadrži izvršni kod koji deluje kao bootloader. Ovaj bootloader ili direktno pokreće proces učitavanja drugog nivoa OS-a (videti [bootloader drugog nivoa](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)) ili radi u harmoniji sa [zapisa o podizanju zapremine](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) svake particije. Za dubinsko znanje, pogledajte [MBR Wikipedia stranicu](https://en.wikipedia.org/wiki/Master\_boot\_record).

## Reference

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantniji događaj u oblasti **kibernetičke bezbednosti** u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključno mesto susreta tehnoloških i kibernetičkih profesionalaca u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
