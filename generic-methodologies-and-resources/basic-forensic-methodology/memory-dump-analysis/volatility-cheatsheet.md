# Volatility - CheatSheet

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

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{% embed url="https://www.rootedcon.com/" %}

If you want something **fast and crazy** that will launch several Volatility plugins on parallel you can use: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalacja

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Metoda1" %}
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

## Komendy Volatility

Zobacz oficjalną dokumentację w [odniesieniu do komend Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Uwaga na wtyczki „list” vs. „scan”

Volatility ma dwa główne podejścia do wtyczek, które czasami są odzwierciedlone w ich nazwach. Wtyczki „list” będą próbować nawigować przez struktury jądra Windows, aby uzyskać informacje takie jak procesy (lokalizowanie i przechodzenie przez powiązaną listę struktur `_EPROCESS` w pamięci), uchwyty systemu operacyjnego (lokalizowanie i wyświetlanie tabeli uchwytów, dereferencjonowanie wszelkich znalezionych wskaźników itp.). Zachowują się one mniej więcej tak, jakby API Windows zostało poproszone o, na przykład, wylistowanie procesów.

To sprawia, że wtyczki „list” są dość szybkie, ale równie podatne na manipulacje przez złośliwe oprogramowanie, jak API Windows. Na przykład, jeśli złośliwe oprogramowanie użyje DKOM, aby odłączyć proces od powiązanej listy `_EPROCESS`, nie pojawi się on w Menedżerze zadań, ani w pslist.

Z drugiej strony, wtyczki „scan” przyjmą podejście podobne do wydobywania z pamięci rzeczy, które mogą mieć sens, gdy zostaną dereferencjonowane jako konkretne struktury. `psscan` na przykład odczyta pamięć i spróbuje stworzyć obiekty `_EPROCESS` z niej (używa skanowania tagów puli, które polega na wyszukiwaniu 4-bajtowych ciągów wskazujących na obecność interesującej struktury). Zaletą jest to, że może wykryć procesy, które zakończyły działanie, a nawet jeśli złośliwe oprogramowanie manipuluje powiązaną listą `_EPROCESS`, wtyczka nadal znajdzie strukturę leżącą w pamięci (ponieważ nadal musi istnieć, aby proces mógł działać). Wadą jest to, że wtyczki „scan” są nieco wolniejsze niż wtyczki „list” i czasami mogą dawać fałszywe pozytywy (proces, który zakończył działanie zbyt dawno i miał części swojej struktury nadpisane przez inne operacje).

Z: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profile systemu operacyjnego

### Volatility3

Jak wyjaśniono w readme, musisz umieścić **tabelę symboli systemu operacyjnego**, który chcesz obsługiwać, w _volatility3/volatility/symbols_.\
Pakiety tabel symboli dla różnych systemów operacyjnych są dostępne do **pobrania** pod adresem:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Zewnętrzny profil

Możesz uzyskać listę obsługiwanych profili, wykonując:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Jeśli chcesz użyć **nowego profilu, który pobrałeś** (na przykład linuxowego), musisz stworzyć gdzieś następującą strukturę folderów: _plugins/overlays/linux_ i umieścić w tym folderze plik zip zawierający profil. Następnie, uzyskaj numer profili używając:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Możesz **pobrać profile dla Linuxa i Maca** z [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

W poprzednim fragmencie możesz zobaczyć, że profil nazywa się `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, i możesz go użyć do wykonania czegoś takiego:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Odkryj profil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Różnice między imageinfo a kdbgscan**

[**Stąd**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): W przeciwieństwie do imageinfo, które po prostu sugeruje profile, **kdbgscan** jest zaprojektowane do pozytywnej identyfikacji poprawnego profilu i poprawnego adresu KDBG (jeśli występuje ich wiele). Ten plugin skanuje sygnatury KDBGHeader powiązane z profilami Volatility i stosuje kontrole sanity, aby zredukować fałszywe pozytywy. Szczegółowość wyników i liczba kontroli sanity, które można przeprowadzić, zależy od tego, czy Volatility może znaleźć DTB, więc jeśli już znasz poprawny profil (lub jeśli masz sugestię profilu z imageinfo), upewnij się, że go używasz.

Zawsze zwracaj uwagę na **liczbę procesów, które znalazł kdbgscan**. Czasami imageinfo i kdbgscan mogą znaleźć **więcej niż jeden** odpowiedni **profil**, ale tylko **ważny będzie miał jakieś powiązane procesy** (Dzieje się tak, ponieważ do wyodrębnienia procesów potrzebny jest poprawny adres KDBG).
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

**Blok debuggera jądra**, określany jako **KDBG** przez Volatility, jest kluczowy dla zadań kryminalistycznych wykonywanych przez Volatility i różne debugery. Zidentyfikowany jako `KdDebuggerDataBlock` i typu `_KDDEBUGGER_DATA64`, zawiera istotne odniesienia, takie jak `PsActiveProcessHead`. To konkretne odniesienie wskazuje na początek listy procesów, co umożliwia wylistowanie wszystkich procesów, co jest fundamentalne dla dokładnej analizy pamięci.

## Informacje o systemie operacyjnym
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners` może być użyty w **vol3, aby spróbować znaleźć bannery linuxowe** w zrzucie.

## Hashe/Hasła

Wyodrębnij hashe SAM, [pamiętane poświadczenia domeny](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) i [sekrety lsa](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Zrzut pamięci

Zrzut pamięci procesu **wyciągnie wszystko** z bieżącego stanu procesu. Moduł **procdump** **wyciągnie** tylko **kod**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{% embed url="https://www.rootedcon.com/" %}

## Procesy

### Lista procesów

Spróbuj znaleźć **podejrzane** procesy (po nazwie) lub **nieoczekiwane** procesy potomne (na przykład cmd.exe jako proces potomny iexplorer.exe).\
Może być interesujące **porównanie** wyniku pslist z wynikiem psscan, aby zidentyfikować ukryte procesy.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### Zrzut proc

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Wiersz poleceń

Czy wykonano coś podejrzanego?

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Polecenia wykonywane w `cmd.exe` są zarządzane przez **`conhost.exe`** (lub `csrss.exe` w systemach przed Windows 7). Oznacza to, że jeśli **`cmd.exe`** zostanie zakończone przez atakującego przed uzyskaniem zrzutu pamięci, nadal możliwe jest odzyskanie historii poleceń sesji z pamięci **`conhost.exe`**. Aby to zrobić, jeśli wykryto nietypową aktywność w modułach konsoli, pamięć powiązanego procesu **`conhost.exe`** powinna zostać zrzutowana. Następnie, przeszukując **ciągi** w tym zrzucie, można potencjalnie wyodrębnić linie poleceń używane w sesji.

### Środowisko

Uzyskaj zmienne env każdego uruchomionego procesu. Mogą istnieć interesujące wartości.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### Uprawnienia tokenów

Sprawdź tokeny uprawnień w niespodziewanych usługach.\
Może być interesujące, aby wymienić procesy korzystające z niektórego tokena z uprawnieniami.

{% tabs %}
{% tab title="vol3" %}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Sprawdź każdy SSID posiadany przez proces.\
Może być interesujące, aby wymienić procesy używające SID z uprawnieniami (oraz procesy używające SID jakiejś usługi).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Uchwyty

Przydatne do wiedzy, do których innych plików, kluczy, wątków, procesów... **proces ma uchwyt** (otworzył) 

{% tabs %}
{% tab title="vol3" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Ciągi per procesy

Volatility pozwala nam sprawdzić, do którego procesu należy ciąg. 

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Umożliwia również wyszukiwanie ciągów wewnątrz procesu za pomocą modułu yarascan:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** śledzi programy, które uruchamiasz, za pomocą funkcji w rejestrze zwanej **kluczami UserAssist**. Te klucze rejestrują, ile razy każdy program został uruchomiony i kiedy był ostatnio uruchamiany.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z technologii i cyberbezpieczeństwa w każdej dziedzinie.

{% embed url="https://www.rootedcon.com/" %}

## Usługi

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}
{% endtabs %}

## Sieć

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}
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

## Rejestr hives

### Wydrukuj dostępne hives

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Uzyskaj wartość

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Zrzut
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## System plików

### Montowanie

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Skanowanie/zrzut

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}
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

### Mistrzowska Tabela Plików

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

System plików **NTFS** używa krytycznego komponentu znanego jako _master file table_ (MFT). Ta tabela zawiera przynajmniej jeden wpis dla każdego pliku na woluminie, obejmując również samą MFT. Kluczowe szczegóły dotyczące każdego pliku, takie jak **rozmiar, znaczniki czasu, uprawnienia i rzeczywiste dane**, są zawarte w wpisach MFT lub w obszarach zewnętrznych do MFT, ale odniesionych przez te wpisy. Więcej szczegółów można znaleźć w [oficjalnej dokumentacji](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Klucze/Certyfikaty SSL

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

## Złośliwe oprogramowanie

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

{% tab title="vol2" %}
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

### Skanowanie za pomocą yara

Użyj tego skryptu, aby pobrać i połączyć wszystkie zasady malware yara z github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Utwórz katalog _**rules**_ i uruchom go. To stworzy plik o nazwie _**malware\_rules.yar**_, który zawiera wszystkie zasady yara dla malware.

{% tabs %}
{% tab title="vol3" %}
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
{% endtab %}
{% endtabs %}

## MISC

### Zewnętrzne wtyczki

Jeśli chcesz używać zewnętrznych wtyczek, upewnij się, że foldery związane z wtyczkami są pierwszym parametrem używanym.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Pobierz z [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
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

{% tab title="vol2" %}
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
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Możliwe jest **odczytanie historii bash z pamięci.** Możesz również zrzucić plik _.bash\_history_, ale został on wyłączony, więc ucieszysz się, że możesz użyć tego modułu volatility.

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Oś Czasu

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Sterowniki

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Pobierz schowek
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Pobierz historię IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Pobierz tekst z notatnika
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Zrzut ekranu
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Mistrzowski Rekord Rozruchowy (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** odgrywa kluczową rolę w zarządzaniu logicznymi partycjami nośnika, które są zorganizowane w różne [systemy plików](https://en.wikipedia.org/wiki/File\_system). Nie tylko przechowuje informacje o układzie partycji, ale także zawiera kod wykonywalny działający jako program rozruchowy. Ten program rozruchowy albo bezpośrednio inicjuje proces ładowania drugiego etapu systemu operacyjnego (zobacz [program rozruchowy drugiego etapu](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)), albo współpracuje z [rekordem rozruchowym woluminu](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) każdej partycji. Aby uzyskać szczegółowe informacje, zapoznaj się z [stroną MBR na Wikipedii](https://en.wikipedia.org/wiki/Master\_boot\_record).

## References

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
