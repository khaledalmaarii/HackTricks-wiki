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

​​[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою популяризації технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

Якщо ви хочете щось **швидке і божевільне**, що запустить кілька плагінів Volatility паралельно, ви можете використовувати: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Встановлення

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Метод1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Метод 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Команди Volatility

Доступ до офіційної документації в [посиланні на команди Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Примітка про плагіни “list” та “scan”

Volatility має два основні підходи до плагінів, які іноді відображаються в їхніх назвах. Плагіни “list” намагатимуться навігувати через структури ядра Windows, щоб отримати інформацію, таку як процеси (знаходити та проходити через зв'язаний список структур `_EPROCESS` в пам'яті), дескриптори ОС (знаходити та перераховувати таблицю дескрипторів, розіменовувати будь-які знайдені вказівники тощо). Вони більше-менш поводяться так, як би поводився API Windows, якщо б його попросили, наприклад, перерахувати процеси.

Це робить плагіни “list” досить швидкими, але такими ж вразливими до маніпуляцій зловмисним ПЗ, як і API Windows. Наприклад, якщо зловмисне ПЗ використовує DKOM, щоб відключити процес від зв'язаного списку `_EPROCESS`, він не з'явиться в Диспетчері завдань, і не з'явиться в pslist.

Плагіни “scan”, з іншого боку, використовують підхід, схожий на карвінг пам'яті для речей, які можуть мати сенс, коли їх розіменовують як специфічні структури. `psscan`, наприклад, прочитає пам'ять і спробує створити об'єкти `_EPROCESS` з неї (він використовує сканування тегів пулу, яке шукає 4-байтові рядки, що вказують на наявність структури, що цікавить). Перевага полягає в тому, що він може виявити процеси, які завершили роботу, і навіть якщо зловмисне ПЗ втручається в зв'язаний список `_EPROCESS`, плагін все ще знайде структуру, що залишилася в пам'яті (оскільки вона все ще повинна існувати, щоб процес міг працювати). Недолік полягає в тому, що плагіни “scan” трохи повільніші, ніж плагіни “list”, і іноді можуть давати хибнопозитивні результати (процес, який завершив роботу занадто давно і частини його структури були перезаписані іншими операціями).

З: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Профілі ОС

### Volatility3

Як пояснено в readme, вам потрібно помістити **таблицю символів ОС**, яку ви хочете підтримувати, в _volatility3/volatility/symbols_.\
Пакети таблиць символів для різних операційних систем доступні для **завантаження** за адресами:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Зовнішній профіль

Ви можете отримати список підтримуваних профілів, виконавши:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Якщо ви хочете використовувати **новий профіль, який ви завантажили** (наприклад, для linux), вам потрібно створити десь таку структуру папок: _plugins/overlays/linux_ і помістити всередину цієї папки zip-файл, що містить профіль. Потім отримайте номер профілів, використовуючи:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Ви можете **завантажити профілі для Linux та Mac** з [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

У попередньому фрагменті ви можете побачити, що профіль називається `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, і ви можете використовувати його для виконання чогось на зразок:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Виявлення профілю
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Відмінності між imageinfo та kdbgscan**

[**Звідси**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): На відміну від imageinfo, який просто надає пропозиції профілю, **kdbgscan** призначений для точного визначення правильного профілю та правильного адреси KDBG (якщо їх кілька). Цей плагін сканує підписи KDBGHeader, пов'язані з профілями Volatility, і застосовує перевірки на адекватність, щоб зменшити кількість хибнопозитивних результатів. Число перевірок на адекватність та обсяг виводу залежать від того, чи може Volatility знайти DTB, тому, якщо ви вже знаєте правильний профіль (або якщо у вас є пропозиція профілю від imageinfo), переконайтеся, що ви його використовуєте.

Завжди звертайте увагу на **кількість процесів, які знайшов kdbgscan**. Іноді imageinfo та kdbgscan можуть знайти **більше ніж один** підходящий **профіль**, але лише **дійсний матиме деякі пов'язані процеси** (Це тому, що для витягнення процесів потрібна правильна адреса KDBG).
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

**Блок відладки ядра**, відомий як **KDBG** у Volatility, є критично важливим для судово-медичних завдань, які виконуються Volatility та різними відладчиками. Ідентифікований як `KdDebuggerDataBlock` і типу `_KDDEBUGGER_DATA64`, він містить важливі посилання, такі як `PsActiveProcessHead`. Це конкретне посилання вказує на голову списку процесів, що дозволяє перерахувати всі процеси, що є основою для ретельного аналізу пам'яті.

## OS Information
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners` can be used in **vol3 to try to find linux banners** in the dump.

## Hashes/Passwords

Витягніть хеші SAM, [кешовані облікові дані домену](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) та [секрети lsa](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets).

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

## Memory Dump

Дамп пам'яті процесу **вилучить все** з поточного стану процесу. Модуль **procdump** лише **вилучить** **код**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) є найактуальнішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

## Процеси

### Список процесів

Спробуйте знайти **підозрілі** процеси (за назвою) або **неочікувані** дочірні **процеси** (наприклад, cmd.exe як дочірній процес iexplorer.exe).\
Може бути цікаво **порівняти** результат pslist з результатом psscan, щоб виявити приховані процеси.

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

### Вивантаження процесу

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

### Командний рядок

Чи було виконано щось підозріле?

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

Команди, виконані в `cmd.exe`, керуються **`conhost.exe`** (або `csrss.exe` на системах до Windows 7). Це означає, що якщо **`cmd.exe`** буде завершено зловмисником до отримання дампу пам'яті, все ще можливо відновити історію команд сесії з пам'яті **`conhost.exe`**. Для цього, якщо в модулях консолі виявлено незвичну активність, пам'ять відповідного процесу **`conhost.exe`** слід дампувати. Потім, шукаючи **рядки** в цьому дампі, можна потенційно витягнути команди, використані в сесії.

### Середовище

Отримайте змінні середовища кожного запущеного процесу. Можуть бути цікаві значення.

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

### Привілеї токенів

Перевірте наявність привілейованих токенів у несподіваних службах.\
Може бути цікаво перерахувати процеси, які використовують деякі привілейовані токени.

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

Перевірте кожен SSID, що належить процесу.\
Може бути цікаво перерахувати процеси, які використовують SID з привілеями (та процеси, які використовують SID деякої служби).

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

### Handles

Корисно знати, до яких інших файлів, ключів, потоків, процесів... **процес має дескриптор** (відкритий)
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

### Строки за процесами

Volatility дозволяє нам перевірити, до якого процесу належить рядок.

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

Це також дозволяє шукати рядки всередині процесу, використовуючи модуль yarascan:

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

**Windows** відстежує програми, які ви запускаєте, за допомогою функції в реєстрі, яка називається **UserAssist keys**. Ці ключі записують, скільки разів кожна програма була виконана і коли вона була запущена востаннє.

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

​​​​[**RootedCON**](https://www.rootedcon.com/) є найактуальнішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою популяризації технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

## Послуги

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

## Мережа

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

## Реєстровий хів

### Друк доступних хівів

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

### Отримати значення

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

### Вивантаження
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Файлова система

### Монтування

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

### Сканування/дамп

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

### Master File Table

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

Файлова система **NTFS** використовує критично важливий компонент, відомий як _таблиця майстер-файлів_ (MFT). Ця таблиця містить принаймні один запис для кожного файлу на томі, охоплюючи також саму MFT. Важливі деталі про кожен файл, такі як **розмір, мітки часу, дозволи та фактичні дані**, інкапсульовані в записах MFT або в областях, що знаходяться зовні MFT, але на які посилаються ці записи. Більше деталей можна знайти в [офіційній документації](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### SSL Keys/Certs

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

## Шкідливе ПЗ

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

### Сканування з yara

Використовуйте цей скрипт для завантаження та об'єднання всіх правил yara для шкідливого ПЗ з github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Створіть директорію _**rules**_ і виконайте його. Це створить файл під назвою _**malware\_rules.yar**_, який міститиме всі правила yara для шкідливого ПЗ.

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

### Зовнішні плагіни

Якщо ви хочете використовувати зовнішні плагіни, переконайтеся, що папки, пов'язані з плагінами, є першим параметром, що використовується.

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

Завантажте його з [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
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

### Символічні посилання

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

Можливо **зчитати історію bash з пам'яті.** Ви також можете скинути файл _.bash\_history_, але він був вимкнений, ви будете раді, що можете використовувати цей модуль волатильності.

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

### Хронологія

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

### Драйвери

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

### Отримати буфер обміну
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Отримати історію IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Отримати текст з блокнота
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Скриншот
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Майстер-запис завантаження (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Запис головного завантаження (MBR)** відіграє важливу роль в управлінні логічними розділами носія, які структуровані з різними [файловими системами](https://en.wikipedia.org/wiki/File\_system). Він не лише містить інформацію про розташування розділів, але й містить виконуваний код, що діє як завантажувач. Цей завантажувач або безпосередньо ініціює процес завантаження ОС другого етапу (див. [завантажувач другого етапу](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader)), або працює в гармонії з [записом завантаження тома](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR) кожного розділу. Для детальнішої інформації зверніться до [сторінки MBR у Вікіпедії](https://en.wikipedia.org/wiki/Master\_boot\_record).

## Посилання

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Вчіться та практикуйте Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
