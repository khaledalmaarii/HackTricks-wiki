# Volatility - Шпаргалка

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) є найбільш важливою подією з кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **місією просування технічних знань**, цей конгрес є кипучою точкою зустрічі для професіоналів технологій та кібербезпеки у кожній дисципліні.

{% embed url="https://www.rootedcon.com/" %}

Якщо ви хочете щось **швидке та безумовне**, що запустить кілька плагінів Volatility паралельно, ви можете використовувати: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Установка

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

Открийте офіційну документацію за посиланням [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Примітка щодо плагінів "list" та "scan"

Volatility має два основних підходи до плагінів, які іноді відображаються у їх назвах. Плагіни "list" спробують навігувати через структури ядра Windows для отримання інформації, такої як процеси (знаходження та пройдення зв'язаного списку структур `_EPROCESS` в пам'яті), обробники ОС (знаходження та перелік таблиці обробників, розіменування будь-яких знайдених вказівників і т. д.). Вони більш-менш працюють так, як робила б Windows API, якщо було б запитано, наприклад, список процесів.

Це робить "list" плагіни досить швидкими, але такими ж вразливими, як Windows API до маніпулювання зловмисним ПЗ. Наприклад, якщо зловмисне ПЗ використовує DKOM для відкріплення процесу від зв'язаного списку `_EPROCESS`, він не відображатиметься в диспетчері завдань, і його також не буде в pslist.

Плагіни "scan", з іншого боку, будуть використовувати підхід, схожий на вирізання пам'яті для речей, які можуть мати сенс при розіменуванні як конкретні структури. Наприклад, `psscan` буде читати пам'ять і намагатися створити об'єкти `_EPROCESS` з неї (він використовує сканування тегів пулу, яке полягає в пошуку рядків по 4 байти, що вказують на наявність цікавої структури). Перевага полягає в тому, що він може витягти процеси, які вийшли, і навіть якщо зловмисне ПЗ втручається у зв'язаний список `_EPROCESS`, плагін все одно знайде структуру, що лежить в пам'яті (оскільки вона все ще повинна існувати для того, щоб процес працював). Недолік полягає в тому, що плагіни "scan" трохи повільніші за плагіни "list" і іноді можуть давати помилкові результати (процес, який вийшов занадто давно і частини його структури були перезаписані іншими операціями).

З: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Профілі ОС

### Volatility3

Як пояснено в readme, вам потрібно помістити **таблицю символів ОС**, яку ви хочете підтримувати, в _volatility3/volatility/symbols_.\
Пакети таблиці символів для різних операційних систем доступні для **завантаження** за наступними посиланнями:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Зовнішній профіль

Ви можете отримати список підтримуваних профілів, виконавши:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Якщо ви хочете використовувати **новий профіль, який ви завантажили** (наприклад, linux), вам потрібно створити десь наступну структуру папок: _plugins/overlays/linux_ та помістити всередину цієї папки zip-файл, що містить профіль. Потім отримайте номер профілів, використовуючи:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Ви можете **завантажити профілі Linux та Mac** з [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

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

[**Звідси**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): На відміну від imageinfo, який просто надає рекомендації профілю, **kdbgscan** призначений для позитивної ідентифікації правильного профілю та правильної адреси KDBG (якщо є кілька). Цей плагін сканує підписи KDBGHeader, пов'язані з профілями Volatility, та застосовує перевірки на адекватність для зменшення помилкових сигналів. Рівень докладності виводу та кількість перевірок на адекватність, які можна виконати, залежить від того, чи може Volatility знайти DTB, тому якщо ви вже знаєте правильний профіль (або якщо у вас є рекомендація профілю від imageinfo), то переконайтеся, що використовуєте його з .

Завжди подивіться на **кількість процесів, які знайшов kdbgscan**. Іноді imageinfo та kdbgscan можуть знайти **більше одного** підходящого **профілю**, але лише **правильний буде мати деякі пов'язані з процесами** (Це через те, що для видобутку процесів потрібна правильна адреса KDBG)
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

**Блок відладки ядра**, відомий як **KDBG** у Volatility, є важливим для слідчих завдань, виконуваних за допомогою Volatility та різних відладчиків. Ідентифікований як `KdDebuggerDataBlock` та типу `_KDDEBUGGER_DATA64`, він містить важливі посилання, такі як `PsActiveProcessHead`. Це конкретне посилання вказує на початок списку процесів, що дозволяє вивести всі процеси, що є фундаментальним для ретельного аналізу пам'яті.

## Інформація про ОС
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Плагін `banners.Banners` може бути використаний в **vol3 для спроби знайти банери linux** в дампі.

## Хеші/Паролі

Витягніть хеші SAM, [кешовані облікові дані домену](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) та [секрети lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

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
## Дамп пам'яті

Дамп пам'яті процесу витягне **все** поточний стан процесу. Модуль **procdump** витягне лише **код**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) є найбільш важливою подією з кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **місією просування технічних знань**, цей конгрес є кипучою точкою зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

## Процеси

### Список процесів

Спробуйте знайти **підозрілі** процеси (за назвою) або **неочікувані** дочірні **процеси** (наприклад, cmd.exe як дочірній процес iexplorer.exe).\
Можливо, буде цікаво **порівняти** результат pslist з результатом psscan, щоб ідентифікувати приховані процеси.

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
### Дамп процесу

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
### Основна методологія аналізу дампу пам'яті з використанням Volatility

1. Встановлення Volatility
    - `sudo apt-get install volatility`

2. Вибір профілю
    - `volatility -f memory.dmp imageinfo`

3. Аналіз процесів
    - `volatility -f memory.dmp --profile=Profile pslist`

4. Аналіз сокетів
    - `volatility -f memory.dmp --profile=Profile sockscan`

5. Аналіз з'єднань
    - `volatility -f memory.dmp --profile=Profile connections`

6. Аналіз модулів ядра
    - `volatility -f memory.dmp --profile=Profile modules`

7. Аналіз реєстру Windows
    - `volatility -f memory.dmp --profile=Profile hivelist`
    - `volatility -f memory.dmp --profile=Profile printkey -o OFFSET`

8. Аналіз файлів
    - `volatility -f memory.dmp --profile=Profile filescan`

9. Аналіз потоків
    - `volatility -f memory.dmp --profile=Profile pstree`

10. Аналіз об'єктів
    - `volatility -f memory.dmp --profile=Profile handles`

11. Аналіз розкладу
    - `volatility -f memory.dmp --profile=Profile timeliner`

12. Аналіз робочих станів
    - `volatility -f memory.dmp --profile=Profile wintree`

13. Аналіз реєстраційних ключів
    - `volatility -f memory.dmp --profile=Profile printkey -o OFFSET`

14. Аналіз автозапуску
    - `volatility -f memory.dmp --profile=Profile autoruns`

15. Аналіз кешу
    - `volatility -f memory.dmp --profile=Profile shimcache`

16. Аналіз драйверів
    - `volatility -f memory.dmp --profile=Profile driverscan`

17. Аналіз середовища
    - `volatility -f memory.dmp --profile=Profile envars`

18. Аналіз середовища виконання
    - `volatility -f memory.dmp --profile=Profile consoles`

19. Аналіз потоків команд
    - `volatility -f memory.dmp --profile=Profile cmdscan`

20. Аналіз потоків мережі
    - `volatility -f memory.dmp --profile=Profile netscan`

21. Аналіз потоків реєстрації
    - `volatility -f memory.dmp --profile=Profile userassist`

22. Аналіз потоків URL
    - `volatility -f memory.dmp --profile=Profile urlscan`

23. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile desktops`

24. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile deskscan`

25. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile screenshot`

26. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile windows`

27. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile wndscan`

28. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile clipboard`

29. Аналіз потоків робочого столу
    - `volatility -f memory.dmp --profile=Profile consoles`
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Командний рядок

Чи було виконано щось підозріле?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}### Швидкий довідник з Volatility

#### Основні команди

- `imageinfo` - визначає тип системи та версію ОС
- `pslist` - виводить список процесів
- `pstree` - виводить дерево процесів
- `psscan` - виводить список процесів з використанням дескрипторів
- `dlllist` - виводить список завантажених DLL
- `handles` - виводить список відкритих дескрипторів
- `filescan` - виводить список відкритих файлів
- `cmdline` - виводить командний рядок для кожного процесу
- `consoles` - виводить список консолей
- `malfind` - виявляє підозрілі процеси
- `apihooks` - виводить API-захоплення
- `svcscan` - виводить список служб
- `connections` - виводить активні мережеві з'єднання
- `sockets` - виводить активні сокети
- `modules` - виводить завантажені модулі
- `modscan` - виводить модулі ядра
- `ssdt` - виводить таблицю дескрипторів системних служб
- `callbacks` - виводить зареєстровані зворотні виклики
- `driverirp` - виводить таблицю перенаправлення запитів драйвера
- `idt` - виводить таблицю дескрипторів переривань
- `gdt` - виводить таблицю дескрипторів задач
- `ldrmodules` - виводить завантажені модулі з використанням LDR-структури
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атоми
- `atomscan` - виводить атом
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
Команди, виконані в `cmd.exe`, керуються **`conhost.exe`** (або `csrss.exe` на системах до Windows 7). Це означає, що якщо **`cmd.exe`** було завершено зловмисником перед отриманням дампу пам'яті, все ще можливо відновити історію команд сеансу з пам'яті **`conhost.exe`**. Для цього, якщо виявлено незвичайну активність в модулях консолі, пам'ять пов'язаного процесу **`conhost.exe`** повинна бути вивантажена. Потім, шляхом пошуку **рядків** у цьому дампі, можна потенційно видобути використані в сеансі рядки команд.

### Середовище

Отримайте змінні середовища кожного запущеного процесу. Тут можуть бути цікаві значення.

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
### Привілеї токенів

Перевірте наявність токенів привілеїв у неочікуваних службах.\
Можливо, буде цікаво перелічити процеси, які використовують деякий привілейований токен.
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
### SIDs

Перевірте кожний SSID, що належить процесу.\
Можливо, буде цікаво перелічити процеси, які використовують SID привілеїв (і процеси, які використовують деякі службові SID).
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
### Використання

Корисно знати, до яких інших файлів, ключів, потоків, процесів... **процес має дескриптор** (відкрито)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
### Основна методологія та ресурси

#### Аналіз дампу пам'яті

##### Volatility Cheatsheet

1. Встановлення Volatility

   ```bash
   sudo apt install volatility
   ```

2. Виведення списку підтримуваних профілів

   ```bash
   volatility -f <memory_dump> imageinfo
   ```

3. Аналіз процесів

   ```bash
   volatility -f <memory_dump> --profile=<profile> pslist
   ```

4. Аналсіз сокетів

   ```bash
   volatility -f <memory_dump> --profile=<profile> sockscan
   ```

5. Аналіз файлової системи

   ```bash
   volatility -f <memory_dump> --profile=<profile> filescan
   ```

6. Відновлення видалених файлів

   ```bash
   volatility -f <memory_dump> --profile=<profile> file_recovery
   ```

7. Аналіз реєстру

   ```bash
   volatility -f <memory_dump> --profile=<profile> hivelist
   ```

8. Відображення вмісту реєстру

   ```bash
   volatility -f <memory_dump> --profile=<profile> printkey -o <offset>
   ```

9. Аналіз мережевої активності

   ```bash
   volatility -f <memory_dump> --profile=<profile> connscan
   ```

10. Аналіз автозапуску

    ```bash
    volatility -f <memory_dump> --profile=<profile> autoruns
    ```

11. Аналіз DLL

    ```bash
    volatility -f <memory_dump> --profile=<profile> dlllist
    ```

12. Аналіз драйверів

    ```bash
    volatility -f <memory_dump> --profile=<profile> driverscan
    ```

13. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> pstree
    ```

14. Аналіз об'єктів

    ```bash
    volatility -f <memory_dump> --profile=<profile> handles
    ```

15. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> timeliner
    ```

16. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> cmdline
    ```

17. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> consoles
    ```

18. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> getsids
    ```

19. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> getservicesids
    ```

20. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> svcscan
    ```

21. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> malfind
    ```

22. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> yarascan
    ```

23. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> malsysproc
    ```

24. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> modscan
    ```

25. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> ldrmodules
    ```

26. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> threads
    ```

27. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

28. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> mutantscan
    ```

29. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> devicetree
    ```

30. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> idt
    ```

31. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> gdt
    ```

32. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> ssdt
    ```

33. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> driversirp
    ```

34. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> driverirp
    ```

35. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> drivermodule
    ```

36. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> ssdtshadow
    ```

37. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

38. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

39. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

40. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

41. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

42. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

43. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

44. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

45. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

46. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

47. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

48. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

49. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```

50. Аналіз розкладу завдань

    ```bash
    volatility -f <memory_dump> --profile=<profile> callbacks
    ```
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

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Рядки на кожен процес

Volatility дозволяє нам перевірити, до якого процесу належить рядок.
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}### Основна методологія аналізу дампу пам'яті

#### Кроки аналізу дампу пам'яті:

1. **Встановлення оточення**: Встановіть Volatility та зіберіть інформацію про операційну систему, яка була використана для створення дампу пам'яті.

2. **Визначення процесів**: Використовуйте команду `pslist` для виведення списку процесів, які були активні під час створення дампу.

3. **Аналіз потоків**: Використовуйте команду `pstree` для відображення ієрархії процесів.

4. **Аналіз портативних виконуваних файлів**: Використовуйте команду `ldrmodules` для виведення завантажених модулів та виконуваних файлів.

5. **Аналіз мережевої активності**: Використовуйте команду `netscan` для виведення інформації про мережеву активність.

6. **Аналіз реєстру**: Використовуйте команду `hivelist` для виведення списку реєстрів, які можуть бути аналізовані.

7. **Аналіз потоків викликів системи**: Використовуйте команду `callbacks` для виведення інформації про потоки викликів системи.

8. **Аналіз об'єктів ядра**: Використовуйте команду `kdbgscan` для пошуку потенційних об'єктів ядра.

9. **Аналіз потоків викликів системи**: Використовуйте команду `ssdt` для виведення інформації про службові таблиці системних викликів.

10. **Аналіз потоків викликів системи**: Використовуйте команду `driverirp` для виведення інформації про обробники запитів водіїв.

11. **Аналіз потоків викликів системи**: Використовуйте команду `devicetree` для виведення інформації про дерево пристроїв.

12. **Аналіз потоків викликів системи**: Використовуйте команду `modscan` для виведення інформації про завантажені модулі ядра.

13. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

14. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

15. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

16. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

17. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

18. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

19. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

20. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

21. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

22. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформації про безпекові ідентифікатори.

23. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

24. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

25. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

26. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

27. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

28. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

29. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

30. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

31. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

32. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

33. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

34. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

35. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

36. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

37. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

38. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

39. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

40. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

41. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

42. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

43. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

44. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

45. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

46. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

47. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

48. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

49. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

50. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

51. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

52. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

53. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

54. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

55. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

56. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

57. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

58. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

59. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

60. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

61. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

62. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

63. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про безпекові ідентифікатори.

64. **Аналіз потоків викликів системи**: Використовуйте команду `getsids` для виведення інформацію про без
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
Це також дозволяє шукати рядки всередині процесу за допомогою модуля yarascan:
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** відстежує програми, які ви запускаєте, використовуючи функцію в реєстрі, яка називається **Ключі UserAssist**. Ці ключі записують, скільки разів кожна програма була запущена і коли вона востаннє запускалася.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}### Основна методологія аналізу дампу пам'яті

#### Кроки аналізу дампу пам'яті:

1. **Ідентифікація процесів та сервісів**: Використовуйте `pslist`, `pstree`, `psscan` для виявлення процесів та сервісів, що працюють у системі.
2. **Аналіз мертвих процесів**: Використовуйте `psscan`, `psxview` для виявлення процесів, які завершили роботу.
3. **Аналіз мертвих сервісів**: Використовуйте `svcscan`, `driverirp` для виявлення сервісів, які завершили роботу.
4. **Аналіз мертвих з'єднань**: Використовуйте `netscan`, `sockets` для виявлення мертвих з'єднань.
5. **Аналіз потоків**: Використовуйте `pslist`, `pstree`, `psscan` для виявлення потоків, що працюють у системі.
6. **Аналіз DLL**: Використовуйте `dlllist`, `ldrmodules`, `modules` для виявлення завантажених DLL-бібліотек.
7. **Аналіз реєстру**: Використовуйте `hivelist`, `printkey`, `hivedump` для аналізу реєстру системи.
8. **Аналіз файлів**: Використовуйте `filescan`, `fileinfo`, `dumpfiles` для аналізу файлів у системі.
9. **Аналіз кешу пам'яті**: Використовуйте `memmap`, `memdump`, `memstrings` для аналізу кешу пам'яті.

#### Використання Volatility:

- **Завантаження профілю**: `volatility -f memory.dmp imageinfo`
- **Використання плагінів**: `volatility -f memory.dmp <plugin_name>`
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З місією просування технічних знань, цей конгрес є підігрітим місцем зустрічі для професіоналів у галузі технологій та кібербезпеки у кожній дисципліні.

{% embed url="https://www.rootedcon.com/" %}

## Сервіси

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
## Реєстр Hive

### Виведення доступних Hive

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
### Дамп
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Файлова система

### Підключення

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
### Сканування/вивантаження

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
### Майстер-файлова таблиця

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

**Файлова система NTFS** використовує критичний компонент, відомий як _таблиця майстра файлів_ (MFT). Ця таблиця включає принаймні один запис для кожного файлу на томі, охоплюючи саму MFT. Важливі деталі про кожен файл, такі як **розмір, мітки часу, дозволи та фактичні дані**, укладені в записах MFT або в областях, зовнішніх для MFT, але на які посилаються ці записи. Додаткові деталі можна знайти в [офіційній документації](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Ключі/Сертифікати SSL
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
## Віруси

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

{% tab title="vol2" %}### Основна методологія аналізу дампу пам'яті

#### Крок 1: Встановлення Volatility

```bash
sudo apt install volatility
```

#### Крок 2: Визначення профілю

```bash
volatility -f memory_dump.raw imageinfo
```

#### Крок 3: Аналшиз процесів

```bash
volatility -f memory_dump.raw --profile=PROFILE pslist
```

#### Крок 4: Аналіз сокетів

```bash
volatility -f memory_dump.raw --profile=PROFILE sockscan
```

#### Крок 5: Аналіз реєстру

```bash
volatility -f memory_dump.raw --profile=PROFILE hivelist
volatility -f memory_dump.raw --profile=PROFILE printkey -o OFFSET
```

#### Крок 6: Аналіз файлів

```bash
volatility -f memory_dump.raw --profile=PROFILE filescan
```

#### Крок 7: Аналіз мережевих з'єднань

```bash
volatility -f memory_dump.raw --profile=PROFILE netscan
```

#### Крок 8: Аналіз потоків

```bash
volatility -f memory_dump.raw --profile=PROFILE pstree
```

#### Крок 9: Аналіз модулів ядра

```bash
volatility -f memory_dump.raw --profile=PROFILE modules
```

#### Крок 10: Аналіз розкладу пам'яті

```bash
volatility -f memory_dump.raw --profile=PROFILE memmap
```

#### Крок 11: Аналіз керованих об'єктів

```bash
volatility -f memory_dump.raw --profile=PROFILE handles
```

#### Крок 12: Аналіз розкладу стеку

```bash
volatility -f memory_dump.raw --profile=PROFILE stackstrings
```

#### Крок 13: Аналіз кешу

```bash
volatility -f memory_dump.raw --profile=PROFILE shimcache
```

#### Крок 14: Аналіз реєстру запуску

```bash
volatility -f memory_dump.raw --profile=PROFILE hivelist
volatility -f memory_dump.raw --profile=PROFILE printkey -o OFFSET
```

#### Крок 15: Аналіз драйверів

```bash
volatility -f memory_dump.raw --profile=PROFILE driverscan
```

#### Крок 16: Аналіз розкладу керованих об'єктів

```bash
volatility -f memory_dump.raw --profile=PROFILE objecttypes
```

#### Крок 17: Аналіз потоків

```bash
volatility -f memory_dump.raw --profile=PROFILE threads
```

#### Крок 18: Аналіз розкладу кешу

```bash
volatility -f memory_dump.raw --profile=PROFILE userassist
```

#### Крок 19: Аналіз розкладу реєстру

```bash
volatility -f memory_dump.raw --profile=PROFILE printkey -o OFFSET
``json
```
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

### Сканування за допомогою yara

Використовуйте цей скрипт для завантаження та об'єднання всіх правил виявлення шкідливих програм yara з github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Створіть каталог _**rules**_ та виконайте його. Це створить файл під назвою _**malware\_rules.yar**_, який містить всі правила yara для виявлення шкідливих програм.
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
## РІЗНЕ

### Зовнішні плагіни

Якщо ви хочете використовувати зовнішні плагіни, переконайтеся, що теки, пов'язані з плагінами, є першим параметром, який використовується.
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

#### Автозапуск

Завантажте його з [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### М'ютекси

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
### Bash

Можливо **читати історію bash з пам'яті.** Ви також можете витягти файл _.bash\_history_, але якщо він вимкнений, ви будете раді використовувати цей модуль volatility
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}### Основна методологія аналізу дампу пам'яті

#### Кроки аналізу дампу пам'яті:

1. **Ідентифікація процесів та сервісів**: Використовуйте команду `pslist` для перегляду списку процесів та їх атрибутів.
2. **Аналіз потоків**: Використовуйте команду `pstree` для візуалізації зв'язків між процесами.
3. **Аналіз портів та сокетів**: Використовуйте команди `sockets` та `socketscan` для виявлення відкритих портів та мережевих з'єднань.
4. **Аналіз файлів та дескрипторів файлів**: Використовуйте команди `filescan` та `filescan` для виявлення відкритих файлів та дескрипторів файлів.
5. **Аналіз реєстру**: Використовуйте команду `hivelist` для виявлення віртуальних адрес реєстру.
6. **Аналіз модулів ядра**: Використовуйте команду `modules` для перегляду завантажених модулів ядра.
7. **Аналіз об'єктів та драйверів**: Використовуйте команди `objscan` та `driverirp` для виявлення об'єктів та драйверів.
8. **Аналіз потоків та стеків викликів**: Використовуйте команди `threads` та `stacks` для аналізу потоків та стеків викликів.
9. **Аналіз кешу пам'яті**: Використовуйте команду `memmap` для відображення кешу пам'яті та виявлення потенційної шкідливої діяльності.
10. **Аналіз автозапуску**: Використовуйте команду `autoruns` для виявлення автозапускових програм та сервісів.

#### Корисні команди Volatility:

- `imageinfo`: Відображення основної інформації про образ.
- `kdbgscan`: Пошук потенційних значень KDBG.
- `pslist`: Відображення списку процесів.
- `pstree`: Відображення дерева процесів.
- `sockets`: Відображення відкритих сокетів.
- `socketscan`: Сканування сокетів для виявлення відкритих портів.
- `filescan`: Сканування файлів для виявлення відкритих файлів.
- `filescan`: Відображення відкритих файлів та дескрипторів файлів.
- `hivelist`: Відображення віртуальних адрес реєстру.
- `modules`: Відображення завантажених модулів ядра.
- `objscan`: Сканування об'єктів для виявлення об'єктів та драйверів.
- `driverirp`: Відображення драйверів та їх IRP.
- `threads`: Відображення списку потоків.
- `stacks`: Відображення стеків викликів.
- `memmap`: Відображення кешу пам'яті.
- `autoruns`: Відображення автозапускових програм та сервісів.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Часова шкала

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
### Основна методологія та ресурси

#### Аналіз дампу пам'яті

##### Volatility Cheatsheet

1. Встановлення Volatility

```bash
sudo apt-get install volatility
```

2. Виведення списку підтримуваних профілів

```bash
volatility -f <memory_dump> imageinfo
```

3. Аналіз процесів

```bash
volatility -f <memory_dump> --profile=<profile> pslist
```

4. Аналіз сокетів

```bash
volatility -f <memory_dump> --profile=<profile> sockscan
```

5. Аналіз файлової системи

```bash
volatility -f <memory_dump> --profile=<profile> filescan
```

6. Відновлення видалених файлів

```bash
volatility -f <memory_dump> --profile=<profile> file_recovery
```

7. Аналіз реєстру Windows

```bash
volatility -f <memory_dump> --profile=<profile> hivelist
volatility -f <memory_dump> --profile=<profile> printkey -o <offset>
```

8. Аналіз мережевої активності

```bash
volatility -f <memory_dump> --profile=<profile> connscan
```

9. Аналіз автозапуску

```bash
volatility -f <memory_dump> --profile=<profile> autoruns
```

10. Аналіз драйверів

```bash
volatility -f <memory_dump> --profile=<profile> driverscan
```

11. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

12. Аналіз модулів ядра

```bash
volatility -f <memory_dump> --profile=<profile> modscan
```

13. Аналіз об'єктів

```bash
volatility -f <memory_dump> --profile=<profile> handles
```

14. Аналіз кешу

```bash
volatility -f <memory_dump> --profile=<profile> shimcache
```

15. Аналіз робочих наборів

```bash
volatility -f <memory_dump> --profile=<profile> memmap
```

16. Аналіз потоків

```bash
volatility -f <memory_dump> --profile=<profile> threads
```

17. Аналіз середовища

```bash
volatility -f <memory_dump> --profile=<profile> envars
```

18. Аналіз відкритих файлів

```bash
volatility -f <memory_dump> --profile=<profile> filescan
```

19. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

20. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

21. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

22. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

23. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

24. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

25. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

26. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

27. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```

28. Аналіз розкладу завдань

```bash
volatility -f <memory_dump> --profile=<profile> pstree
```
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### Драйвери

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}### Основна методологія аналізу дампу пам'яті з використанням Volatility

1. **Встановлення Volatility**
    - `sudo apt-get install volatility`

2. **Визначення профілю пам'яті**
    - `volatility -f memory_dump.raw imageinfo`

3. **Аналіз процесів**
    - `volatility -f memory_dump.raw --profile=PROFILE pslist`

4. **Аналіз сокетів**
    - `volatility -f memory_dump.raw --profile=PROFILE sockscan`

5. **Аналіз файлової системи**
    - `volatility -f memory_dump.raw --profile=PROFILE filescan`

6. **Аналіз реєстру**
    - `volatility -f memory_dump.raw --profile=PROFILE hivelist`
    - `volatility -f memory_dump.raw --profile=PROFILE printkey -o OFFSET`

7. **Аналіз мережевої активності**
    - `volatility -f memory_dump.raw --profile=PROFILE netscan`

8. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

9. **Аналіз модулів ядра**
    - `volatility -f memory_dump.raw --profile=PROFILE linux_lsmod`

10. **Аналіз керованих об'єктів**
    - `volatility -f memory_dump.raw --profile=PROFILE handles`

11. **Аналіз кеша**
    - `volatility -f memory_dump.raw --profile=PROFILE shimcache`

12. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

13. **Аналіз автозапуску**
    - `volatility -f memory_dump.raw --profile=PROFILE autoruns`

14. **Аналіз драйверів**
    - `volatility -f memory_dump.raw --profile=PROFILE driverscan`

15. **Аналіз середовища**
    - `volatility -f memory_dump.raw --profile=PROFILE envars`

16. **Аналіз розкладу завдань**
    - `volatility -f memory_dump.raw --profile=PROFILE pstime`

17. **Аналіз робочих директорій**
    - `volatility -f memory_dump.raw --profile=PROFILE consoles`

18. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

19. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

20. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

21. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

22. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

23. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

24. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

25. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

26. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

27. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

28. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

29. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

30. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

31. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

32. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

33. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

34. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

35. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

36. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

37. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

38. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

39. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

40. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

41. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

42. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

43. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

44. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

45. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

46. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

47. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

48. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

49. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

50. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

51. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

52. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

53. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

54. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

55. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

56. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

57. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

58. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

59. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

60. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

61. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

62. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

63. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

64. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

65. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

66. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

67. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

68. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

69. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

70. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

71. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

72. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

73. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

74. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

75. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

76. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

77. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

78. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

79. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

80. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

81. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

82. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

83. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

84. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

85. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

86. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

87. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

88. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

89. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

90. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

91. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

92. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

93. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

94. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

95. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

96. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

97. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

98. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

99. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

100. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

101. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

102. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

103. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

104. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

105. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

106. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

107. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

108. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

109. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

110. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

111. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

112. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

113. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

114. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

115. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

116. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

117. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

118. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

119. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

120. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

121. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

122. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

123. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

124. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

125. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

126. **Аналіз робочих станів**
    - `volatility -f memory_dump.raw --profile=PROFILE sessions`

127. **Аналіз потоків**
    - `volatility -f memory_dump.raw --profile=PROFILE pstree`

128. **Аналіз робочих стан
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
### Знімок екрану
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Загрузочная запись мастера (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** відіграє важливу роль у керуванні логічними розділами носія даних, які структуровані за допомогою різних [файлових систем](https://en.wikipedia.org/wiki/File_system). Він не лише містить інформацію про розташування розділів, але також містить виконуваний код, який діє як завантажувач. Цей завантажувач або безпосередньо ініціює процес завантаження другого етапу ОС (див. [завантажувач другого етапу](https://en.wikipedia.org/wiki/Second-stage_boot_loader)), або працює у взаємодії з [записом завантаження тома](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) кожного розділу. Для глибоких знань звертайтеся до [сторінки Вікіпедії про MBR](https://en.wikipedia.org/wiki/Master_boot_record).

## Посилання
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) - найбільш важлива подія з кібербезпеки в **Іспанії** та одна з найважливіших в **Європі**. З **місією просування технічних знань**, цей конгрес є плідним місцем зустрічі для професіоналів технологій та кібербезпеки у будь-якій галузі.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github репозиторіїв.

</details>
