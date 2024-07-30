# Зловживання токенами

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримка HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Токени

Якщо ви **не знаєте, що таке токени доступу Windows**, прочитайте цю сторінку перед продовженням:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які у вас вже є**

### SeImpersonatePrivilege

Це привілей, який має будь-який процес, що дозволяє зловживання (але не створення) будь-яким токеном, якщо можна отримати дескриптор до нього. Привілейований токен можна отримати з Windows-сервісу (DCOM), спонукаючи його виконати NTLM-аутентифікацію проти експлойту, що дозволяє виконання процесу з привілеями SYSTEM. Цю вразливість можна експлуатувати за допомогою різних інструментів, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (який вимагає, щоб winrm був вимкнений), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) та [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Цей привілей дуже схожий на **SeImpersonatePrivilege**, він використовує **той же метод** для отримання привілейованого токена.\
Потім цей привілей дозволяє **призначити первинний токен** новому/призупиненому процесу. З привілейованим токеном зловживання ви можете отримати первинний токен (DuplicateTokenEx).\
З токеном ви можете створити **новий процес** за допомогою 'CreateProcessAsUser' або створити призупинений процес і **встановити токен** (в загальному, ви не можете змінити первинний токен працюючого процесу).

### SeTcbPrivilege

Якщо ви активували цей токен, ви можете використовувати **KERB\_S4U\_LOGON** для отримання **токена зловживання** для будь-якого іншого користувача без знання облікових даних, **додати довільну групу** (адміністратори) до токена, встановити **рівень цілісності** токена на "**середній**" і призначити цей токен **поточному потоку** (SetThreadToken).

### SeBackupPrivilege

Цей привілей змушує систему **надавати весь доступ для читання** до будь-якого файлу (обмеженого операціями читання). Він використовується для **читання хешів паролів локальних облікових записів адміністратора** з реєстру, після чого інструменти, такі як "**psexec**" або "**wmiexec**", можуть бути використані з хешем (техніка Pass-the-Hash). Однак ця техніка не працює за двох умов: коли обліковий запис локального адміністратора вимкнено або коли існує політика, яка позбавляє адміністративних прав локальних адміністраторів, які підключаються віддалено.\
Ви можете **зловживати цим привілеєм** за допомогою:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* слідуючи **IppSec** в [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Або, як пояснено в розділі **підвищення привілеїв з резервними операторами**:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Цей привілей надає дозвіл на **запис** до будь-якого системного файлу, незалежно від списку контролю доступу (ACL) файлу. Це відкриває численні можливості для підвищення привілеїв, включаючи можливість **модифікувати сервіси**, виконувати DLL Hijacking та встановлювати **дебагери** через параметри виконання образу серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege є потужним дозволом, особливо корисним, коли користувач має можливість зловживати токенами, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності зловживати токеном, який представляє того ж користувача і рівень цілісності якого не перевищує рівень цілісності поточного процесу.

**Ключові моменти:**
- **Зловживання без SeImpersonatePrivilege:** Можливо використовувати SeCreateTokenPrivilege для EoP, зловживаючи токенами за певних умов.
- **Умови для зловживання токенами:** Успішне зловживання вимагає, щоб цільовий токен належав тому ж користувачу і мав рівень цілісності, який менший або дорівнює рівню цілісності процесу, що намагається зловживати.
- **Створення та модифікація токенів зловживання:** Користувачі можуть створювати токен зловживання та покращувати його, додаючи SID (ідентифікатор безпеки) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **завантажувати та вивантажувати драйвери пристроїв** шляхом створення запису в реєстрі з конкретними значеннями для `ImagePath` та `Type`. Оскільки прямий доступ на запис до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб зробити `HKCU` впізнаваним для ядра для конфігурації драйвера, потрібно дотримуватися певного шляху.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` є відносним ідентифікатором поточного користувача. Всередині `HKCU` потрібно створити цей весь шлях і встановити два значення:
- `ImagePath`, що є шляхом до виконуваного бінарного файлу
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Кроки для виконання:**
1. Доступ до `HKCU` замість `HKLM` через обмежений доступ на запис.
2. Створити шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` в `HKCU`, де `<RID>` представляє відносний ідентифікатор поточного користувача.
3. Встановити `ImagePath` на шлях виконання бінарного файлу.
4. Призначити `Type` як `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Більше способів зловживання цим привілеєм у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **приймати власність на об'єкт**, обходячи вимогу явного дискреційного доступу через надання прав доступу WRITE_OWNER. Процес включає спочатку отримання власності на запланований ключ реєстру для запису, а потім зміну DACL для дозволу операцій запису.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Ця привілегія дозволяє **налагоджувати інші процеси**, включаючи читання та запис у пам'ять. Можна використовувати різні стратегії для ін'єкції пам'яті, здатні обходити більшість антивірусних та рішень для запобігання вторгненням на хост.

#### Dump memory

Ви можете використовувати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **захопити пам'ять процесу**. Зокрема, це може стосуватися процесу **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

Потім ви можете завантажити цей дамп у mimikatz, щоб отримати паролі:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати `NT SYSTEM` оболонку, ви можете використати:

* ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
* ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Перевірка привілеїв
```
whoami /priv
```
**Токени, які з'являються як Вимкнені**, можуть бути увімкнені, ви насправді можете зловживати _Увімкненими_ та _Вимкненими_ токенами.

### Увімкнути всі токени

Якщо у вас є вимкнені токени, ви можете використовувати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) для увімкнення всіх токенів:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Це дозволить користувачу імітувати токени та підвищити привілеї до системи nt, використовуючи такі інструменти, як potato.exe, rottenpotato.exe та juicypotato.exe"_                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte\_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читати чутливі файли за допомогою `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Може бути більш цікавим, якщо ви можете прочитати %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (і robocopy) не допомагають, коли йдеться про відкриті файли.<br><br>- Robocopy вимагає як SeBackup, так і SeRestore для роботи з параметром /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створити довільний токен, включаючи права локального адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Дублювати токен `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажити помилковий драйвер ядра, такий як <code>szkg64.sys</code><br>2. Використати вразливість драйвера<br><br>Альтернативно, привілей може бути використаний для вивантаження драйверів, пов'язаних із безпекою, за допомогою вбудованої команди <code>ftlMC</code>. тобто: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Вразливість <code>szkg64</code> вказана як <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">код експлуатації</a> був створений <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE з присутнім привілеєм SeRestore.<br>2. Увімкніть привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменуйте utilman.exe в utilman.old<br>4. Перейменуйте cmd.exe в utilman.exe<br>5. Заблокуйте консоль і натисніть Win+U</p> | <p>Атаку можуть виявити деякі антивірусні програми.</p><p>Альтернативний метод ґрунтується на заміні бінарних файлів служб, збережених у "Program Files", використовуючи той же привілей</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменуйте cmd.exe в utilman.exe<br>4. Заблокуйте консоль і натисніть Win+U</p>                                                                                                                                       | <p>Атаку можуть виявити деякі антивірусні програми.</p><p>Альтернативний метод ґрунтується на заміні бінарних файлів служб, збережених у "Program Files", використовуючи той же привілей.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Маніпулювати токенами, щоб включити права локального адміністратора. Може вимагати SeImpersonate.</p><p>Потрібно перевірити.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

* Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) about privesc with tokens.

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
