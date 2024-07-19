# Kerberos Double Hop Problem

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduction

Проблема "Подвійного стрибка" Kerberos виникає, коли зловмисник намагається використовувати **аутентифікацію Kerberos через два** **стрибки**, наприклад, використовуючи **PowerShell**/**WinRM**.

Коли відбувається **аутентифікація** через **Kerberos**, **облікові дані** **не** кешуються в **пам'яті.** Тому, якщо ви запустите mimikatz, ви **не знайдете облікові дані** користувача на машині, навіть якщо він виконує процеси.

Це відбувається тому, що при підключенні з Kerberos виконуються такі кроки:

1. Користувач1 надає облікові дані, і **контролер домену** повертає Kerberos **TGT** користувачу1.
2. Користувач1 використовує **TGT** для запиту **квитка служби** для **підключення** до Серверу1.
3. Користувач1 **підключається** до **Сервера1** і надає **квиток служби**.
4. **Сервер1** **не має** **облікових даних** користувача1 кешованими або **TGT** користувача1. Тому, коли користувач1 з Серверу1 намагається увійти на другий сервер, він **не може аутентифікуватися**.

### Unconstrained Delegation

Якщо **неконтрольована делегація** увімкнена на ПК, цього не станеться, оскільки **Сервер** **отримає** **TGT** кожного користувача, який до нього звертається. Більше того, якщо використовується неконтрольована делегація, ви, ймовірно, зможете **зламати контролер домену** з цього.\
[**Більше інформації на сторінці неконтрольованої делегації**](unconstrained-delegation.md).

### CredSSP

Інший спосіб уникнути цієї проблеми, який є [**значно небезпечним**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), це **Постачальник підтримки безпеки облікових даних**. Від Microsoft:

> Аутентифікація CredSSP делегує облікові дані користувача з локального комп'ютера на віддалений комп'ютер. Ця практика підвищує ризик безпеки віддаленої операції. Якщо віддалений комп'ютер зламаний, коли облікові дані передаються на нього, ці облікові дані можуть бути використані для контролю мережевої сесії.

Рекомендується **вимкнути CredSSP** на виробничих системах, чутливих мережах та подібних середовищах через проблеми безпеки. Щоб визначити, чи **CredSSP** увімкнено, можна виконати команду `Get-WSManCredSSP`. Ця команда дозволяє **перевірити статус CredSSP** і може бути виконана навіть віддалено, за умови, що **WinRM** увімкнено.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Щоб вирішити проблему подвійного стрибка, пропонується метод, що включає вкладений `Invoke-Command`. Це не вирішує проблему безпосередньо, але пропонує обхідний шлях без необхідності спеціальних налаштувань. Цей підхід дозволяє виконати команду (`hostname`) на вторинному сервері через команду PowerShell, виконану з початкової атакуючої машини або через раніше встановлену PS-Session з першим сервером. Ось як це робиться:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Альтернативно, пропонується встановити PS-Session з першим сервером і виконати `Invoke-Command`, використовуючи `$cred`, для централізації завдань.

### Реєстрація конфігурації PSSession

Рішення для обходу проблеми подвійного стрибка передбачає використання `Register-PSSessionConfiguration` з `Enter-PSSession`. Цей метод вимагає іншого підходу, ніж `evil-winrm`, і дозволяє створити сесію, яка не страждає від обмеження подвійного стрибка.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Для локальних адміністраторів на проміжній цілі, переадресація портів дозволяє надсилати запити на кінцевий сервер. Використовуючи `netsh`, можна додати правило для переадресації портів, разом з правилом брандмауера Windows для дозволу переадресованого порту.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` може бути використаний для пересилання запитів WinRM, потенційно як менш помітний варіант, якщо моніторинг PowerShell є проблемою. Нижче наведено приклад його використання:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Встановлення OpenSSH на першому сервері дозволяє обійти проблему подвійного стрибка, що особливо корисно для сценаріїв з використанням jump box. Цей метод вимагає CLI-встановлення та налаштування OpenSSH для Windows. Коли він налаштований для автентифікації за паролем, це дозволяє проміжному серверу отримати TGT від імені користувача.

#### Кроки встановлення OpenSSH

1. Завантажте та перемістіть останній реліз OpenSSH у zip-форматі на цільовий сервер.
2. Розпакуйте та запустіть скрипт `Install-sshd.ps1`.
3. Додайте правило брандмауера для відкриття порту 22 та перевірте, чи працюють служби SSH.

Щоб вирішити помилки `Connection reset`, можливо, потрібно оновити дозволи, щоб дозволити всім читати та виконувати доступ до каталогу OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## References

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
