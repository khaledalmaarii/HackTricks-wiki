# Skeleton Key

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

## Skeleton Key Attack

Атака **Skeleton Key** є складною технікою, яка дозволяє зловмисникам **обійти аутентифікацію Active Directory**, **впроваджуючи майстер-пароль** у контролер домену. Це дозволяє зловмиснику **аутентифікуватися як будь-який користувач** без їх пароля, фактично **надаючи їм необмежений доступ** до домену.

Цю атаку можна виконати за допомогою [Mimikatz](https://github.com/gentilkiwi/mimikatz). Для здійснення цієї атаки **потрібні права адміністратора домену**, і зловмисник повинен націлитися на кожен контролер домену, щоб забезпечити всебічне порушення. Однак ефект атаки є тимчасовим, оскільки **перезавантаження контролера домену знищує шкідливе ПЗ**, що вимагає повторної реалізації для підтримки доступу.

**Виконання атаки** вимагає єдиної команди: `misc::skeleton`.

## Mitigations

Стратегії пом'якшення проти таких атак включають моніторинг конкретних ідентифікаторів подій, які вказують на установку служб або використання чутливих привілеїв. Зокрема, пошук системного ідентифікатора події 7045 або ідентифікатора події безпеки 4673 може виявити підозрілі дії. Крім того, запуск `lsass.exe` як захищеного процесу може значно ускладнити зусилля зловмисників, оскільки це вимагає від них використання драйвера режиму ядра, що підвищує складність атаки.

Ось команди PowerShell для підвищення заходів безпеки:

- Щоб виявити установку підозрілих служб, використовуйте: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Зокрема, для виявлення драйвера Mimikatz можна використовувати наступну команду: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Щоб зміцнити `lsass.exe`, рекомендується активувати його як захищений процес: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Перевірка після перезавантаження системи є критично важливою для забезпечення того, що захисні заходи були успішно застосовані. Це можна досягти за допомогою: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

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
