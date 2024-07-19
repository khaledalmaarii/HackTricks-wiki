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


**Оригінальний пост** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Резюме

Було виявлено два ключі реєстру, які можна записувати поточним користувачем:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Було запропоновано перевірити дозволи служби **RpcEptMapper** за допомогою **regedit GUI**, зокрема вкладки **Ефективні дозволи** вікна **Розширені налаштування безпеки**. Цей підхід дозволяє оцінити надані дозволи конкретним користувачам або групам без необхідності перевіряти кожен запис контролю доступу (ACE) окремо.

Скриншот показав дозволи, надані користувачу з низькими привілеями, серед яких особливо виділявся дозвіл **Створити підключ**. Цей дозвіл, також відомий як **AppendData/AddSubdirectory**, відповідає висновкам скрипта.

Було зазначено, що неможливо безпосередньо змінювати певні значення, але є можливість створювати нові підключі. Прикладом було спроба змінити значення **ImagePath**, що призвело до повідомлення про відмову в доступі.

Незважаючи на ці обмеження, було виявлено потенціал для ескалації привілеїв через можливість використання підключа **Performance** в реєстрі служби **RpcEptMapper**, підключа, яке за замовчуванням не присутнє. Це могло б дозволити реєстрацію DLL та моніторинг продуктивності.

Була проконсультована документація про підключ **Performance** та його використання для моніторингу продуктивності, що призвело до розробки доказу концепції DLL. Ця DLL, що демонструє реалізацію функцій **OpenPerfData**, **CollectPerfData** та **ClosePerfData**, була протестована через **rundll32**, підтверджуючи її успішну роботу.

Метою було примусити **RPC Endpoint Mapper service** завантажити створену DLL для продуктивності. Спостереження показали, що виконання запитів класу WMI, пов'язаних з даними продуктивності через PowerShell, призводило до створення файлу журналу, що дозволяло виконання довільного коду в контексті **LOCAL SYSTEM**, таким чином надаючи підвищені привілеї.

Постійність і потенційні наслідки цієї вразливості були підкреслені, що підкреслює її значення для стратегій після експлуатації, бічного переміщення та ухилення від систем антивірусного/EDR захисту.

Хоча вразливість спочатку була розкрита ненавмисно через скрипт, було підкреслено, що її експлуатація обмежена застарілими версіями Windows (наприклад, **Windows 7 / Server 2008 R2**) і вимагає локального доступу.

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
