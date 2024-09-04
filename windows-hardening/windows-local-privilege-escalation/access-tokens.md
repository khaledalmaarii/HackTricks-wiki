# Access Tokens

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


## Access Tokens

Кожен **користувач, що увійшов** в систему **має токен доступу з інформацією про безпеку** для цієї сесії входу. Система створює токен доступу, коли користувач входить. **Кожен процес, що виконується** від імені користувача **має копію токена доступу**. Токен ідентифікує користувача, групи користувача та привілеї користувача. Токен також містить SID входу (Security Identifier), який ідентифікує поточну сесію входу.

Ви можете побачити цю інформацію, виконавши `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Локальний адміністратор

Коли локальний адміністратор входить в систему, **створюються два токени доступу**: один з правами адміністратора і інший з нормальними правами. **За замовчуванням**, коли цей користувач виконує процес, використовується токен з **звичайними** (неадміністративними) **правами**. Коли цей користувач намагається **виконати** щось **як адміністратор** ("Запустити від імені адміністратора", наприклад), буде використано **UAC** для запиту дозволу.\
Якщо ви хочете [**дізнатися більше про UAC, прочитайте цю сторінку**](../authentication-credentials-uac-and-efs/#uac)**.**

### Імітація облікових даних користувача

Якщо у вас є **дійсні облікові дані будь-якого іншого користувача**, ви можете **створити** **нову сесію входу** з цими обліковими даними:
```
runas /user:domain\username cmd.exe
```
**Токен доступу** також має **посилання** на сеанси входу всередині **LSASS**, це корисно, якщо процесу потрібно отримати доступ до деяких об'єктів мережі.\
Ви можете запустити процес, який **використовує різні облікові дані для доступу до мережевих служб**, використовуючи:
```
runas /user:domain\username /netonly cmd.exe
```
Це корисно, якщо у вас є корисні облікові дані для доступу до об'єктів у мережі, але ці облікові дані не дійсні на поточному хості, оскільки вони будуть використовуватися лише в мережі (на поточному хості будуть використовуватися ваші поточні привілеї користувача).

### Типи токенів

Існує два типи токенів:

* **Первинний токен**: Він слугує представленням безпекових облікових даних процесу. Створення та асоціація первинних токенів з процесами є діями, які вимагають підвищених привілеїв, підкреслюючи принцип розділення привілеїв. Зазвичай, служба аутентифікації відповідає за створення токенів, тоді як служба входу обробляє їх асоціацію з оболонкою операційної системи користувача. Варто зазначити, що процеси успадковують первинний токен свого батьківського процесу під час створення.
* **Токен уособлення**: Дозволяє серверному додатку тимчасово приймати ідентичність клієнта для доступу до захищених об'єктів. Цей механізм поділяється на чотири рівні роботи:
* **Анонімний**: Надає серверу доступ, подібний до доступу невизначеного користувача.
* **Ідентифікація**: Дозволяє серверу перевірити ідентичність клієнта без використання її для доступу до об'єктів.
* **Уособлення**: Дозволяє серверу діяти під ідентичністю клієнта.
* **Делегування**: Подібно до уособлення, але включає можливість розширити це прийняття ідентичності на віддалені системи, з якими взаємодіє сервер, забезпечуючи збереження облікових даних.

#### Токени уособлення

Використовуючи модуль _**incognito**_ метасплойта, якщо у вас достатньо привілеїв, ви можете легко **переглядати** та **уособлювати** інші **токени**. Це може бути корисно для виконання **дій так, ніби ви є іншим користувачем**. Ви також можете **підвищити привілеї** за допомогою цієї техніки.

### Привілеї токенів

Дізнайтеся, які **привілеї токенів можуть бути зловживані для підвищення привілеїв:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Ознайомтеся з [**усіма можливими привілеями токенів та деякими визначеннями на цій зовнішній сторінці**](https://github.com/gtworek/Priv2Admin).

## Посилання

Дізнайтеся більше про токени в цих навчальних посібниках: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) та [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


{% hint style="success" %}
Дізнайтеся та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Дізнайтеся та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
